#!/usr/bin/env python3
"""Turns Ghostlink's Apple profiles into a strongSwan client configuration with exactly the
parameters each profile gives iOS: addresses, identities, credentials, the CA, the client
certificate (from the PKCS#12 with its embedded password) and the algorithms.

Usage: client_config.py OUTDIR NAME=PROFILE.mobileconfig [NAME=...] [--wrong NAME]
"""
import base64
import plistlib
import re
import subprocess
import sys
from pathlib import Path


def b64(data: bytes) -> str:
    return "0s" + base64.b64encode(data).decode()


def payloads(profile):
    return {p["PayloadType"]: p for p in profile["PayloadContent"]}


def p12_to_pem(data: bytes, password: str, out: Path) -> tuple[str, str]:
    p12 = out / "identity.p12"
    p12.write_bytes(data)
    for extra in ([], ["-legacy"]):
        result = subprocess.run(["openssl", "pkcs12", "-in", str(p12), "-nodes", "-passin", "pass:" + password, *extra],
                                capture_output=True, text=True)
        if result.returncode == 0:
            break
    else:
        sys.exit("openssl cannot open the profile's PKCS#12: " + result.stderr)
    p12.unlink()
    certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", result.stdout, re.S)
    key = re.search(r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", result.stdout, re.S)
    if not certs or not key:
        sys.exit("PKCS#12 lacks a certificate or key")
    # The leaf is the certificate that is not the CA (the CA is also in the bundle).
    return certs, key.group(0)


def main() -> None:
    out = Path(sys.argv[1])
    args = sys.argv[2:]
    wrong = set()
    while "--wrong" in args:
        i = args.index("--wrong")
        wrong.add(args[i + 1])
        del args[i:i + 2]
    swanctl = out / "swanctl"
    for d in ("x509ca", "x509", "private"):
        (swanctl / d).mkdir(parents=True, exist_ok=True)
    conns, secrets = [], []
    for item in args:
        name, path = item.split("=", 1)
        profile = plistlib.loads(Path(path).read_bytes())
        p = payloads(profile)
        vpn = p["com.apple.vpn.managed"]
        root = p["com.apple.security.root"]["PayloadContent"]
        ca_pem = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(root).decode() + "-----END CERTIFICATE-----\n"
        (swanctl / "x509ca" / "ca.pem").write_text(ca_pem)
        kind = vpn["VPNType"]
        s = vpn[kind]
        identity_cert = None
        if s.get("AuthenticationMethod") == "Certificate":
            p12 = p["com.apple.security.pkcs12"]
            assert s["PayloadCertificateUUID"] == p12["PayloadUUID"], "VPN does not reference its certificate"
            certs, key = p12_to_pem(p12["PayloadContent"], p12["Password"], out)
            leaf = [c for c in certs if base64.b64decode("".join(c.splitlines()[1:-1])) != root][0]
            (swanctl / "x509" / f"{name}.pem").write_text(leaf + "\n")
            (swanctl / "private" / f"{name}.pem").write_text(key + "\n")
            identity_cert = f"{name}.pem"
        lines = [f"  {name} {{", f"    remote_addrs = {s['RemoteAddress']}", "    vips = 0.0.0.0"]
        if kind == "IKEv2":
            ike = s["IKESecurityAssociationParameters"]
            child = s["ChildSecurityAssociationParameters"]
            assert ike["EncryptionAlgorithm"] == "AES-256-GCM" and ike["IntegrityAlgorithm"] == "SHA2-256" and ike["DiffieHellmanGroup"] == 19
            assert child["DiffieHellmanGroup"] == 19 and s["EnablePFS"] == 1
            lines += ["    version = 2", "    proposals = aes256gcm16-prfsha256-ecp256"]
            if identity_cert:
                lines += ["    local {", "      auth = pubkey", f"      certs = {identity_cert}", f"      id = {s['LocalIdentifier']}", "    }"]
            else:
                assert s["AuthenticationMethod"] == "None" and s["ExtendedAuthEnabled"] == 1
                lines += ["    local {", "      auth = eap-mschapv2", f"      id = {s['LocalIdentifier']}", f"      eap_id = {s['AuthName']}", "    }"]
                password = "wrong-password" if name in wrong else s["AuthPassword"]
                secrets.append(f"  eap-{name} {{\n    id = {s['AuthName']}\n    secret = {b64(password.encode())}\n  }}")
            lines += ["    remote {", "      auth = pubkey", f"      id = {s['RemoteIdentifier']}", "      cacerts = ca.pem", "    }"]
            lines += ["    children {", f"      {name} {{", "        remote_ts = 0.0.0.0/0", "        esp_proposals = aes256gcm16-ecp256", "      }", "    }"]
        else:
            assert kind == "IPSec" and s["XAuthEnabled"] == 1
            lines += ["    version = 1", "    proposals = aes256-sha256-modp2048"]
            if identity_cert:
                lines += ["    local {", "      auth = pubkey", f"      certs = {identity_cert}", "    }"]
                lines += ["    remote {", "      auth = pubkey", "      cacerts = ca.pem", "    }"]
            else:
                assert s["AuthenticationMethod"] == "SharedSecret" and s["LocalIdentifierType"] == "KeyID"
                group = s["LocalIdentifier"]
                lines += ["    aggressive = yes", "    local {", "      auth = psk", f"      id = keyid:{group}", "    }"]
                lines += ["    remote {", "      auth = psk", "    }"]
                secrets.append(f"  ike-{name} {{\n    id = keyid:{group}\n    secret = {b64(s['SharedSecret'])}\n  }}")
            lines += ["    local-xauth {", "      auth = xauth", f"      xauth_id = {s['XAuthName']}", "    }"]
            password = "wrong-password" if name in wrong else s["XAuthPassword"]
            secrets.append(f"  xauth-{name} {{\n    id = {s['XAuthName']}\n    secret = {b64(password.encode())}\n  }}")
            lines += ["    children {", f"      {name} {{", "        remote_ts = 0.0.0.0/0", "        esp_proposals = aes256-sha256", "      }", "    }"]
        lines.append("  }")
        conns.append("\n".join(lines))
    (swanctl / "swanctl.conf").write_text("connections {\n" + "\n".join(conns) + "\n}\nsecrets {\n" + "\n".join(secrets) + "\n}\n")
    (out / "strongswan.conf").write_text("""charon {
  user = root
  group = root
  i_dont_care_about_security_and_use_aggressive_mode_psk = yes
  load = random nonce kdf constraints openssl pem pkcs1 pkcs8 x509 revocation pubkey kernel-netlink socket-default vici eap-identity eap-mschapv2 xauth-generic
  plugins {
    openssl {
      load_legacy = yes
    }
  }
  filelog {
    stderr {
      default = 1
      net = 0
      enc = 0
      asn = 0
      job = 0
      mgr = 0
    }
  }
}
""")


if __name__ == "__main__":
    main()
