#!/usr/bin/env python3
"""OpenSSL-backed personal PKI. No cryptography is implemented here.

CA passphrases are supplied on stdin to OpenSSL, never in process arguments.
The PKI directory is offline material; deploy only the server bundle, never the CA key.
"""
import argparse
import contextlib
import csv
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

# An OpenVPN server with crl-verify refuses every client once its CRL expires, and only this
# offline tool can make a new one. Revocations reach the server only in a bundle you deploy, so a
# short validity protects nothing; 10 years matches the CA, so the CRL never expires first.
CRL_DAYS = 3650

SERVER_EXISTS = ("A server identity already exists. To renew it, move server.key, server.csr and server.crt out of "
                 "the PKI root and run server again; the tls-crypt key is kept, so issued profiles keep working")


class PKIError(ValueError):
    """A failure whose message names no secret, so it is printed as it is."""


def identity(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Identity must contain 1-64 ASCII letters, digits, hyphens or underscores")
    return value


def volume_keeps_permissions(path):
    """Whether the volume holding path stores permissions; FAT and exFAT, as on many USB sticks, do not."""
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.GetVolumePathNameW.restype = ctypes.c_int
    kernel32.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.GetVolumeInformationW.restype = ctypes.c_int
    root, flags = ctypes.create_unicode_buffer(32768), ctypes.c_uint32()
    if not kernel32.GetVolumePathNameW(str(path), root, len(root)) or not kernel32.GetVolumeInformationW(root.value, None, 0, None, None, ctypes.byref(flags), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(flags.value & 0x8)  # FILE_PERSISTENT_ACLS


def restrict_to_owner(path, directory=False):
    """Drop inherited access to path and give this account and SYSTEM full control.

    Windows ignores the POSIX modes used here, so files outside a protected folder would
    otherwise take that folder's permissions. A drive that stores no permissions is left as it
    is: nothing can be restricted there, and profiles are often carried on such USB sticks.
    """
    if os.name != "nt" or not volume_keeps_permissions(path):
        return
    # Absolute System32 paths: a bare name can resolve to an unrelated tool on PATH, such as Git's GNU whoami.
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    result = subprocess.check_output([str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"], text=True)
    sid = next(csv.reader([result.strip()]))[-1]
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise PKIError("Cannot identify the current Windows account")
    inherit = "(OI)(CI)" if directory else ""
    subprocess.run([str(system32 / "icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:{inherit}F", f"*S-1-5-18:{inherit}F"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def private_write(path, content):
    with open(path, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600), newline="\n") as output:
        output.write(content)


class PKI:
    def __init__(self, root, openssl, password):
        self.root = Path(root).resolve()
        self.openssl = str(openssl)
        self.password = password

    def run(self, *args, secret=False):
        result = subprocess.run([self.openssl, *map(str, args)], cwd=self.root,
                                input=(self.password + "\n").encode() if secret else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            # OpenSSL output can contain paths, certificate subjects, or sensitive provider errors.
            raise RuntimeError("OpenSSL operation failed; inspect PKI permissions and passphrase (raw output suppressed)")
        return result.stdout.decode()

    def check_passphrase(self):
        # Unlock the CA key before anything is written, so a mistyped passphrase leaves no partial identity.
        try:
            self.run("pkey", "-in", "ca.key", "-passin", "stdin", "-noout", secret=True)
        except RuntimeError:
            raise PKIError("Cannot unlock ca.key with this passphrase; nothing was changed") from None

    @contextlib.contextmanager
    def lock(self):
        lock = self.root / ".pki.lock"
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            # A command that was killed leaves its lock behind, and nothing else would say so.
            raise PKIError("Another command is using this PKI (.pki.lock exists). If none is running, an earlier one was interrupted: delete .pki.lock and try again") from None
        try:
            os.write(descriptor, str(os.getpid()).encode())
            yield
        finally:
            os.close(descriptor)
            lock.unlink()

    def init(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        restrict_to_owner(self.root, directory=True)
        # All config paths are relative: the PKI can be backed up and moved intact.
        config = """[ca]
default_ca = CA_default
[CA_default]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.crt
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
crl = $dir/crl.pem
default_md = sha384
default_days = 365
default_crl_days = 3650
policy = policy
unique_subject = no
copy_extensions = none
[policy]
commonName = supplied
[req]
distinguished_name = dn
[dn]
[ca_cert]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[server_cert]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
[client_cert]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"""
        private_write(self.root / "openssl.cnf", config)
        private_write(self.root / "index.txt", "")
        private_write(self.root / "serial", "1000\n")
        private_write(self.root / "crlnumber", "1000\n")
        (self.root / "newcerts").mkdir(mode=0o700)
        (self.root / "clients").mkdir(mode=0o700)
        self.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-aes-256-cbc", "-pass", "stdin", "-out", "ca.key", secret=True)
        self.run("req", "-new", "-x509", "-sha384", "-days", "3650", "-config", "openssl.cnf", "-extensions", "ca_cert", "-subj", "/CN=Ghostlink-Personal-CA", "-key", "ca.key", "-passin", "stdin", "-out", "ca.crt", secret=True)
        # TLS-crypt uses the official OpenVPN static-key format; OpenSSL only supplies random bytes.
        # Prefer an actual OpenVPN-generated key for compatibility rather than implementing a key format.
        private_write(self.root / "README.txt", "Offline CA: keep ca.key and this directory off the VPN server. Run server to generate a server identity, then issue separate client identities.\n")

    def create_identity(self, name, server=False, days=365):
        name = identity(name)
        target = self.root if server else self.root / "clients" / name
        base = "server" if server else "client"
        key = target / f"{base}.key"
        csr = target / f"{base}.csr"
        cert = target / f"{base}.crt"
        if server and (key.exists() or cert.exists()):
            raise PKIError(SERVER_EXISTS)
        if not server and target.exists():
            raise PKIError(f"A client named {name} already exists (revoked names stay taken); use a new name")
        if not server:
            target.mkdir(mode=0o700)
        try:
            self.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", key)
            self.run("req", "-new", "-sha384", "-config", "openssl.cnf", "-subj", f"/CN={name}", "-key", key, "-out", csr)
            self.run("ca", "-config", "openssl.cnf", "-batch", "-rand_serial", "-notext", "-days", str(days), "-extensions", "server_cert" if server else "client_cert", "-in", csr, "-out", cert, "-passin", "stdin", secret=True)
        except BaseException:
            # Remove what this attempt wrote, or every retry would be refused as a duplicate.
            for path in (key, csr, cert):
                path.unlink(missing_ok=True)
            if not server:
                with contextlib.suppress(OSError):
                    target.rmdir()
            raise
        return target

    def crl(self):
        # The command line overrides default_crl_days, which is 30 in PKIs made by earlier versions.
        self.run("ca", "-config", "openssl.cnf", "-gencrl", "-crldays", str(CRL_DAYS), "-out", "crl.pem", "-passin", "stdin", secret=True)

    def server(self, openvpn):
        # Refuse before anything is touched, the tls-crypt key included.
        if (self.root / "server.key").exists() or (self.root / "server.crt").exists():
            raise PKIError(SERVER_EXISTS)
        self.check_passphrase()
        tls_crypt = self.root / "tls-crypt.key"
        if not tls_crypt.exists():
            # Every issued profile embeds this key, so it is made once and kept when the server identity is renewed.
            pending = self.root / "tls-crypt.key.new"
            try:
                result = subprocess.run([str(openvpn), "--genkey", "secret", str(pending)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except FileNotFoundError:
                raise PKIError("OpenVPN was not found; give its path with server --openvpn") from None
            if result.returncode or not pending.is_file():
                pending.unlink(missing_ok=True)
                raise RuntimeError("OpenVPN TLS-crypt key generation failed")
            pending.replace(tls_crypt)
        self.create_identity("ghostlink-server", server=True)
        self.crl()

    def issue(self, name, endpoint, port, transport, mode, output, days):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", endpoint):
            raise PKIError("Invalid public endpoint")
        if not (self.root / "tls-crypt.key").is_file():
            raise PKIError("Generate the server identity first")
        output = Path(output).resolve()
        if output.exists():
            raise PKIError("Profile output already exists")
        self.check_passphrase()
        # Create the profile first, so a folder that cannot take it fails before an identity is issued.
        try:
            profile = open(output, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600), newline="\n")
        except FileExistsError:
            raise PKIError("Profile output already exists") from None
        except FileNotFoundError:
            raise PKIError("The folder for --output does not exist") from None
        try:
            with profile:
                restrict_to_owner(output)
                target = self.create_identity(name, days=days)
                settings = f"client\ndev tun\nproto {transport}\nremote {endpoint} {port}\nnobind\nremote-cert-tls server\nverify-x509-name ghostlink-server name\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nauth SHA256\nauth-nocache\nallow-compression no\n"
                settings += "redirect-gateway def1\n" if mode == "full" else "route-nopull\nroute 10.8.0.0 255.255.255.0\n"
                for tag, source in [("ca", self.root / "ca.crt"), ("cert", target / "client.crt"), ("key", target / "client.key"), ("tls-crypt", self.root / "tls-crypt.key")]:
                    settings += f"<{tag}>\n{source.read_text().strip()}\n</{tag}>\n"
                # CA PRIVATE KEY IS NEVER READ OR ADDED TO A CLIENT PROFILE.
                profile.write(settings)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        return output

    def revoke(self, name):
        name = identity(name)
        cert = self.root / "clients" / name / "client.crt"
        if not cert.is_file():
            raise PKIError(f"No client named {name}")
        self.run("ca", "-config", "openssl.cnf", "-revoke", cert, "-crl_reason", "cessationOfOperation", "-passin", "stdin", secret=True)
        self.crl()

    def bundle(self, output):
        # Explicit file list prevents accidentally deploying the CA private key or client keys.
        names = ["ca.crt", "server.crt", "server.key", "tls-crypt.key", "crl.pem"]
        missing = [name for name in names if not (self.root / name).is_file()]
        if missing:
            raise PKIError("Run server first; the bundle needs " + ", ".join(missing))
        output = Path(output)
        try:
            archive = tarfile.open(output, "x:gz")
        except FileExistsError:
            raise PKIError("The bundle file already exists; give a new file name") from None
        except FileNotFoundError:
            raise PKIError("The folder for --output does not exist") from None
        try:
            with archive:
                restrict_to_owner(output)
                for name in names:
                    info = archive.gettarinfo(str(self.root / name), arcname=name)
                    info.mode = 0o600 if name.endswith(".key") else 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    with open(self.root / name, "rb") as source:
                        archive.addfile(info, source)
        except BaseException:
            # A partial archive can already hold the server key.
            output.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--openssl", default=shutil.which("openssl") or "openssl")
    parser.add_argument("--passphrase-file", type=Path, help="Private file; passphrase itself is never an argument")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    server = commands.add_parser("server", help="Make the server identity (365 days) and the tls-crypt key. To renew, move server.key, server.csr and server.crt out of the root and run it again")
    server.add_argument("--openvpn", default=shutil.which("openvpn") or "openvpn")
    issue = commands.add_parser("issue")
    issue.add_argument("name", type=identity)
    issue.add_argument("--endpoint", required=True)
    issue.add_argument("--port", type=int, choices=range(1, 65536), default=1194, metavar="PORT")
    issue.add_argument("--transport", choices=["udp", "tcp-client"], default="udp")
    issue.add_argument("--mode", choices=["full", "split"], default="split")
    issue.add_argument("--days", type=int, choices=range(1, 366), default=365, metavar="DAYS")
    issue.add_argument("--output", type=Path, required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("name", type=identity)
    commands.add_parser("crl", help=f"Make a new CRL, valid for {CRL_DAYS} days; deploy it in a new bundle")
    bundle = commands.add_parser("bundle")
    bundle.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.passphrase_file:
        if os.name != "nt" and args.passphrase_file.stat().st_mode & 0o077:
            raise PKIError("Passphrase file must have permissions 0600 or stricter")
        password = args.passphrase_file.read_text().rstrip("\r\n")
    else:
        password = getpass.getpass("Offline CA passphrase: ")
        # A typo here would make a CA that no later command can unlock.
        if args.command == "init" and getpass.getpass("Repeat the passphrase: ") != password:
            raise PKIError("The passphrases do not match; nothing was created")
    if len(password) < 16 or "\n" in password or "\r" in password:
        raise PKIError("Use a CA passphrase of at least 16 characters on one line")
    pki = PKI(args.root, args.openssl, password)
    if args.command == "init":
        if pki.root.exists():
            raise PKIError("--root already exists; init makes a new folder")
        pki.init()
    else:
        if not (pki.root / "openssl.cnf").is_file():
            raise PKIError("No PKI at --root; run init first")
        # Windows Python before 3.12.4 ignores mkdir modes; this also protects a PKI one of those made.
        restrict_to_owner(pki.root, directory=True)
        with pki.lock():
            if args.command == "server": pki.server(args.openvpn)
            elif args.command == "issue": pki.issue(args.name, args.endpoint, args.port, args.transport, args.mode, args.output, args.days)
            elif args.command == "revoke": pki.revoke(args.name)
            elif args.command == "crl": pki.crl()
            elif args.command == "bundle": pki.bundle(args.output)
    print(json.dumps({"success": True, "operation": args.command}))


if __name__ == "__main__":
    try:
        main()
    except (PKIError, RuntimeError) as error:
        # Both carry fixed text from this tool; OpenSSL's own output is never shown.
        print(json.dumps({"success": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({"success": False, "error": "PKI operation failed; check identity uniqueness, paths, private file permissions and CA passphrase. Inspect offline state before retrying a partial issuance."}), file=sys.stderr)
        sys.exit(1)
