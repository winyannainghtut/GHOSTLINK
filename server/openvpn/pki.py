#!/usr/bin/env python3
"""OpenSSL-backed personal PKI. No cryptography is implemented here.

CA passphrases are supplied on stdin to OpenSSL, never in process arguments.
The PKI directory is offline material; deploy only the server bundle, never the CA key.
"""
import argparse
import contextlib
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


def identity(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Identity must contain 1-64 ASCII letters, digits, hyphens or underscores")
    return value


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

    @contextlib.contextmanager
    def lock(self):
        lock = self.root / ".pki.lock"
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, str(os.getpid()).encode())
            yield
        finally:
            os.close(descriptor)
            lock.unlink()

    def init(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
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
default_crl_days = 30
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
        if not server:
            target.mkdir(mode=0o700, exist_ok=False)
        base = "server" if server else "client"
        key = target / f"{base}.key"
        csr = target / f"{base}.csr"
        cert = target / f"{base}.crt"
        if key.exists() or cert.exists():
            raise ValueError("Identity already exists; revoke it and use a new identity name")
        self.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", key)
        self.run("req", "-new", "-sha384", "-config", "openssl.cnf", "-subj", f"/CN={name}", "-key", key, "-out", csr)
        self.run("ca", "-config", "openssl.cnf", "-batch", "-rand_serial", "-notext", "-days", str(days), "-extensions", "server_cert" if server else "client_cert", "-in", csr, "-out", cert, "-passin", "stdin", secret=True)
        return target

    def crl(self):
        self.run("ca", "-config", "openssl.cnf", "-gencrl", "-out", "crl.pem", "-passin", "stdin", secret=True)

    def server(self, openvpn):
        self.create_identity("ghostlink-server", server=True)
        result = subprocess.run([str(openvpn), "--genkey", "secret", str(self.root / "tls-crypt.key")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            raise RuntimeError("OpenVPN TLS-crypt key generation failed")
        self.crl()

    def issue(self, name, endpoint, port, transport, mode, output, days):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", endpoint):
            raise ValueError("Invalid public endpoint")
        if not (self.root / "tls-crypt.key").is_file():
            raise ValueError("Generate the server identity first")
        output = Path(output).resolve()
        if output.exists():
            raise ValueError("Profile output already exists")
        target = self.create_identity(name, days=days)
        settings = f"client\ndev tun\nproto {transport}\nremote {endpoint} {port}\nnobind\nremote-cert-tls server\nverify-x509-name ghostlink-server name\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nauth SHA256\nauth-nocache\nallow-compression no\n"
        settings += "redirect-gateway def1\n" if mode == "full" else "route-nopull\nroute 10.8.0.0 255.255.255.0\n"
        for tag, source in [("ca", self.root / "ca.crt"), ("cert", target / "client.crt"), ("key", target / "client.key"), ("tls-crypt", self.root / "tls-crypt.key")]:
            settings += f"<{tag}>\n{source.read_text().strip()}\n</{tag}>\n"
        # CA PRIVATE KEY IS NEVER READ OR ADDED TO A CLIENT PROFILE.
        private_write(output, settings)
        return output

    def revoke(self, name):
        name = identity(name)
        cert = self.root / "clients" / name / "client.crt"
        self.run("ca", "-config", "openssl.cnf", "-revoke", cert, "-crl_reason", "cessationOfOperation", "-passin", "stdin", secret=True)
        self.crl()

    def bundle(self, output):
        # Explicit file list prevents accidentally deploying the CA private key or client keys.
        with tarfile.open(output, "x:gz") as archive:
            for name in ["ca.crt", "server.crt", "server.key", "tls-crypt.key", "crl.pem"]:
                info = archive.gettarinfo(str(self.root / name), arcname=name)
                info.mode = 0o600 if name.endswith(".key") else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                with open(self.root / name, "rb") as source:
                    archive.addfile(info, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--openssl", default=shutil.which("openssl") or "openssl")
    parser.add_argument("--passphrase-file", type=Path, help="Private file; passphrase itself is never an argument")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    server = commands.add_parser("server")
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
    commands.add_parser("crl")
    bundle = commands.add_parser("bundle")
    bundle.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.passphrase_file:
        if os.name != "nt" and args.passphrase_file.stat().st_mode & 0o077:
            raise ValueError("Passphrase file must have permissions 0600 or stricter")
        password = args.passphrase_file.read_text().rstrip("\r\n")
    else:
        password = getpass.getpass("Offline CA passphrase: ")
    if len(password) < 16 or "\n" in password or "\r" in password:
        raise ValueError("Use a CA passphrase of at least 16 characters on one line")
    pki = PKI(args.root, args.openssl, password)
    if args.command == "init":
        pki.init()
    else:
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
    except (ValueError, RuntimeError, OSError):
        print(json.dumps({"success": False, "error": "PKI operation failed; check identity uniqueness, paths, private file permissions and CA passphrase. Inspect offline state before retrying a partial issuance."}), file=sys.stderr)
        sys.exit(1)
