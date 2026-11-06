import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable
OPENSSL = os.environ.get("MYVPN_TEST_OPENSSL", r"C:\Program Files\Git\usr\bin\openssl.exe" if os.name == "nt" else "openssl")
ENGINE = Path(os.environ.get("MYVPN_TEST_SING_BOX", ROOT / ".tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe"))
OPENVPN = Path(os.environ.get("MYVPN_TEST_ENGINE", ROOT / ".tools/openvpn-bin/openvpn.exe" if os.name == "nt" else shutil.which("openvpn") or "/usr/sbin/openvpn"))


class ProvisioningTests(unittest.TestCase):
    def test_outline_generation_unique_keys_and_removal(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            root = Path(temporary) / "outline"
            command = [PYTHON, str(ROOT / "server/outline/provision.py"), "--directory", str(root)]
            self.assertTrue(json.loads(subprocess.check_output(command + ["init", "--listen", "127.0.0.1"]))["success"])
            first = subprocess.check_output(command + ["add", "--name", "laptop", "--endpoint", "127.0.0.1", "--port", "15001"])
            second = subprocess.check_output(command + ["add", "--name", "phone", "--endpoint", "127.0.0.1", "--port", "15002"])
            state = json.loads((root / "state.json").read_text())
            self.assertNotEqual(state["keys"]["laptop"]["password"], state["keys"]["phone"]["password"])
            for password in [key["password"] for key in state["keys"].values()]:
                self.assertNotIn(password.encode(), first + second)
            self.assertTrue((root / "laptop.access-key").read_text().startswith("ss://"))
            if ENGINE.is_file():
                subprocess.run([str(ENGINE), "check", "-c", str(root / "config.json")], check=True, capture_output=True)
            subprocess.run(command + ["remove", "--name", "phone"], check=True, capture_output=True)
            self.assertEqual([item["tag"] for item in json.loads((root / "config.json").read_text())["inbounds"]], ["laptop"])
            duplicate = subprocess.run(command + ["add", "--name", "laptop", "--endpoint", "example.com", "--port", "15003"], capture_output=True)
            self.assertEqual(duplicate.returncode, 1)

    @unittest.skipUnless(OPENVPN.is_file(), "Standalone OpenVPN required for official tls-crypt generation")
    def test_openvpn_offline_ca_issuance_bundle_and_revocation(self):
        spec = importlib.util.spec_from_file_location("myvpn_pki", ROOT / "server/openvpn/pki.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix=".state-pki-", dir=ROOT) as temporary:
            root = Path(temporary)
            pki = module.PKI(root / "pki", OPENSSL, "test-only-long-ca-passphrase")
            old_umask = os.umask(0o077)
            try:
                pki.init()
                pki.server(str(OPENVPN))
                profile = pki.issue("laptop", "vpn.example.com", 1194, "udp", "split", root / "laptop.ovpn", 30)
                contents = profile.read_text()
                self.assertIn("<tls-crypt>", contents)
                self.assertNotIn((pki.root / "ca.key").read_text().strip(), contents)
                pki.bundle(root / "server.tar.gz")
                import tarfile
                with tarfile.open(root / "server.tar.gz") as archive:
                    self.assertEqual(set(archive.getnames()), {"ca.crt", "server.crt", "server.key", "tls-crypt.key", "crl.pem"})
                pki.revoke("laptop")
                verify = subprocess.run([OPENSSL, "verify", "-CAfile", str(pki.root / "ca.crt"), "-CRLfile", str(pki.root / "crl.pem"), "-crl_check", str(pki.root / "clients/laptop/client.crt")], capture_output=True)
                self.assertNotEqual(verify.returncode, 0)
                self.assertIn(b"revoked", verify.stderr)
            finally:
                os.umask(old_umask)


if __name__ == "__main__":
    unittest.main()
