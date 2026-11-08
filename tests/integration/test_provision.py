import contextlib
import http.server
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable
OPENSSL = os.environ.get("GHOSTLINK_TEST_OPENSSL", r"C:\Program Files\Git\usr\bin\openssl.exe" if os.name == "nt" else "openssl")
ENGINE = Path(os.environ.get("GHOSTLINK_TEST_SING_BOX", ROOT / (".tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe" if os.name == "nt" else ".tools/sing-box/sing-box-1.14.4-linux-amd64/sing-box")))
OPENVPN = Path(os.environ.get("GHOSTLINK_TEST_ENGINE", ROOT / ".tools/openvpn-bin/openvpn.exe" if os.name == "nt" else shutil.which("openvpn") or "/usr/sbin/openvpn"))
PROVISION = ROOT / "server/outline/provision.py"
PASSPHRASE = "test-only-long-ca-passphrase"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def private_umask():
    # The tools set umask 077 themselves; the tests run their code in this process.
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def provision(directory, *arguments):
    return subprocess.run([PYTHON, str(PROVISION), "--directory", str(directory), *arguments], capture_output=True)


def error_of(result):
    return json.loads(result.stdout or result.stderr)["error"]


def free_port():
    """A loopback port free for TCP and UDP alike, as a Shadowsocks listener takes both."""
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("No free loopback port")


@contextlib.contextmanager
def running(config, port):
    """Run the engine with config until it is stopped, once it listens on port."""
    process = subprocess.Popen([str(ENGINE), "run", "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise AssertionError("sing-box stopped before it listened")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError("sing-box did not listen in time")
                time.sleep(0.05)
        yield
    finally:
        process.terminate()
        process.wait(timeout=10)


class Inside(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"inside"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *arguments):
        pass


@contextlib.contextmanager
def loopback_web_server():
    """A web server only the host itself should reach, like a service bound to loopback."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Inside)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def receive(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def fetch(proxy_port, host, port):
    """Ask the local SOCKS5 proxy for http://host:port/ and return the reply; b"" if refused."""
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as connection:
        connection.sendall(b"\x05\x01\x00")
        if receive(connection, 2) != b"\x05\x00":
            raise AssertionError("SOCKS5 greeting refused")
        try:
            address = b"\x01" + socket.inet_aton(host)
        except OSError:
            address = b"\x03" + bytes([len(host)]) + host.encode()
        connection.sendall(b"\x05\x01\x00" + address + port.to_bytes(2, "big"))
        head = receive(connection, 4)
        if head is None or head[1] != 0:
            return b""
        length = {1: 4, 4: 16}.get(head[3])
        if length is None:
            size = receive(connection, 1)
            length = size[0] if size else 0
        if receive(connection, length + 2) is None:
            return b""
        connection.sendall(b"GET / HTTP/1.0\r\nHost: inside\r\n\r\n")
        reply = b""
        try:
            while chunk := connection.recv(4096):
                reply += chunk
        except OSError:
            pass
        return reply


class ProvisioningTests(unittest.TestCase):
    def test_outline_generation_unique_keys_and_removal(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            root = Path(temporary) / "outline"
            command = [PYTHON, str(PROVISION), "--directory", str(root)]
            self.assertTrue(json.loads(subprocess.check_output(command + ["init", "--listen", "127.0.0.1"]))["success"])
            first = subprocess.check_output(command + ["add", "--name", "laptop", "--endpoint", "127.0.0.1", "--port", "15001"])
            second = subprocess.check_output(command + ["add", "--name", "phone", "--endpoint", "127.0.0.1", "--port", "15002"])
            state = json.loads((root / "state.json").read_text())
            self.assertNotEqual(state["keys"]["laptop"]["password"], state["keys"]["phone"]["password"])
            for password in [key["password"] for key in state["keys"].values()]:
                self.assertNotIn(password.encode(), first + second)
            self.assertTrue((root / "laptop.access-key").read_text().startswith("ss://"))
            subprocess.run(command + ["remove", "--name", "phone"], check=True, capture_output=True)
            self.assertEqual([item["tag"] for item in json.loads((root / "config.json").read_text())["inbounds"]], ["laptop"])
            duplicate = subprocess.run(command + ["add", "--name", "laptop", "--endpoint", "example.com", "--port", "15003"], capture_output=True)
            self.assertEqual(duplicate.returncode, 1)
            # A removed name keeps its export as a backup, and the refusal says so.
            again = provision(root, "add", "--name", "phone", "--endpoint", "127.0.0.1", "--port", "15004")
            self.assertEqual(again.returncode, 1)
            self.assertIn("phone.access-key", error_of(again))

    def test_outline_config_blocks_internal_destinations(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            root = Path(temporary) / "outline"
            provision(root, "init").check_returncode()
            provision(root, "add", "--name", "laptop", "--endpoint", "203.0.113.7", "--port", "15001").check_returncode()
            provision(root, "add", "--name", "phone", "--endpoint", "vpn.example.com", "--port", "15002").check_returncode()
            config = json.loads((root / "config.json").read_text())
            rules = config["route"]["rules"]
            # Names are resolved before the blocks, so a name that points inside is caught as well.
            self.assertEqual(rules[0]["action"], "resolve")
            self.assertIn({"ip_is_private": True, "action": "reject"}, rules)
            blocked = next(rule["ip_cidr"] for rule in rules if "ip_cidr" in rule)
            for cidr in ["127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "203.0.113.7/32"]:
                self.assertIn(cidr, blocked)
            self.assertEqual(config["route"]["final"], "direct")
            self.assertEqual({inbound["listen"] for inbound in config["inbounds"]}, {"::"})

    @unittest.skipUnless(ENGINE.is_file(), "The pinned sing-box runs the generated proxy; set GHOSTLINK_TEST_SING_BOX")
    def test_outline_proxy_refuses_internal_destinations(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary, loopback_web_server() as web_port:
            temporary = Path(temporary)
            root = temporary / "outline"
            provision(root, "init", "--listen", "127.0.0.1").check_returncode()
            provision(root, "add", "--name", "laptop", "--endpoint", "127.0.0.1", "--port", str(free_port())).check_returncode()
            config = root / "config.json"
            subprocess.run([str(ENGINE), "check", "-c", str(config)], check=True, capture_output=True)
            key = json.loads((root / "state.json").read_text())["keys"]["laptop"]
            blocked = json.loads(config.read_text())
            # Names come from a fixed table here, so the test sends no DNS query; the route rules
            # under test are the generated ones.
            blocked["dns"]["servers"] = [{"type": "hosts", "tag": "local", "predefined": {"inside.test": ["127.0.0.1"]}}]
            # The same configuration without its reject rules shows that the harness reaches the service at all.
            unblocked = json.loads(json.dumps(blocked))
            unblocked["route"]["rules"] = [rule for rule in unblocked["route"]["rules"] if rule["action"] != "reject"]
            unblocked["inbounds"][0]["listen_port"] = free_port()
            for name, server, reachable in [("unblocked", unblocked, True), ("generated", blocked, False)]:
                server_port = server["inbounds"][0]["listen_port"]
                (temporary / "server.json").write_text(json.dumps(server))
                client_port = free_port()
                client = {"log": {"disabled": True},
                          "inbounds": [{"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": client_port}],
                          "outbounds": [{"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": server_port, "method": key["method"], "password": key["password"]}]}
                (temporary / "client.json").write_text(json.dumps(client))
                with running(temporary / "server.json", server_port), running(temporary / "client.json", client_port):
                    for host in ["127.0.0.1", "inside.test"]:
                        reply = fetch(client_port, host, web_port)
                        self.assertEqual(reply.startswith(b"HTTP/1.0 200"), reachable, f"{host} through the {name} rules")

    def test_outline_listener_answers_the_endpoint_family(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            dual, ipv4 = Path(temporary) / "dual", Path(temporary) / "ipv4"
            provision(dual, "init").check_returncode()
            self.assertEqual(json.loads((dual / "state.json").read_text())["listen"], "::")
            provision(dual, "add", "--name", "v6", "--endpoint", "2001:db8::10", "--port", "15001").check_returncode()
            self.assertIn("@[2001:db8::10]:15001/", (dual / "v6.access-key").read_text())
            # A state made with an IPv4 listener, as init made by default before, cannot serve an IPv6 key.
            provision(ipv4, "init", "--listen", "0.0.0.0").check_returncode()
            refused = provision(ipv4, "add", "--name", "v6", "--endpoint", "2001:db8::10", "--port", "15001")
            self.assertEqual(refused.returncode, 1)
            self.assertIn("--listen", error_of(refused))
            self.assertFalse((ipv4 / "v6.access-key").exists())
            provision(ipv4, "add", "--name", "v4", "--endpoint", "192.0.2.10", "--port", "15001").check_returncode()
            provision(ipv4, "add", "--name", "named", "--endpoint", "vpn.example.com", "--port", "15002").check_returncode()

    def test_outline_failures_leave_nothing_behind_and_say_why(self):
        module = load("ghostlink_provision", "server/outline/provision.py")
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            root = Path(temporary) / "outline"
            provision(root, "init", "--listen", "127.0.0.1").check_returncode()
            add = ["add", "--name", "laptop", "--endpoint", "192.0.2.10", "--port", "15001"]
            write = module.atomic_private_json

            def state_write_fails(path, value):
                if path.name == "state.json":
                    raise OSError("disk full")
                write(path, value)

            with mock.patch.object(sys, "argv", ["provision.py", "--directory", str(root), *add]), \
                    mock.patch.object(module, "atomic_private_json", state_write_fails), \
                    contextlib.redirect_stdout(io.StringIO()), private_umask():
                with self.assertRaises(OSError):
                    module.main()
            # The key never reached the state, so no export is left to block its name.
            self.assertFalse((root / "laptop.access-key").exists())
            self.assertEqual(json.loads((root / "state.json").read_text())["keys"], {})
            provision(root, *add).check_returncode()
            # A command that was killed leaves its lock behind; the refusal names it.
            (root / ".provision.lock").write_text("")
            locked = provision(root, "list")
            self.assertEqual(locked.returncode, 1)
            self.assertIn(".provision.lock", error_of(locked))

    @unittest.skipUnless(os.name == "nt", "Windows permissions")
    def test_outline_private_directory_refuses_other_accounts(self):
        with tempfile.TemporaryDirectory(prefix=".state-provision-", dir=ROOT) as temporary:
            root = Path(temporary) / "outline"
            root.mkdir()
            icacls = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"
            # An explicit grant survives the inheritance reset; the key passwords would be readable by Users.
            subprocess.run([str(icacls), str(root), "/grant", "*S-1-5-32-545:(OI)(CI)R"], check=True, capture_output=True)
            refused = provision(root, "init")
            self.assertEqual(refused.returncode, 1)
            self.assertIn("other accounts", error_of(refused))
            self.assertFalse((root / "state.json").exists())

    @unittest.skipUnless(OPENVPN.is_file(), "Standalone OpenVPN required for official tls-crypt generation")
    def test_openvpn_offline_ca_issuance_bundle_and_revocation(self):
        module = load("ghostlink_pki", "server/openvpn/pki.py")
        with tempfile.TemporaryDirectory(prefix=".state-pki-", dir=ROOT) as temporary:
            root = Path(temporary)
            pki = module.PKI(root / "pki", OPENSSL, PASSPHRASE)
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
