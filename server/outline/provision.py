#!/usr/bin/env python3
"""Generate private, standard Outline-compatible server keys/configuration offline.

Each identity has its own listener port and random AEAD credential. Deploy the updated
configuration and restart the server to apply additions/removals. No remote API is called.
"""
import argparse
import base64
import contextlib
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
from urllib.parse import quote

# Destinations no key holder may reach through the proxy. It runs on the host itself, so without
# these blocks every key would also reach the host's loopback services, its private network and
# the cloud metadata endpoint. They are the ranges the Ghostlink server always blocks.
INTERNAL_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
    "fc00::/7", "fe80::/10", "ff00::/8",
]


class ProvisionError(ValueError):
    """A failure whose message names no secret, so it is printed as it is."""


def valid_name(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Use a name containing 1-64 ASCII letters, digits, hyphens or underscores")
    return value


def valid_endpoint(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in value.split(".")):
            raise ValueError("Invalid public endpoint")
    return value


def windows_security(path):
    """Return the owner and DACL of path as SDDL, which names accounts the same way in every language."""
    import ctypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    out = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, out, out, out, out, out]
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, out, ctypes.c_void_p]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    owner_and_dacl = 0x1 | 0x4
    descriptor, text = ctypes.c_void_p(), ctypes.c_void_p()
    error = advapi32.GetNamedSecurityInfoW(str(path), 1, owner_and_dacl, None, None, None, None, ctypes.byref(descriptor))
    if error:
        raise OSError(error, "Cannot read private directory permissions")
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, owner_and_dacl, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.wstring_at(text.value)
    finally:
        kernel32.LocalFree(descriptor)
        if text.value:
            kernel32.LocalFree(text)


def check_windows_private(path, sid):
    # icacls removes inherited access and replaces this account's and SYSTEM's grants, but an
    # existing directory keeps explicit grants to other accounts, and its owner can always give
    # itself access again. SDDL writes SYSTEM, Administrators, "owner rights" (which a private
    # mkdir grants) and the built-in Administrator account as two-letter aliases.
    trusted = {sid, "SY", "BA", "OW", "LA"}
    sddl = windows_security(path)
    owner = re.match(r"O:(.*?)D:", sddl)
    if owner is None or owner.group(1) not in trusted:
        raise ProvisionError("The private directory is owned by another account; choose a new directory")
    for ace in re.findall(r"\(([^()]*)\)", sddl):
        fields = ace.split(";")
        # Deny entries (D, OD, XD) only take access away.
        if len(fields) < 6 or (not fields[0].endswith("D") and fields[5] not in trusted):
            raise ProvisionError("The private directory gives other accounts access; remove their permissions or choose a new directory")


def private_directory(path):
    path = Path(path).absolute()
    if path.exists() and (path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400):
        raise ProvisionError("Private directory must not be a link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        # Absolute System32 paths: a bare name can resolve to an unrelated tool on PATH, such as
        # Git for Windows' GNU whoami, which rejects these arguments.
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        result = subprocess.check_output([str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"], text=True)
        sid = next(csv.reader([result.strip()]))[-1]
        if not re.fullmatch(r"S-1-[0-9-]+", sid):
            raise ValueError("Cannot identify private storage owner")
        subprocess.run([str(system32 / "icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check_windows_private(path, sid)
    else:
        if path.stat().st_uid != os.geteuid():
            raise ProvisionError("Private directory has a different owner")
        path.chmod(0o700)
    return path


def atomic_private_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".transaction-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def locked(root):
    path = root / ".provision.lock"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # A command that was killed leaves its lock behind, and nothing else would say so.
        raise ProvisionError("Another command is using this directory (.provision.lock exists). If none is running, an earlier one was interrupted: delete .provision.lock and try again") from None
    try:
        yield
    finally:
        os.close(descriptor)
        path.unlink()


def server_config(state):
    # The server's own address, when a key names it, is blocked too: the proxy's connection to it
    # is local, so it would reach host services that a firewall only opens to the administrator.
    own = sorted({str(ipaddress.ip_network(key["endpoint"].split("%")[0])) for key in state["keys"].values() if is_address(key["endpoint"])})
    rules = [
        # Resolve names first, so that a name pointing inside is blocked as well.
        {"action": "resolve", "strategy": "prefer_ipv4"},
        {"ip_is_private": True, "action": "reject"},
        {"ip_cidr": INTERNAL_RANGES + own, "action": "reject"},
    ]
    return {"log": {"disabled": True},
            "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local", "strategy": "prefer_ipv4"},
            "inbounds": [
                {"type": "shadowsocks", "tag": name, "listen": state["listen"], "listen_port": key["port"], "method": key["method"], "password": key["password"]}
                for name, key in sorted(state["keys"].items())
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": rules, "final": "direct", "default_domain_resolver": {"server": "local", "strategy": "prefer_ipv4"}}}


def is_address(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def listener_serves(listen, endpoint):
    """Whether a proxy listening on `listen` answers clients that dial `endpoint`."""
    if not is_address(endpoint):
        return True  # A name may resolve to either family; nothing can be checked offline.
    listen = ipaddress.ip_address(listen)
    # sing-box listens on IPv4 only for an IPv4 address, 0.0.0.0 included; "::" takes both.
    return listen == ipaddress.IPv6Address("::") or listen.version == ipaddress.ip_address(endpoint).version


def access_key(key, display_name):
    credential = base64.urlsafe_b64encode(f"{key['method']}:{key['password']}".encode()).decode().rstrip("=")
    host = f"[{key['endpoint']}]" if ":" in key["endpoint"] else key["endpoint"]
    return f"ss://{credential}@{host}:{key['port']}/?outline=1#{quote(display_name, safe='')}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    # "::" listens on IPv4 and IPv6 alike; 0.0.0.0 would never answer a key with an IPv6 endpoint.
    init.add_argument("--listen", default="::", type=ipaddress.ip_address)
    add = commands.add_parser("add")
    add.add_argument("--name", required=True, type=valid_name)
    add.add_argument("--endpoint", required=True, type=valid_endpoint)
    add.add_argument("--port", required=True, type=int)
    add.add_argument("--display-name")
    commands.add_parser("list")
    commands.add_parser("render")
    remove = commands.add_parser("remove")
    remove.add_argument("--name", required=True, type=valid_name)
    args = parser.parse_args()
    os.umask(0o077)
    root = private_directory(args.directory)
    with locked(root), contextlib.ExitStack() as rollback:
        state_path = root / "state.json"
        if args.command == "init":
            if state_path.exists():
                raise ProvisionError("Server provisioning state already exists")
            state = {"schema_version": 1, "listen": str(args.listen), "keys": {}}
        else:
            if not state_path.exists():
                raise ProvisionError("No provisioning state in this directory; run init first")
            state = json.loads(state_path.read_text())
            if state.get("schema_version") != 1:
                raise ProvisionError("Unsupported provisioning state")
        output = {"success": True, "operation": args.command}
        if args.command == "add":
            if args.name in state["keys"] or any(key["port"] == args.port for key in state["keys"].values()):
                raise ProvisionError("Use a unique identity and a separate unused port")
            if not 1 <= args.port <= 65535:
                raise ProvisionError("Invalid port")
            if not listener_serves(state["listen"], args.endpoint):
                raise ProvisionError(f"The server listens on {state['listen']} (init --listen), which never answers this endpoint; use an address of the same IP version or a name")
            label = args.display_name or args.name
            if not label.strip() or len(label) > 80 or any(ord(char) < 32 for char in label):
                raise ProvisionError("Invalid display name")
            key = {"endpoint": args.endpoint, "port": args.port, "method": "aes-256-gcm", "password": secrets.token_urlsafe(32)}
            key_path = root / f"{args.name}.access-key"
            if key_path.exists():
                raise ProvisionError(f"{key_path.name} is kept from an earlier key with this name; move it out of the directory or choose another name")
            with open(key_path, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600), newline="\n") as output_file:
                # Until the state holds the key, a failure removes its export, which would only block the name.
                rollback.callback(key_path.unlink, missing_ok=True)
                output_file.write(access_key(key, label))
            state["keys"][args.name] = key
            output["access_key_file"] = str(key_path)
        elif args.command == "remove":
            if state["keys"].pop(args.name, None) is None:
                raise ProvisionError("Unknown identity")
        if args.command != "list":
            # State is authoritative; deploy config.json only after a successful command.
            atomic_private_json(state_path, state)
            rollback.pop_all()
            atomic_private_json(root / "config.json", server_config(state))
        output["keys"] = [{"name": name, "port": value["port"], "endpoint": value["endpoint"]} for name, value in sorted(state["keys"].items())]
        output["deployment_required"] = args.command != "list"
        print(json.dumps(output))


if __name__ == "__main__":
    try:
        main()
    except ProvisionError as error:
        print(json.dumps({"success": False, "error": f"{error}. No remote server change was performed."}))
        raise SystemExit(1)
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({"success": False, "error": "Provisioning failed; inspect private state, unique identity/port, endpoint and permissions. No remote server change was performed."}))
        raise SystemExit(1)
