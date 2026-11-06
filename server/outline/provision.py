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


def private_directory(path):
    path = Path(path).absolute()
    if path.exists() and (path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400):
        raise ValueError("Private directory must not be a link")
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
    else:
        if path.stat().st_uid != os.geteuid():
            raise ValueError("Private directory has a different owner")
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
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        yield
    finally:
        os.close(descriptor)
        path.unlink()


def server_config(state):
    return {"log": {"disabled": True}, "inbounds": [
        {"type": "shadowsocks", "tag": name, "listen": state["listen"], "listen_port": key["port"], "method": key["method"], "password": key["password"]}
        for name, key in sorted(state["keys"].items())
    ], "outbounds": [{"type": "direct"}]}


def access_key(key, display_name):
    credential = base64.urlsafe_b64encode(f"{key['method']}:{key['password']}".encode()).decode().rstrip("=")
    host = f"[{key['endpoint']}]" if ":" in key["endpoint"] else key["endpoint"]
    return f"ss://{credential}@{host}:{key['port']}/?outline=1#{quote(display_name, safe='')}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--listen", default="0.0.0.0", type=ipaddress.ip_address)
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
    with locked(root):
        state_path = root / "state.json"
        if args.command == "init":
            if state_path.exists():
                raise ValueError("Server provisioning state already exists")
            state = {"schema_version": 1, "listen": str(args.listen), "keys": {}}
        else:
            state = json.loads(state_path.read_text())
            if state.get("schema_version") != 1:
                raise ValueError("Unsupported provisioning state")
        output = {"success": True, "operation": args.command}
        if args.command == "add":
            if args.name in state["keys"] or any(key["port"] == args.port for key in state["keys"].values()):
                raise ValueError("Use a unique identity and a separate unused port")
            if not 1 <= args.port <= 65535:
                raise ValueError("Invalid port")
            label = args.display_name or args.name
            if not label.strip() or len(label) > 80 or any(ord(char) < 32 for char in label):
                raise ValueError("Invalid display name")
            key = {"endpoint": args.endpoint, "port": args.port, "method": "aes-256-gcm", "password": secrets.token_urlsafe(32)}
            key_path = root / f"{args.name}.access-key"
            with open(key_path, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600), newline="\n") as output_file:
                output_file.write(access_key(key, label))
            state["keys"][args.name] = key
            output["access_key_file"] = str(key_path)
        elif args.command == "remove":
            if state["keys"].pop(args.name, None) is None:
                raise ValueError("Unknown identity")
        if args.command != "list":
            # State is authoritative; deploy config.json only after a successful command.
            atomic_private_json(state_path, state)
            atomic_private_json(root / "config.json", server_config(state))
        output["keys"] = [{"name": name, "port": value["port"], "endpoint": value["endpoint"]} for name, value in sorted(state["keys"].items())]
        output["deployment_required"] = args.command != "list"
        print(json.dumps(output))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({"success": False, "error": "Provisioning failed; inspect private state, unique identity/port, endpoint and permissions. No remote server change was performed."}))
        raise SystemExit(1)
