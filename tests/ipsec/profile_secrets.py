#!/usr/bin/env python3
"""Prints every secret an Apple profile carries, one per line: the EAP or XAuth password, the
shared group key and the password of the embedded PKCS#12 identity. The interop test greps the
component's logs for them, so none may ever be logged.

Usage: profile_secrets.py PROFILE.mobileconfig [...]
"""
import plistlib
import sys
from pathlib import Path


def secrets(profile):
    for payload in profile["PayloadContent"]:
        if payload["PayloadType"] == "com.apple.security.pkcs12":
            yield payload.get("Password")
        if payload["PayloadType"] == "com.apple.vpn.managed":
            settings = payload[payload["VPNType"]]
            yield settings.get("AuthPassword")
            yield settings.get("XAuthPassword")
            shared = settings.get("SharedSecret")
            yield shared.decode() if isinstance(shared, bytes) else shared


def main() -> None:
    for path in sys.argv[1:]:
        for secret in secrets(plistlib.loads(Path(path).read_bytes())):
            if secret:
                print(secret)


if __name__ == "__main__":
    main()
