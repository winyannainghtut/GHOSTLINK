#!/usr/bin/env python3
"""Sends one DNS A query over UDP and prints the response code (NOERROR, NXDOMAIN, ...) or
TIMEOUT. Usage: dnsquery.py SERVER NAME"""
import random
import socket
import struct
import sys

server, name = sys.argv[1], sys.argv[2]
ident = random.randrange(65536)
question = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"
packet = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(4)
try:
    sock.sendto(packet, (server, 53))
    reply, _ = sock.recvfrom(1500)
except OSError:
    print("TIMEOUT")
    sys.exit(0)
code = struct.unpack(">H", reply[2:4])[0] & 0xF
print({0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(code, f"RCODE{code}"))
