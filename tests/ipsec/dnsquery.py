#!/usr/bin/env python3
"""Sends one DNS query the way a phone does and prints what came back, as one line:

  NOERROR, NXDOMAIN, SERVFAIL, REFUSED or RCODE<n>   the response code (with --count, followed by
                                                      the number of answers: "NOERROR 2")
  TIMEOUT                                             nothing came back
  WRONGSOURCE ADDRESS:PORT                            the answer came from another address than
                                                      the one asked: a phone drops such an answer

Usage: dnsquery.py [--type A|AAAA|HTTPS|SVCB] [--tcp] [--count] SERVER NAME

The query goes to SERVER port 53, over UDP unless --tcp. The answer's source is checked against
SERVER:53, because that is what the client's resolver does and what the reverse NAT of the
server's DNS redirect has to produce (code review 2026-11-10, IKEv2 findings v0.8.6).
"""
import argparse
import random
import socket
import struct
import sys

TYPES = {"A": 1, "AAAA": 28, "SVCB": 64, "HTTPS": 65}
CODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

parser = argparse.ArgumentParser()
parser.add_argument("--type", default="A", choices=sorted(TYPES))
parser.add_argument("--tcp", action="store_true")
parser.add_argument("--count", action="store_true")
parser.add_argument("server")
parser.add_argument("name")
args = parser.parse_args()

ident = random.randrange(65536)
question = b"".join(bytes([len(label)]) + label.encode() for label in args.name.rstrip(".").split(".")) + b"\0"
packet = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", TYPES[args.type], 1)


def read_exactly(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


try:
    if args.tcp:
        sock = socket.create_connection((args.server, 53), timeout=4)
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        reply = read_exactly(sock, struct.unpack(">H", read_exactly(sock, 2))[0])
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        sock.sendto(packet, (args.server, 53))
        reply, source = sock.recvfrom(4096)
        if source != (args.server, 53):
            print(f"WRONGSOURCE {source[0]}:{source[1]}")
            sys.exit(0)
except OSError:
    print("TIMEOUT")
    sys.exit(0)
if len(reply) < 12 or struct.unpack(">H", reply[:2])[0] != ident:
    print("TIMEOUT")
    sys.exit(0)
flags, _, answers = struct.unpack(">HHH", reply[2:8])
code = CODES.get(flags & 0xF, f"RCODE{flags & 0xF}")
print(f"{code} {answers}" if args.count else code)
