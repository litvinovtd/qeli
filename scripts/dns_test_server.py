#!/usr/bin/env python3
"""Minimal deterministic DNS responder/probe for isolated release netns tests."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import struct
from pathlib import Path

ANSWERS = {
    1: ipaddress.ip_address("192.0.2.80").packed,
    28: ipaddress.ip_address("2001:db8::80").packed,
}
TYPE_NAMES = {1: "A", 28: "AAAA"}


def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError(f"invalid DNS name: {name!r}")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"


def parse_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels) + ".", offset
        if length & 0xC0:
            raise ValueError("compressed question names are not accepted")
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length


def parse_question(packet: bytes) -> tuple[int, str, int, int]:
    if len(packet) < 12:
        raise ValueError("truncated DNS header")
    txid, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!6H", packet[:12])
    if qdcount != 1:
        raise ValueError("exactly one DNS question is required")
    name, offset = parse_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    if qclass != 1:
        raise ValueError("only IN questions are supported")
    return txid, name, qtype, offset + 4


def build_query(name: str, qtype: int, txid: int) -> bytes:
    return struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def build_response(query: bytes) -> tuple[bytes, str, int]:
    txid, name, qtype, question_end = parse_question(query)
    question = query[12:question_end]
    rdata = ANSWERS.get(qtype)
    if rdata is None:
        return struct.pack("!6H", txid, 0x8180, 1, 0, 0, 0) + question, name, qtype
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return struct.pack("!6H", txid, 0x8180, 1, 1, 0, 0) + question + answer, name, qtype


def parse_answer(packet: bytes, txid: int, qtype: int) -> str:
    if len(packet) < 12:
        raise ValueError("truncated DNS response")
    got_txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!6H", packet[:12])
    if got_txid != txid or not flags & 0x8000 or flags & 0x000F or qdcount != 1 or ancount < 1:
        raise ValueError("invalid DNS response header")
    _name, offset = parse_name(packet, 12)
    offset += 4
    if offset + 12 > len(packet) or packet[offset : offset + 2] != b"\xc0\x0c":
        raise ValueError("invalid DNS answer owner")
    got_type, qclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset + 2 : offset + 12])
    offset += 12
    if got_type != qtype or qclass != 1 or offset + rdlength > len(packet):
        raise ValueError("invalid DNS answer record")
    return str(ipaddress.ip_address(packet[offset : offset + rdlength]))


def family_for(address: str) -> socket.AddressFamily:
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def serve(address: str, log_path: Path) -> None:
    family = family_for(address)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 53))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        query, peer = sock.recvfrom(65535)
        try:
            response, name, qtype = build_response(query)
            sock.sendto(response, peer)
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(
                    f"family={6 if family == socket.AF_INET6 else 4} "
                    f"qtype={TYPE_NAMES.get(qtype, qtype)} qname={name}\n"
                )
                stream.flush()
        except (UnicodeError, ValueError):
            continue


def query(server: str, name: str, qtype: int, expected: str) -> None:
    family = family_for(server)
    txid = int.from_bytes(os.urandom(2), "big")
    request = build_query(name, qtype, txid)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(request, (server, 53))
    response, peer = sock.recvfrom(65535)
    if ipaddress.ip_address(peer[0]) != ipaddress.ip_address(server):
        raise RuntimeError(f"response came from unexpected peer {peer[0]}")
    actual = parse_answer(response, txid, qtype)
    if ipaddress.ip_address(actual) != ipaddress.ip_address(expected):
        raise RuntimeError(f"expected {expected}, received {actual}")
    print(f"PASS: {TYPE_NAMES[qtype]} {name} via {server} -> {actual}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--address", required=True)
    serve_parser.add_argument("--log", required=True, type=Path)
    query_parser = sub.add_parser("query")
    query_parser.add_argument("--server", required=True)
    query_parser.add_argument("--name", required=True)
    query_parser.add_argument("--type", required=True, choices=("A", "AAAA"))
    query_parser.add_argument("--expect", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.address, args.log)
    else:
        query(args.server, args.name, 1 if args.type == "A" else 28, args.expect)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
