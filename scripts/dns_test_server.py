#!/usr/bin/env python3
"""Minimal deterministic DNS responder/probe for isolated release netns tests."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import struct
import threading
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


def read_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ValueError("incomplete TCP DNS frame")
        data.extend(part)
    return bytes(data)


def serve(address: str, log_path: Path) -> None:
    family = family_for(address)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def reply(query: bytes, transport: str) -> bytes:
        response, name, qtype = build_response(query)
        truncated = transport == "udp" and name.startswith("tc.")
        if truncated:
            _, _, _, question_end = parse_question(query)
            response = struct.pack("!6H", int.from_bytes(query[:2], "big"), 0x8380, 1, 0, 0, 0) + query[12:question_end]
        with lock, log_path.open("a", encoding="utf-8") as stream:
            stream.write(f"family={6 if family == socket.AF_INET6 else 4} transport={transport} "
                         f"tc={int(truncated)} qtype={TYPE_NAMES.get(qtype, qtype)} qname={name}\n")
        return response

    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 53))
    listener.listen(16)

    def connection(stream: socket.socket) -> None:
        with stream:
            stream.settimeout(3)
            try:
                while True:
                    length = int.from_bytes(read_exact(stream, 2), "big")
                    response = reply(read_exact(stream, length), "tcp")
                    stream.sendall(struct.pack("!H", len(response)) + response)
            except (OSError, UnicodeError, ValueError):
                return

    def accept() -> None:
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=connection, args=(stream,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((address, 53))
        while True:
            query, peer = sock.recvfrom(65535)
            try:
                sock.sendto(reply(query, "udp"), peer)
            except (UnicodeError, ValueError):
                continue


def query(server: str, name: str, qtype: int, expected: str, tcp: bool = False) -> None:
    family = family_for(server)
    txid = int.from_bytes(os.urandom(2), "big")
    request = build_query(name, qtype, txid)
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        if tcp:
            sock.connect((server, 53))
            sock.sendall(struct.pack("!H", len(request)) + request)
            response = read_exact(sock, int.from_bytes(read_exact(sock, 2), "big"))
        else:
            sock.sendto(request, (server, 53))
            response, peer = sock.recvfrom(65535)
            if ipaddress.ip_address(peer[0]) != ipaddress.ip_address(server) or peer[1] != 53:
                raise RuntimeError(f"response came from unexpected peer {peer}")
    actual = parse_answer(response, txid, qtype)
    if ipaddress.ip_address(actual) != ipaddress.ip_address(expected):
        raise RuntimeError(f"expected {expected}, received {actual}")
    print(f"PASS: {TYPE_NAMES[qtype]} {name} via {server}/{'tcp' if tcp else 'udp'} -> {actual}")


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
    query_parser.add_argument("--tcp", action="store_true")
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.address, args.log)
    else:
        query(args.server, args.name, 1 if args.type == "A" else 28, args.expect, args.tcp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
