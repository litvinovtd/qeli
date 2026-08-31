#!/usr/bin/env python3
"""Prove that a live qeli TAP answers IPv6 RS/NS locally with valid RA/NA frames."""
from __future__ import annotations

import ipaddress
import json
import socket
import struct
import sys
import time
from pathlib import Path

ETH_P_IPV6 = 0x86DD
ICMPV6 = 58
ALL_ROUTERS = ipaddress.IPv6Address("ff02::2")
ALL_NODES = ipaddress.IPv6Address("ff02::1")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmpv6_payload(source: ipaddress.IPv6Address, destination: ipaddress.IPv6Address, body: bytes) -> bytes:
    pseudo = source.packed + destination.packed + struct.pack("!I3xB", len(body), ICMPV6)
    value = checksum(pseudo + body)
    return body[:2] + struct.pack("!H", value) + body[4:]


def ethernet_ipv6(
    source_mac: bytes,
    destination_mac: bytes,
    source: ipaddress.IPv6Address,
    destination: ipaddress.IPv6Address,
    body: bytes,
) -> bytes:
    payload = icmpv6_payload(source, destination, body)
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(payload), ICMPV6, 255, source.packed, destination.packed)
    return destination_mac + source_mac + struct.pack("!H", ETH_P_IPV6) + ipv6 + payload


def router_solicitation(source_mac: bytes) -> bytes:
    return ethernet_ipv6(
        source_mac,
        bytes.fromhex("333300000002"),
        ipaddress.IPv6Address("::"),
        ALL_ROUTERS,
        struct.pack("!BBHI", 133, 0, 0, 0),
    )


def solicited_node(address: ipaddress.IPv6Address) -> tuple[ipaddress.IPv6Address, bytes]:
    suffix = address.packed[-3:]
    destination = ipaddress.IPv6Address(int(ipaddress.IPv6Address("ff02::1:ff00:0")) | int.from_bytes(suffix, "big"))
    return destination, bytes.fromhex("3333ff") + suffix


def neighbor_solicitation(
    source_mac: bytes, source: ipaddress.IPv6Address, target: ipaddress.IPv6Address
) -> bytes:
    destination, destination_mac = solicited_node(target)
    body = struct.pack("!BBHI16sBB6s", 135, 0, 0, 0, target.packed, 1, 1, source_mac)
    return ethernet_ipv6(source_mac, destination_mac, source, destination, body)


def ipv6_icmp(frame: bytes) -> tuple[ipaddress.IPv6Address, ipaddress.IPv6Address, bytes]:
    if len(frame) < 62 or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6:
        raise ValueError("not an Ethernet IPv6 control frame")
    payload_len = int.from_bytes(frame[18:20], "big")
    if frame[20] != ICMPV6 or frame[21] != 255 or len(frame) < 54 + payload_len:
        raise ValueError("invalid ICMPv6 header, hop limit, or payload length")
    source = ipaddress.IPv6Address(frame[22:38])
    destination = ipaddress.IPv6Address(frame[38:54])
    payload = frame[54 : 54 + payload_len]
    pseudo = source.packed + destination.packed + struct.pack("!I3xB", len(payload), ICMPV6)
    if checksum(pseudo + payload) != 0:
        raise ValueError("invalid ICMPv6 checksum")
    return source, destination, payload


def options(payload: bytes, offset: int):
    cursor = offset
    while cursor + 2 <= len(payload):
        kind, units = payload[cursor], payload[cursor + 1]
        length = units * 8
        if length == 0 or cursor + length > len(payload):
            raise ValueError("malformed ICMPv6 option")
        yield kind, payload[cursor : cursor + length]
        cursor += length
    if cursor != len(payload):
        raise ValueError("trailing ICMPv6 option bytes")


def validate_ra(frame: bytes, expected_prefix: ipaddress.IPv6Network) -> dict[str, str | int]:
    source, destination, payload = ipv6_icmp(frame)
    if len(payload) < 16 or payload[:2] != b"\x86\x00":
        raise ValueError("not a Router Advertisement")
    if not source.is_link_local or destination != ALL_NODES:
        raise ValueError("RA source/destination is not link-local/all-nodes")
    if int.from_bytes(payload[6:8], "big") != 0:
        raise ValueError("RA must not install an implicit default route")
    prefixes = [value for kind, value in options(payload, 16) if kind == 3]
    if not prefixes:
        raise ValueError("RA has no Prefix Information option")
    prefix = prefixes[0]
    advertised = ipaddress.IPv6Network((ipaddress.IPv6Address(prefix[16:32]), prefix[2]), strict=False)
    if advertised != expected_prefix or prefix[3] & 0x80 == 0 or prefix[3] & 0x40:
        raise ValueError("RA prefix/L/A contract does not match the authenticated NetworkPlan")
    return {"source": str(source), "prefix": str(advertised), "router_lifetime": 0}


def validate_na(frame: bytes, expected_target: ipaddress.IPv6Address) -> dict[str, str]:
    source, _destination, payload = ipv6_icmp(frame)
    if len(payload) < 24 or payload[:2] != b"\x88\x00":
        raise ValueError("not a Neighbor Advertisement")
    target = ipaddress.IPv6Address(payload[8:24])
    if source != expected_target or target != expected_target:
        raise ValueError("NA source/target does not match the authenticated gateway")
    if not any(kind == 2 and len(value) == 8 for kind, value in options(payload, 24)):
        raise ValueError("NA has no target link-layer address")
    return {"source": str(source), "target": str(target)}


def receive_type(packet: socket.socket, icmp_type: int, timeout: float = 4.0) -> bytes:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for ICMPv6 type {icmp_type}")
        packet.settimeout(remaining)
        frame = packet.recv(4096)
        if len(frame) >= 55 and frame[12:14] == b"\x86\xdd" and frame[54] == icmp_type:
            return frame


def interface_mac(name: str) -> bytes:
    raw = Path(f"/sys/class/net/{name}/address").read_text(encoding="ascii").strip()
    value = bytes.fromhex(raw.replace(":", ""))
    if len(value) != 6 or value == b"\0" * 6:
        raise ValueError(f"invalid TAP MAC: {raw}")
    return value


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        raise SystemExit(f"usage: {argv[0]} <tap> <client-ipv6> <gateway-ipv6> <prefix-len>")
    interface, client_raw, gateway_raw, prefix_raw = argv[1:]
    client = ipaddress.IPv6Address(client_raw)
    gateway = ipaddress.IPv6Address(gateway_raw)
    prefix = ipaddress.IPv6Network((gateway, int(prefix_raw)), strict=False)
    mac = interface_mac(interface)
    packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6))
    packet.bind((interface, 0))
    try:
        packet.send(router_solicitation(mac))
        ra = validate_ra(receive_type(packet, 134), prefix)
        packet.send(neighbor_solicitation(mac, client, gateway))
        na = validate_na(receive_type(packet, 136), gateway)
    finally:
        packet.close()
    print(json.dumps({"interface": interface, "mac": mac.hex(":"), "ra": ra, "na": na}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
