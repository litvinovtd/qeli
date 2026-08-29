#!/usr/bin/env python3
"""Read integer fields from qeli's private roaming-stats control response.

The helper deliberately returns aggregate counters only. It never prints the complete control
response, session locators, CIDs, proofs, or other session material.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import Any

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def extract_fields(
    response_text: str, profile_name: str, transport: str, fields: list[str]
) -> list[int]:
    response = json.loads(response_text)
    if response.get("ok") is not True:
        raise ValueError(f"control command failed: {response.get('error', 'unknown error')}")
    message = response.get("message")
    if not isinstance(message, str):
        raise ValueError("control response has no roaming-stats message")
    payload = json.loads(message)
    profiles = payload.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("roaming-stats payload has no profiles array")
    matches = [entry for entry in profiles if entry.get("name") == profile_name]
    if len(matches) != 1:
        raise ValueError(
            f"expected one roaming profile named {profile_name!r}, found {len(matches)}"
        )
    stats = matches[0].get(transport)
    if not isinstance(stats, dict):
        raise ValueError(f"profile has no {transport!r} roaming counters")

    values: list[int] = []
    for field in fields:
        value: Any = stats.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"counter {transport}.{field} is not a non-negative integer")
        values.append(value)
    return values


def query(socket_path: str) -> str:
    chunks: list[bytes] = []
    received = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(5)
        control.connect(socket_path)
        control.sendall(b'{"cmd":"roaming-stats"}\n')
        control.shutdown(socket.SHUT_WR)
        while True:
            chunk = control.recv(64 * 1024)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_RESPONSE_BYTES:
                raise ValueError("control response exceeds 8 MiB")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="read aggregate integer fields from qeli roaming-stats"
    )
    result.add_argument("socket", help="qeli Unix control socket")
    result.add_argument("profile", help="exact profile name")
    result.add_argument("transport", choices=("tcp", "udp"))
    result.add_argument("fields", nargs="+")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        values = extract_fields(
            query(args.socket), args.profile, args.transport, args.fields
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"cannot read roaming counters: {error}", file=sys.stderr)
        return 2
    print("\t".join(str(value) for value in values))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
