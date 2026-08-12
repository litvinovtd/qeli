#!/usr/bin/env python3
"""Pin a scrubbed production SSH host key without exposing the root password.

The public repository intentionally does not contain the production address or SSH
fingerprint. Supply a fingerprint copied from a previously verified deployment through
``QELI_PROD_HOSTKEY_SHA256``. The root password is never read or sent by this script.
"""

import base64
import hashlib
import os
import socket
import sys

import paramiko


HOST = os.environ.get("QELI_PROD_HOST", "").strip()
EXPECTED_HOSTKEY = os.environ.get("QELI_PROD_HOSTKEY_SHA256", "").strip()


def main() -> int:
    if not HOST:
        raise SystemExit("QELI_PROD_HOST is required")
    if not EXPECTED_HOSTKEY.startswith("SHA256:"):
        raise SystemExit("QELI_PROD_HOSTKEY_SHA256 is required")
    try:
        socket.inet_aton(HOST)
    except OSError as error:
        raise SystemExit("QELI_PROD_HOST must be a numeric IPv4 address") from error

    # Read the key before authentication. No password, key signature, or command is sent.
    connection = socket.create_connection((HOST, 22), timeout=20)
    transport = paramiko.Transport(connection)
    try:
        transport.start_client(timeout=20)
        remote_key = transport.get_remote_server_key()
        presented_b64 = base64.b64encode(remote_key.asbytes()).decode("ascii")
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(remote_key.asbytes()).digest()
        ).decode("ascii").rstrip("=")
        if fingerprint != EXPECTED_HOSTKEY:
            raise RuntimeError("production SSH host fingerprint changed")

        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        os.makedirs(os.path.dirname(known_hosts), exist_ok=True)
        existing = paramiko.HostKeys()
        if os.path.exists(known_hosts):
            existing.load(known_hosts)
        known = existing.lookup(HOST)
        if known and known.get(remote_key.get_name()) == remote_key:
            print("PROD_HOSTKEY_RESULT: ALREADY_PINNED")
            return 0
        if known:
            raise RuntimeError("known_hosts already contains a different key for production")

        with open(known_hosts, "a", encoding="utf-8", newline="\n") as stream:
            if os.path.getsize(known_hosts) > 0:
                stream.write("\n")
            stream.write(f"{HOST} {remote_key.get_name()} {presented_b64}\n")
        print("PROD_HOSTKEY_RESULT: PINNED")
        return 0
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PROD_HOSTKEY_RESULT: FAILED ({error})", file=sys.stderr)
        raise SystemExit(1)
