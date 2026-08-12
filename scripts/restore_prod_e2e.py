#!/usr/bin/env python3
"""Restore the exact production config after an interrupted all-modes E2E wrapper."""

import os
import re
import socket
import time

import paramiko

import ssh_hostkey


HOST = os.environ.get("QELI_PROD_HOST", "").strip()
PASSWORD = os.environ.get("QELI_PROD_PASS", "")
CONFIG = "/etc/qeli/server-maxobf.conf"
ORIGINAL_SHA256 = os.environ.get("QELI_E2E_CONFIG_SHA256", "").strip().lower()


def connect() -> paramiko.SSHClient:
    if not HOST or not PASSWORD:
        raise SystemExit("QELI_PROD_HOST and QELI_PROD_PASS are required")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.connect((HOST, 22))
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client, HOST)
    client.connect(
        HOST,
        port=22,
        username="root",
        password=PASSWORD,
        sock=sock,
        timeout=30,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(client: paramiko.SSHClient, command: str) -> tuple[int, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=90)
    output = stdout.read().decode("utf-8", "replace")
    output += stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), output.strip()


def main() -> int:
    if not re.fullmatch(r"[0-9a-f]{64}", ORIGINAL_SHA256):
        raise SystemExit(
            "QELI_E2E_CONFIG_SHA256 must be the exact pre-test config SHA-256; "
            "refusing to guess a production restore point"
        )
    client = connect()
    rc, current = run(client, f"sha256sum {CONFIG} | awk '{{print $1}}'")
    if rc != 0:
        raise SystemExit("cannot hash the live production config")

    restored_from = "not needed (already original)"
    if current != ORIGINAL_SHA256:
        rc, backup = run(
            client,
            "find /root/backup/qeli-e2e -maxdepth 1 -type f -name "
            "'*-server-maxobf.conf' -print0 | xargs -0 sha256sum | "
            f"awk '$1 == \"{ORIGINAL_SHA256}\" {{print $2}}' | sort | tail -1",
        )
        if rc != 0 or not backup.startswith("/root/backup/qeli-e2e/"):
            raise SystemExit("no verified original E2E config backup was found")
        temporary = f"{CONFIG}.e2e-recovery.tmp"
        rc, output = run(
            client,
            f"cp --preserve=all {backup} {temporary} && mv -f {temporary} {CONFIG} && "
            "systemctl restart qeli.service",
        )
        if rc != 0:
            raise SystemExit(f"production restore/restart failed: {output}")
        restored_from = backup

    verification = ""
    for _attempt in range(20):
        rc, verification = run(
            client,
            f"printf 'sha='; sha256sum {CONFIG} | awk '{{print $1}}'; "
            "printf 'state='; systemctl is-active qeli.service; "
            "ss -tlnH | awk '{print \"tcp \" $4}'; "
            "ss -ulnH | awk '{print \"udp \" $4}'",
        )
        tcp_ports = {
            int(match.group(1))
            for match in re.finditer(r"(?m)^tcp .*:(\d+)$", verification)
        }
        udp_ports = {
            int(match.group(1))
            for match in re.finditer(r"(?m)^udp .*:(\d+)$", verification)
        }
        ready = (
            rc == 0
            and f"sha={ORIGINAL_SHA256}" in verification
            and "state=active" in verification
            and {443, 8444}.issubset(tcp_ports)
            and {8448, 8449, 8450}.issubset(udp_ports)
            and not {8443, 8445, 8446, 8447}.intersection(tcp_ports)
        )
        if ready:
            break
        time.sleep(2)
    else:
        rc = 1
    client.close()
    if rc != 0:
        raise SystemExit(f"production restore verification failed: {verification}")
    print("PROD_E2E_RESTORE_RESULT: PASS")
    print(f"source: {restored_from}")
    print(f"config sha256: {ORIGINAL_SHA256}")
    print("service/listeners: original set active")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
