#!/usr/bin/env python3
"""Live Windows ABI 1.10 handshake against an isolated qeli lab server.

The test deliberately uses the shipped ``QeliWin.dll handshake`` entry point.  It
therefore covers native-library extraction/resolution, ABI negotiation, the Rust-owned
carrier and handshake, server-identity ACK and authenticated NetworkPlan delivery without
requiring administrator privileges or opening Wintun.

Lab credentials come from ``QELI_LAB_PASS``.  The dedicated TCP :8444 profile and TUN are
removed on every exit; the canonical :443 service is never touched.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from lab_common import LAB_SRV, connect, run


ROOT = Path(__file__).resolve().parent.parent
QELI = "/opt/qeli-src/target/debug/qeli"
TEST_DIR = "/tmp/qeli-win-native-e2e"
CONFIG = f"{TEST_DIR}/server.conf"
LOG = f"{TEST_DIR}/server.log"
PID = f"{TEST_DIR}/server.pid"
PORT = 8444
TUN = "wne2e0"
NETWORK = "10.63.0"
USER = "admin"
PASSWORD = "testpass123"
PASSWORD_HASH = (
    "$argon2id$v=19$m=16384,t=2,p=1$"
    "cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
)


def server_config() -> str:
    return f"""[auth]
require_client_key_proof = false

[logging]
level = info
file = {LOG}

[profile:windows-native]
identity_key = {TEST_DIR}/identity.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUN}
tun.address = {NETWORK}.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = {NETWORK}.0/24
pool.exclude = {NETWORK}.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.padding.enabled = true

[user:{USER}]
password_hash = {PASSWORD_HASH}
enabled = true
"""


def cleanup(ssh) -> None:
    run(
        ssh,
        f"test -f {PID} && kill -9 $(cat {PID}) 2>/dev/null || true; "
        f"pkill -9 -f '{CONFIG}' 2>/dev/null || true; "
        f"ip link del {TUN} 2>/dev/null || true",
    )


def main() -> int:
    if not os.environ.get("QELI_LAB_PASS"):
        print("QELI_LAB_PASS is required", file=sys.stderr)
        return 2

    dll = ROOT / "qeli-win" / "QeliWin" / "bin" / "Release" / "net10.0-windows" / "win-x64" / "QeliWin.dll"
    if not dll.is_file():
        print(f"missing Release build: {dll}", file=sys.stderr)
        return 2

    ssh = connect(LAB_SRV)
    try:
        cleanup(ssh)
        run(ssh, f"mkdir -p {TEST_DIR}; rm -f {LOG}; ip link del {TUN} 2>/dev/null || true")
        with ssh.open_sftp() as sftp:
            sftp.putfo(io.BytesIO(server_config().encode()), CONFIG)

        identity = run(ssh, f"{QELI} show-identity --config {CONFIG} 2>&1")
        match = re.search(r"[0-9a-f]{64}", identity)
        if not match:
            print("server identity was not produced:\n" + identity, file=sys.stderr)
            return 1
        public_key = match.group(0)

        run(
            ssh,
            f"setsid nohup {QELI} server --config {CONFIG} >{TEST_DIR}/stdout.log 2>&1 "
            f"</dev/null & echo $! >{PID}",
        )
        for _ in range(20):
            if run(ssh, f"ss -ltn | grep -c ':{PORT} '").strip() not in ("", "0"):
                break
            time.sleep(0.5)
        else:
            print(run(ssh, f"tail -40 {TEST_DIR}/stdout.log {LOG} 2>/dev/null"), file=sys.stderr)
            return 1

        client_config = (
            "[qeli]\n"
            f"server = {LAB_SRV[0]}:{PORT}\n"
            "proto = tcp\n"
            f"user = {USER}\n"
            f"pass = {PASSWORD}\n"
            "mode = fake-tls\n"
            f"key = {public_key}\n"
            "sni = www.microsoft.com\n"
            "gateway = false\n"
        )
        completed = subprocess.run(
            ["dotnet", str(dll), "handshake", client_config],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        output = completed.stdout + completed.stderr
        print(output.rstrip())
        ok = (
            completed.returncode == 0
            and "RESULT: OK" in output
            and re.search(rf"server assigned tunnel IP {re.escape(NETWORK)}\.\d+", output)
        )
        if not ok:
            print("\nserver tail:\n" + run(ssh, f"tail -30 {LOG} {TEST_DIR}/stdout.log 2>/dev/null"))
            return 1
        print("PASS: Windows client used the ABI 1.10 Rust handshake and received NetworkPlan")
        return 0
    finally:
        cleanup(ssh)
        ssh.close()


if __name__ == "__main__":
    raise SystemExit(main())
