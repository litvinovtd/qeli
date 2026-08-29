#!/usr/bin/env python3
"""Fail-closed Android emulator deep-idle/wake gate for an active Qeli tunnel.

The caller must establish the VPN first.  This gate deliberately does not inject a
profile or tap Connect: it can therefore be reused with every TCP/UDP transport and
does not handle credentials.  It temporarily enables Android Doze, verifies that the
AVD really reaches deep IDLE, and restores the original idle-mode flags afterwards.
"""

from __future__ import annotations

import argparse
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass


class GateFailure(RuntimeError):
    """A mandatory sleep/wake invariant failed."""


@dataclass(frozen=True)
class TunnelSnapshot:
    pid: str
    identity: str
    address: str


def adb_run(
    adb: str,
    *args: str,
    timeout: float = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [adb, *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise GateFailure(
            f"adb command failed ({result.returncode}): {' '.join(args)}\n{detail[-2000:]}"
        )
    return result


def parse_idle_flags(dump: str) -> tuple[bool, bool]:
    deep = re.search(r"\bmDeepEnabled=(true|false)\b", dump)
    light = re.search(r"\bmLightEnabled=(true|false)\b", dump)
    if not deep or not light:
        raise GateFailure("could not read mDeepEnabled/mLightEnabled from deviceidle")
    return deep.group(1) == "true", light.group(1) == "true"


def parse_screen_awake(dump: str) -> bool:
    wakefulness = re.search(r"(?m)^\s*mWakefulness=(\w+)\s*$", dump)
    if not wakefulness:
        raise GateFailure("could not read mWakefulness from dumpsys power")
    return wakefulness.group(1).lower() == "awake"


def find_tun_identity(proc_if_inet6: str, tun_name: str) -> str:
    for line in proc_if_inet6.splitlines():
        fields = line.split()
        if fields and fields[-1] == tun_name:
            return " ".join(fields)
    raise GateFailure(f"{tun_name} has no IPv6 link identity in /proc/net/if_inet6")


def parse_ping_counts(output: str) -> tuple[int, int]:
    match = re.search(r"(\d+) packets transmitted, (\d+) received", output)
    if not match:
        raise GateFailure("continuous ping did not print packet counters")
    return int(match.group(1)), int(match.group(2))


def parse_dns_address(output: str, name: str) -> str:
    escaped = re.escape(name)
    resolved = re.search(rf"(?m)^PING\s+{escaped}\s+\(([^)]+)\)", output)
    if not resolved:
        resolved = re.search(r"(?m)^PING\s+([0-9a-fA-F:.]+)\s+", output)
    if not resolved:
        raise GateFailure(f"DNS did not resolve {name}: {output[-1000:]}")
    return resolved.group(1)


def snapshot(adb: str, package: str, tun_name: str) -> TunnelSnapshot:
    pid = adb_run(adb, "shell", "pidof", package).stdout.strip()
    if not pid:
        raise GateFailure(f"Android package is not running: {package}")
    address = adb_run(adb, "shell", "ip", "-brief", "addr", "show", tun_name).stdout.strip()
    if not address:
        raise GateFailure(f"Android VPN interface is absent: {tun_name}")
    proc_if_inet6 = adb_run(adb, "shell", "cat", "/proc/net/if_inet6").stdout
    return TunnelSnapshot(pid, find_tun_identity(proc_if_inet6, tun_name), address)


def set_idle_flags(adb: str, deep: bool, light: bool) -> None:
    adb_run(adb, "shell", "dumpsys", "deviceidle", "disable", check=False)
    if deep:
        adb_run(adb, "shell", "dumpsys", "deviceidle", "enable", "deep")
    if light:
        adb_run(adb, "shell", "dumpsys", "deviceidle", "enable", "light")


def restore_device(adb: str, deep: bool, light: bool, screen_awake: bool) -> None:
    adb_run(adb, "shell", "dumpsys", "deviceidle", "unforce", check=False)
    set_idle_flags(adb, deep, light)
    adb_run(adb, "shell", "input", "keyevent", "224" if screen_awake else "223", check=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="adb executable on this host")
    parser.add_argument("--package", default="com.qeli")
    parser.add_argument("--tun", default="tun0")
    parser.add_argument("--gateway", required=True, help="reachable peer inside the tunnel")
    parser.add_argument(
        "--expected-address",
        required=True,
        help="literal tunnel address/prefix expected in `ip -brief addr`",
    )
    parser.add_argument("--dns-name", default="example.com")
    parser.add_argument("--sleep-seconds", type=float, default=20)
    parser.add_argument("--settle-seconds", type=float, default=20)
    parser.add_argument("--pre-sleep-seconds", type=float, default=3)
    parser.add_argument("--ping-interval", type=float, default=0.25)
    parser.add_argument(
        "--ping-count",
        type=int,
        default=0,
        help="0 derives a count spanning pre-sleep + sleep + settle",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("sleep_seconds", "settle_seconds", "pre_sleep_seconds", "ping_interval"):
        if getattr(args, name) <= 0:
            raise GateFailure(f"--{name.replace('_', '-')} must be positive")

    devices = adb_run(args.adb, "devices").stdout
    if not re.search(r"(?m)^\S+\s+device$", devices):
        raise GateFailure("adb has no ready Android device")

    initial_idle = adb_run(args.adb, "shell", "dumpsys", "deviceidle").stdout
    deep_enabled, light_enabled = parse_idle_flags(initial_idle)
    screen_awake = parse_screen_awake(adb_run(args.adb, "shell", "dumpsys", "power").stdout)
    before = snapshot(args.adb, args.package, args.tun)
    if args.expected_address not in before.address:
        raise GateFailure(
            f"active {args.tun} does not carry {args.expected_address}: {before.address}"
        )

    duration = args.pre_sleep_seconds + args.sleep_seconds + args.settle_seconds
    ping_count = args.ping_count or math.ceil(duration / args.ping_interval) + 8
    ping_process: subprocess.Popen[str] | None = None
    restored = False
    try:
        enable = adb_run(args.adb, "shell", "dumpsys", "deviceidle", "enable").stdout
        if "enabled" not in enable.lower():
            raise GateFailure(f"Android did not enable Doze: {enable!r}")
        adb_run(args.adb, "logcat", "-c")

        ping_process = subprocess.Popen(
            [
                args.adb,
                "shell",
                "ping",
                "-i",
                str(args.ping_interval),
                "-c",
                str(ping_count),
                "-W",
                "1",
                args.gateway,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        time.sleep(args.pre_sleep_seconds)
        adb_run(args.adb, "shell", "input", "keyevent", "223")
        forced = adb_run(args.adb, "shell", "dumpsys", "deviceidle", "force-idle").stdout
        if "forced" not in forced.lower():
            raise GateFailure(f"Android did not enter forced deep idle: {forced!r}")
        if adb_run(args.adb, "shell", "dumpsys", "deviceidle", "get", "deep").stdout.strip() != "IDLE":
            raise GateFailure("Android deep-idle state is not IDLE immediately after force-idle")

        time.sleep(args.sleep_seconds)
        idle_after = adb_run(
            args.adb, "shell", "dumpsys", "deviceidle", "get", "deep"
        ).stdout.strip()
        if idle_after != "IDLE":
            raise GateFailure(f"Android left deep idle early: {idle_after!r}")

        adb_run(args.adb, "shell", "dumpsys", "deviceidle", "unforce")
        adb_run(args.adb, "shell", "input", "keyevent", "224")
        adb_run(args.adb, "shell", "wm", "dismiss-keyguard")
        set_idle_flags(args.adb, deep_enabled, light_enabled)
        restored = True
        time.sleep(args.settle_seconds)

        timeout = max(30.0, ping_count * args.ping_interval + 15.0)
        ping_output, ping_error = ping_process.communicate(timeout=timeout)
        if ping_process.returncode != 0:
            raise GateFailure(
                f"continuous ping failed ({ping_process.returncode}):\n"
                f"{(ping_output + ping_error)[-2000:]}"
            )
        transmitted, received = parse_ping_counts(ping_output)
        if transmitted != ping_count or received != ping_count:
            raise GateFailure(
                f"continuous ping lost packets: transmitted={transmitted}, received={received}"
            )

        after = snapshot(args.adb, args.package, args.tun)
        if after != before:
            raise GateFailure(f"VPN owner/TUN changed across sleep: before={before}, after={after}")

        dns_probe = adb_run(
            args.adb,
            "shell",
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            args.dns_name,
            timeout=10,
            check=False,
        )
        dns_address = parse_dns_address(dns_probe.stdout + dns_probe.stderr, args.dns_name)
        vpn_log = adb_run(
            args.adb, "logcat", "-d", "-v", "time", "-s", "VpnSvc:D", "*:S"
        ).stdout
        if re.search(r"Auth OK", vpn_log, re.IGNORECASE):
            raise GateFailure("VPN performed a new password AUTH after sleep")
        if re.search(r"NetworkPlan\s+\d+", vpn_log):
            raise GateFailure("VPN rebuilt NetworkPlan after same-network sleep")
        if "same network, keeping the tunnel" not in vpn_log.lower():
            raise GateFailure("same-network wake/keep marker is absent from VpnSvc log")

        print(f"PASS deep-idle remained IDLE for {args.sleep_seconds:g}s")
        print(f"PASS continuous tunnel ping {received}/{transmitted}")
        print(f"PASS owner/TUN unchanged: pid={after.pid}, identity={after.identity}")
        print(f"PASS DNS resolved {args.dns_name} -> {dns_address}")
        print("PASS no AUTH or NetworkPlan rebuild after wake")
        print("ROAMING_ANDROID_SLEEP_WAKE_GATE_PASS")
        return 0
    finally:
        if ping_process is not None and ping_process.poll() is None:
            ping_process.terminate()
            try:
                ping_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ping_process.kill()
        if not restored:
            restore_device(args.adb, deep_enabled, light_enabled, screen_awake)
        elif not screen_awake:
            adb_run(args.adb, "shell", "input", "keyevent", "223", check=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateFailure, subprocess.TimeoutExpired) as error:
        print(f"ROAMING_ANDROID_SLEEP_WAKE_GATE_FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
