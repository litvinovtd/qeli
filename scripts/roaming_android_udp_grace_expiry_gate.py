#!/usr/bin/env python3
"""Fail-closed Android UDP deep-idle and roaming-grace-expiry gate.

The caller establishes an experimental-roaming UDP tunnel before invoking this gate.
Profiles and credentials remain outside the harness.  ``--fault-hook`` is an executable
provided by the lab environment; it accepts exactly ``apply`` or ``restore`` and must make
the active server path bidirectionally dead without stopping either endpoint.  ``restore``
must be idempotent because the gate always calls it during cleanup.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from roaming_android_sleep_wake_gate import (
    GateFailure,
    TunnelSnapshot,
    adb_run,
    find_tun_identity,
    parse_dns_address,
    parse_idle_flags,
    parse_ping_counts,
    parse_screen_awake,
    restore_device,
    set_idle_flags,
    snapshot,
)


def validate_durations(fault_seconds: float, roaming_grace_seconds: float) -> None:
    if roaming_grace_seconds <= 0:
        raise GateFailure("--roaming-grace-seconds must be positive")
    if fault_seconds <= roaming_grace_seconds:
        raise GateFailure(
            "--fault-seconds must be greater than --roaming-grace-seconds"
        )


def find_interface_by_address(ip_brief: str, expected_address: str) -> tuple[str, str]:
    matches: list[tuple[str, str]] = []
    for line in ip_brief.splitlines():
        fields = line.split()
        if len(fields) >= 3 and expected_address in fields[2:]:
            matches.append((fields[0].split("@", 1)[0], line.strip()))
    if len(matches) != 1:
        names = [name for name, _line in matches]
        raise GateFailure(
            f"expected exactly one interface carrying {expected_address}, found {names}"
        )
    return matches[0]


def snapshot_by_address(
    adb: str, package: str, expected_address: str
) -> TunnelSnapshot:
    pid = adb_run(adb, "shell", "pidof", package).stdout.strip()
    if not pid:
        raise GateFailure(f"Android package is not running: {package}")
    addresses = adb_run(adb, "shell", "ip", "-brief", "addr").stdout
    tun_name, address = find_interface_by_address(addresses, expected_address)
    proc_if_inet6 = adb_run(adb, "shell", "cat", "/proc/net/if_inet6").stdout
    return TunnelSnapshot(
        pid,
        find_tun_identity(proc_if_inet6, tun_name),
        address,
    )


def reconnect_counts(log: str) -> tuple[int, int]:
    auths = len(re.findall(r"\bAuth OK\b", log, re.IGNORECASE))
    plans = len(
        re.findall(r"\bNative NetworkPlan\s+\d+\s+APPLIED\b", log, re.IGNORECASE)
    )
    return auths, plans


def validate_udp_fallback_sequence(log: str) -> None:
    markers = (
        (
            "same-network roaming attempt",
            r"UDP same-network NAT recovery[^\n]*preparing a soft roaming path",
        ),
        ("transport fallback", r"Native transport error\s+-?\d+"),
        ("full AUTH", r"\bAuth OK\b"),
        ("NetworkPlan", r"\bNative NetworkPlan\s+\d+\s+APPLIED\b"),
    )
    positions: list[int] = []
    for label, pattern in markers:
        match = re.search(pattern, log, re.IGNORECASE)
        if not match:
            raise GateFailure(f"Android log is missing {label}")
        positions.append(match.start())
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise GateFailure("Android fallback markers are out of order")

    auths, plans = reconnect_counts(log)
    if auths != 1 or plans != 1:
        raise GateFailure(
            f"expected one successful full reconnect, got AUTH={auths}, NetworkPlan={plans}"
        )


def fault_hook_argv(path: str, action: str) -> list[str]:
    if action not in {"apply", "restore"}:
        raise GateFailure(f"invalid fault-hook action: {action}")
    hook = Path(path).expanduser().resolve()
    if not hook.is_file():
        raise GateFailure(f"fault hook is not a regular file: {hook}")
    if not os.access(hook, os.X_OK):
        raise GateFailure(f"fault hook is not executable: {hook}")
    return [str(hook), action]


def run_fault_hook(path: str, action: str, timeout: float) -> None:
    result = subprocess.run(
        fault_hook_argv(path, action),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise GateFailure(
            f"fault hook {action} failed ({result.returncode}):\n{detail[-2000:]}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="adb executable on this host")
    parser.add_argument("--package", default="com.qeli")
    parser.add_argument(
        "--tun",
        default="tun0",
        help="interface name of the initially active tunnel; reconnect may replace it",
    )
    parser.add_argument("--gateway", required=True, help="reachable peer inside the tunnel")
    parser.add_argument(
        "--expected-address",
        required=True,
        help="literal tunnel address/prefix expected after recovery",
    )
    parser.add_argument("--dns-name", default="example.com")
    parser.add_argument(
        "--fault-hook",
        required=True,
        help="executable accepting apply|restore; restore must be idempotent",
    )
    parser.add_argument("--fault-seconds", type=float, default=40)
    parser.add_argument("--roaming-grace-seconds", type=float, default=15)
    parser.add_argument("--recovery-seconds", type=float, default=90)
    parser.add_argument("--settle-seconds", type=float, default=2)
    parser.add_argument("--ping-count", type=int, default=5)
    parser.add_argument("--hook-timeout", type=float, default=30)
    return parser


def wait_for_recovery(
    adb: str,
    package: str,
    gateway: str,
    expected_address: str,
    timeout: float,
    ping_count: int,
) -> tuple[TunnelSnapshot, str, int, int]:
    deadline = time.monotonic() + timeout
    last_log = ""
    last_ping = ""
    last_snapshot_error = ""
    while time.monotonic() < deadline:
        last_log = adb_run(
            adb, "logcat", "-d", "-v", "time", "-s", "VpnSvc:D", "*:S", check=False
        ).stdout
        auths, plans = reconnect_counts(last_log)
        try:
            current = snapshot_by_address(adb, package, expected_address)
            last_snapshot_error = ""
        except GateFailure as error:
            current = None
            last_snapshot_error = str(error)

        ping = adb_run(
            adb,
            "shell",
            "ping",
            "-c",
            str(ping_count),
            "-W",
            "1",
            gateway,
            timeout=max(15, ping_count + 10),
            check=False,
        )
        last_ping = ping.stdout + ping.stderr
        try:
            transmitted, received = parse_ping_counts(last_ping)
        except GateFailure:
            transmitted, received = 0, 0
        if (
            current is not None
            and expected_address in current.address
            and auths >= 1
            and plans >= 1
            and transmitted == ping_count
            and received == ping_count
        ):
            return current, last_log, transmitted, received
        time.sleep(1)

    raise GateFailure(
        "full reconnect did not recover before the deadline; "
        f"snapshot={last_snapshot_error or 'present'}; ping={last_ping[-500:]!r}; "
        f"log={last_log[-3000:]!r}"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validate_durations(args.fault_seconds, args.roaming_grace_seconds)
    for name in ("recovery_seconds", "settle_seconds", "hook_timeout"):
        if getattr(args, name) <= 0:
            raise GateFailure(f"--{name.replace('_', '-')} must be positive")
    if args.ping_count <= 0:
        raise GateFailure("--ping-count must be positive")

    devices = adb_run(args.adb, "devices").stdout
    if not re.search(r"(?m)^\S+\s+device$", devices):
        raise GateFailure("adb has no ready Android device")
    before = snapshot(args.adb, args.package, args.tun)
    if args.expected_address not in before.address:
        raise GateFailure(
            f"active {args.tun} does not carry {args.expected_address}: {before.address}"
        )

    initial_idle = adb_run(args.adb, "shell", "dumpsys", "deviceidle").stdout
    deep_enabled, light_enabled = parse_idle_flags(initial_idle)
    screen_awake = parse_screen_awake(
        adb_run(args.adb, "shell", "dumpsys", "power").stdout
    )
    restore_needed = False
    try:
        adb_run(args.adb, "logcat", "-c")
        enable = adb_run(args.adb, "shell", "dumpsys", "deviceidle", "enable").stdout
        if "enabled" not in enable.lower():
            raise GateFailure(f"Android did not enable Doze: {enable!r}")
        adb_run(args.adb, "shell", "input", "keyevent", "223")
        forced = adb_run(args.adb, "shell", "dumpsys", "deviceidle", "force-idle").stdout
        if "forced" not in forced.lower():
            raise GateFailure(f"Android did not enter forced deep idle: {forced!r}")
        if (
            adb_run(args.adb, "shell", "dumpsys", "deviceidle", "get", "deep")
            .stdout.strip()
            != "IDLE"
        ):
            raise GateFailure("Android deep-idle state is not IDLE after force-idle")

        restore_needed = True
        run_fault_hook(args.fault_hook, "apply", args.hook_timeout)
        time.sleep(args.fault_seconds)
        idle_after = adb_run(
            args.adb, "shell", "dumpsys", "deviceidle", "get", "deep"
        ).stdout.strip()
        if idle_after != "IDLE":
            raise GateFailure(f"Android left deep idle early: {idle_after!r}")

        adb_run(args.adb, "shell", "dumpsys", "deviceidle", "unforce")
        adb_run(args.adb, "shell", "input", "keyevent", "224")
        adb_run(args.adb, "shell", "wm", "dismiss-keyguard", check=False)
        set_idle_flags(args.adb, deep_enabled, light_enabled)
        run_fault_hook(args.fault_hook, "restore", args.hook_timeout)
        restore_needed = False
        time.sleep(args.settle_seconds)

        after, vpn_log, transmitted, received = wait_for_recovery(
            args.adb,
            args.package,
            args.gateway,
            args.expected_address,
            args.recovery_seconds,
            args.ping_count,
        )
        if after.pid != before.pid:
            raise GateFailure(f"application PID changed: {before.pid} -> {after.pid}")
        validate_udp_fallback_sequence(vpn_log)

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
        dns_address = parse_dns_address(
            dns_probe.stdout + dns_probe.stderr, args.dns_name
        )
        auths, plans = reconnect_counts(vpn_log)
        print(
            f"PASS deep-idle fault exceeded roaming grace: "
            f"{args.fault_seconds:g}s > {args.roaming_grace_seconds:g}s"
        )
        print(f"PASS same-network attempt fell back to full reconnect: AUTH={auths}, plan={plans}")
        print(f"PASS tunnel recovered: ping={received}/{transmitted}, pid={after.pid}")
        print(f"PASS DNS resolved {args.dns_name} -> {dns_address}")
        print("ROAMING_ANDROID_UDP_GRACE_EXPIRY_GATE_PASS")
        return 0
    finally:
        cleanup_error: Exception | None = None
        if restore_needed:
            try:
                run_fault_hook(args.fault_hook, "restore", args.hook_timeout)
            except Exception as error:  # cleanup must stay visible but not skip device restore
                cleanup_error = error
        try:
            restore_device(
                args.adb, deep_enabled, light_enabled, screen_awake
            )
        except Exception as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None and sys.exc_info()[0] is None:
            raise GateFailure(f"gate cleanup failed: {cleanup_error}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateFailure, subprocess.TimeoutExpired) as error:
        print(f"ROAMING_ANDROID_UDP_GRACE_EXPIRY_GATE_FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
