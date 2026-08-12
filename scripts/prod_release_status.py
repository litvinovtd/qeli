#!/usr/bin/env python3
"""Read-only verification of the deployed 0.7.15 production candidate."""

import os
import shlex
import socket

import paramiko

import ssh_hostkey


HOST = os.environ.get("QELI_PROD_HOST", "").strip()
PASSWORD = os.environ.get("QELI_PROD_PASS", "")
EXPECTED_BINARY_SHA256 = (
    "8e3a7819d2c6cd72231378b13b3240a72d7bd26c553697b8f769e0cf1998ce47"
)
EXPECTED_CONFIG_SHA256 = (
    "e50acf663bf76cc8144261abcdbfd7f60dbae7e074c4fb8e19d344b53c8ea554"
)
PCAP = "/root/qeli-0715-linux-prod.pcap"
PORTS = (443, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450, 53)


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


def run(client: paramiko.SSHClient, command: str, timeout: int = 90) -> tuple[int, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    output += stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), output.strip()


def require(client: paramiko.SSHClient, command: str) -> str:
    status, output = run(client, command)
    if status != 0:
        raise RuntimeError(f"production status command failed ({status}): {command}\n{output}")
    return output


def main() -> int:
    client = connect()
    binary_sha = require(client, "sha256sum /usr/local/bin/qeli | awk '{print $1}'")
    config_sha = require(
        client, "sha256sum /etc/qeli/server-maxobf.conf | awk '{print $1}'"
    )
    version = require(client, "/usr/local/bin/qeli --version 2>&1 | head -1")
    state = require(client, "systemctl is-active qeli.service")
    panel_markers = require(
        client,
        "grep -aFq '/transport/health' /usr/local/bin/qeli && "
        "grep -aFq 'Transport health' /usr/local/bin/qeli && echo OK",
    )
    web_output = require(
        client,
        "awk 'BEGIN { active=0 } /^\\[web\\][[:space:]]*$/ { active=1; next } "
        "/^\\[/ { active=0 } active && "
        "/^(enabled|bind|port|tls|base_path)[[:space:]]*=/ { print }' "
        "/etc/qeli/server-maxobf.conf",
    )
    web = {}
    for line in web_output.splitlines():
        key, value = line.split("=", 1)
        web[key.strip()] = value.split("#", 1)[0].split(";", 1)[0].strip().strip('"')
    panel_enabled = web.get("enabled", "false").lower() == "true"
    panel_route_code = "disabled"
    panel_url = "disabled"
    if panel_enabled:
        scheme = "https" if web.get("tls", "false").lower() == "true" else "http"
        bind = web.get("bind", "127.0.0.1")
        host = "127.0.0.1" if bind in {"0.0.0.0", "::", "[::]"} else bind
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = int(web.get("port", "8080"))
        base_path = web.get("base_path", "").rstrip("/")
        panel_url = f"{scheme}://{host}:{port}{base_path}/transport"
        _status, output = run(
            client,
            "curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "
            + shlex.quote(panel_url),
        )
        panel_route_code = output.strip()
    listeners = require(
        client,
        "{ ss -tlnH | awk '{print \"tcp \" $4}'; "
        "ss -ulnH | awk '{print \"udp \" $4}'; } | "
        "grep -E ':(443|8443|8444|8445|8446|8447|8448|8449|8450)$' | sort",
    )
    _status, dns_rules = run(
        client, "iptables -t filter -S INPUT | grep -F 'qeli-nat:' || true"
    )
    rules = [line for line in dns_rules.splitlines() if line.strip()]
    if not rules or not all("--dport 53" in line for line in rules):
        raise RuntimeError("qeli-managed INPUT rules are missing or broader than DNS/53")

    packet_counts = {}
    for port in PORTS:
        value = require(
            client,
            f"timeout 30 tcpdump -nn -r {PCAP} 'port {port}' 2>/dev/null | wc -l",
        )
        packet_counts[port] = int(value)

    _status, journal_issues = run(
        client,
        "journalctl -u qeli.service --since '2026-08-12 13:02:00' --no-pager "
        "| grep -Ei 'panic|segfault|fatal|profile .* failed|dns input.*failed' || true",
    )
    client.close()

    if binary_sha != EXPECTED_BINARY_SHA256:
        raise RuntimeError(f"production binary SHA mismatch: {binary_sha}")
    if config_sha != EXPECTED_CONFIG_SHA256:
        raise RuntimeError(f"production config SHA mismatch: {config_sha}")
    if version != "qeli 0.7.15" or state != "active":
        raise RuntimeError(f"production readiness mismatch: {version!r}, {state!r}")
    if panel_markers != "OK":
        raise RuntimeError("current panel markers are absent from production ELF")
    live_panel_codes = {"200", "302", "303", "307", "401", "403"}
    if panel_enabled and panel_route_code not in live_panel_codes:
        raise RuntimeError(
            f"live /transport route is unavailable: {panel_url} -> {panel_route_code}"
        )
    missing_capture_ports = [port for port in PORTS[:-1] if packet_counts[port] == 0]
    if missing_capture_ports or packet_counts[53] == 0:
        raise RuntimeError(
            f"production pcap lacks expected traffic: ports={missing_capture_ports}, "
            f"dns={packet_counts[53]}"
        )
    if journal_issues.strip():
        raise RuntimeError("fatal production journal markers found:\n" + journal_issues)

    print("PROD_RELEASE_STATUS: PASS")
    print(f"binary: {version}, sha256={binary_sha}")
    print(f"config sha256={config_sha}, service={state}")
    print(
        f"current panel markers: {panel_markers}; "
        f"/transport: {panel_url} -> {panel_route_code}"
    )
    print(f"qeli DNS-only INPUT rules: {len(rules)}")
    print("listeners:\n" + listeners)
    print(
        "pcap packets: "
        + ", ".join(f"{port}={packet_counts[port]}" for port in PORTS)
    )
    print("fatal journal markers: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
