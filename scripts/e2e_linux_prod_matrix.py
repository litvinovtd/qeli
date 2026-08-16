#!/usr/bin/env python3
"""Fresh Linux client on lab .11 against every enabled production transport.

Uses the gate-passed release binary from lab .10 and the ignored current user01 share links.
Each profile must authenticate, accept server-pushed DNS without client dns_servers, resolve
through the tunnel, reach its server gateway, and restore physical DNS after a graceful stop.
"""

import hashlib
import io
import os
import re
import shlex
import socket
import sys
import time
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import paramiko

import ssh_hostkey


ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "qeli" / "Cargo.toml").open("rb") as manifest:
    VERSION = tomllib.load(manifest)["package"]["version"]
VERSION_TOKEN = VERSION.replace(".", "")
EVIDENCE = ROOT / "release" / "dist" / f"v{VERSION}" / "evidence"
LINKS = ROOT / "release/prod-client-configs/allmodes"
LAB_SERVER = "10.66.116.10"
LAB_CLIENT = os.environ.get("QELI_LAB_IP", "10.66.116.11")
PROD_HOST = os.environ.get("QELI_PROD_HOST", "").strip()
SOURCE_BINARY = "/opt/qeli-src/target/release/qeli"
CLIENT_BINARY = f"/root/qeli-{VERSION_TOKEN}-e2e"
RESOLV_BACKUP = f"/root/qeli-{VERSION_TOKEN}-e2e.resolv.conf"
CLIENT_TUN = f"qeli{VERSION_TOKEN}e2e"
REMOTE_PREFIX = f"/root/qeli-{VERSION_TOKEN}"
PID_FILE = f"{REMOTE_PREFIX}-e2e.pid"
MGMT_ROUTE = "192.168.50.0/24 via 10.66.116.1 dev ens18 metric 50"
LAB_CAPTURE = f"/root/qeli-{VERSION_TOKEN}-linux-lab.pcap"
PROD_CAPTURE = f"/root/qeli-{VERSION_TOKEN}-linux-prod.pcap"
CAPTURE_FILTER = (
    "port 53 or tcp port 443 or tcp portrange 8443-8447 or udp portrange 8448-8450"
)
PROFILES = (
    ("reality-tls", "tcp", 443),
    ("reality", "tcp", 8443),
    ("fake-tls", "tcp", 8444),
    ("obfs-ws", "tcp", 8445),
    ("obfs-none", "tcp", 8446),
    ("plain", "tcp", 8447),
    ("udp-fake-tls", "udp", 8448),
    ("udp-quic", "udp", 8449),
    ("udp-obfs", "udp", 8450),
)


def connect(host: str, password: str) -> paramiko.SSHClient:
    last_error: Exception | None = None
    for attempt in range(1, 7):
        client = paramiko.SSHClient()
        ssh_hostkey.harden(client, host)
        sock: socket.socket | None = None
        try:
            # An explicit IPv4 socket avoids intermittent Windows getaddrinfo/Paramiko
            # failures and makes a reset retry create an entirely fresh transport.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((host, 22))
            client.connect(
                host,
                port=22,
                username="root",
                password=password,
                sock=sock,
                timeout=25,
                banner_timeout=25,
                auth_timeout=25,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(15)
            return client
        except Exception as error:
            last_error = error
            client.close()
            if sock is not None:
                sock.close()
            print(
                f"SSH RETRY [{host} attempt {attempt}/6: {type(error).__name__}]",
                flush=True,
            )
            if attempt < 6:
                time.sleep(5)
    raise RuntimeError(f"cannot connect to {host} after 6 attempts: {last_error}")


def connect_via(
    jump: paramiko.SSHClient, host: str, password: str
) -> paramiko.SSHClient:
    """Reach the client VM through lab .10's on-link route.

    A full-tunnel test necessarily changes .11's default route, so a direct SSH session
    from the workstation can be reset mid-test. The .10 -> .11 path stays on their shared
    LAN and is therefore both the control channel and the recovery path.
    """
    last_error: Exception | None = None
    for attempt in range(1, 7):
        channel = None
        client = paramiko.SSHClient()
        ssh_hostkey.harden(client, host)
        try:
            transport = jump.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("jump-host transport is not active")
            channel = transport.open_channel(
                "direct-tcpip", (host, 22), ("127.0.0.1", 0), timeout=20
            )
            client.connect(
                host,
                port=22,
                username="root",
                password=password,
                sock=channel,
                timeout=25,
                banner_timeout=25,
                auth_timeout=25,
                look_for_keys=False,
                allow_agent=False,
            )
            client_transport = client.get_transport()
            if client_transport is not None:
                client_transport.set_keepalive(15)
            return client
        except Exception as error:
            last_error = error
            client.close()
            if channel is not None:
                channel.close()
            print(
                f"SSH JUMP RETRY [{host} attempt {attempt}/6: {type(error).__name__}]",
                flush=True,
            )
            if attempt < 6:
                time.sleep(5)
    raise RuntimeError(f"cannot connect through lab jump to {host}: {last_error}")


def command(client: paramiko.SSHClient, value: str, timeout: int = 90) -> str:
    _, stdout, stderr = client.exec_command(value, timeout=timeout)
    text = (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).rstrip()
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise RuntimeError(f"remote command failed ({status}): {value}\n{text[-2000:]}")
    return text


def ini_from_link(path: Path) -> str:
    parsed = urlsplit(path.read_text(encoding="utf-8").strip())
    query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    if parsed.hostname != PROD_HOST or parsed.username != "user01" or parsed.password is None:
        raise RuntimeError(f"malformed/current-host mismatch in {path.name}")
    for key in ("proto", "mode", "key"):
        if not query.get(key):
            raise RuntimeError(f"{path.name} is missing {key}")
    lines = [
        "[qeli]",
        f"server = {parsed.hostname}:{parsed.port}",
        f"proto = {query['proto']}",
        f"user = {unquote(parsed.username)}",
        f"pass = {unquote(parsed.password)}",
        f"key = {query['key']}",
        f"mode = {query['mode']}",
        # The production Reality profile pushes an external resolver. A split-tunnel client
        # must reject that resolver because its queries would leave in cleartext over the
        # physical link. Exercise the intended VPN/DNS contract in full-tunnel mode instead.
        "gateway = true",
        # Lab .11 can concurrently host another qeli client on the default vpn0. Never take
        # over another process's interface; this matrix owns a release-specific TUN name.
        f"dev = {CLIENT_TUN}",
        "timeout = 30",
        "reconnect = false",
    ]
    if query.get("sni"):
        lines.append(f"sni = {query['sni']}")
    if query.get("rsid"):
        lines.append(f"reality_sid = {query['rsid']}")
    if query.get("obfs"):
        lines.append(f"obfs_key = {query['obfs']}")
    if query.get("front"):
        lines.append(f"front = {query['front']}")
    if query.get("quic", "").lower() in ("1", "true", "yes", "on"):
        lines.append("quic = true")
    # Keep logging on stdout so every transport gets an isolated evidence file.
    # A fixed [logging].file would divert all modes into one shared remote log.
    lines.append("")
    return "\n".join(lines)


def dns_resolution(client: paramiko.SSHClient, stage: str) -> str:
    output = command(
        client,
        "getent ahostsv4 example.com 2>/dev/null | awk 'NR==1 {print $1}'",
        timeout=15,
    ).strip()
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", output):
        raise RuntimeError(f"Linux DNS failed at {stage}: {output!r}")
    return output


def start_capture(client: paramiko.SSHClient, path: str) -> int:
    pid = command(
        client,
        f"rm -f {path} {path}.log; nohup tcpdump -i any -nn -s0 -U -w {path} "
        f"'{CAPTURE_FILTER}' >{path}.log 2>&1 </dev/null & echo $!",
    ).splitlines()[-1]
    if not pid.isdigit():
        raise RuntimeError(f"tcpdump did not return a PID for {path}: {pid!r}")
    return int(pid)


def stop_capture(client: paramiko.SSHClient, pid: int, path: str, local: Path) -> None:
    command(client, f"kill -INT {pid} 2>/dev/null || true; sleep 2", timeout=15)
    command(client, f"kill -TERM {pid} 2>/dev/null || true", timeout=15)
    with client.open_sftp() as sftp:
        sftp.get(path, str(local))
    if local.stat().st_size <= 24:
        raise RuntimeError(f"packet capture is empty: {local}")


def main() -> int:
    if not PROD_HOST:
        raise SystemExit("QELI_PROD_HOST is required")
    password = os.environ["QELI_LAB_PASS"]
    print(f"SSH CONNECT [build lab {LAB_SERVER}]", flush=True)
    source = connect(LAB_SERVER, password)
    print(f"SSH CONNECT [client lab {LAB_CLIENT} via {LAB_SERVER}]", flush=True)
    lab = connect_via(source, LAB_CLIENT, password)
    print("SSH CONNECT [production]", flush=True)
    prod = connect(PROD_HOST, os.environ["QELI_PROD_PASS"])
    current_pid: int | None = None
    lab_capture_pid: int | None = None
    prod_capture_pid: int | None = None
    management_route_added = False
    results: list[str] = []
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    try:
        # Recover only a prior instance of THIS matrix. A lost direct SSH control channel
        # can leave its full-tunnel process alive; the jump path above remains reachable.
        # Never touch the pre-existing vpn0/PID owned by another lab workload.
        command(
            lab,
            f"pkill -TERM -f '^{CLIENT_BINARY} client -c {REMOTE_PREFIX}-' "
            "2>/dev/null || true; sleep 2; "
            f"pkill -KILL -f '^{CLIENT_BINARY} client -c {REMOTE_PREFIX}-' "
            "2>/dev/null || true; "
            f"test ! -f {RESOLV_BACKUP} || cp --preserve=all {RESOLV_BACKUP} /etc/resolv.conf; "
            f"ip link show {CLIENT_TUN} >/dev/null 2>&1 && ip link delete {CLIENT_TUN} "
            f"2>/dev/null || true; rm -f {PID_FILE}",
        )
        results.append("STALE E2E RECOVERY PASS [isolated process/TUN/resolver only]")

        existing_management_route = command(
            lab, "ip route show 192.168.50.0/24"
        ).strip()
        if existing_management_route:
            if MGMT_ROUTE not in existing_management_route:
                raise RuntimeError(
                    "lab has an unexpected pre-existing management route: "
                    + existing_management_route
                )
        else:
            command(lab, f"ip route add {MGMT_ROUTE}")
            management_route_added = True
        results.append("MANAGEMENT ROUTE PASS [workstation /24 pinned outside full tunnel]")

        # Refuse a partial matrix instead of mutating production configuration. The current
        # server is expected to expose the same nine profiles used by its share-link command.
        tcp = command(prod, "ss -tlnH | awk '{print $4}'")
        udp = command(prod, "ss -ulnH | awk '{print $4}'")
        missing = []
        for name, proto, port in PROFILES:
            listeners = tcp if proto == "tcp" else udp
            if not re.search(rf":{port}(?:\s|$)", listeners):
                missing.append(f"{name}/{proto}:{port}")
        if missing:
            raise RuntimeError(f"production profiles are not listening: {missing}")

        with source.open_sftp() as sftp:
            with sftp.open(SOURCE_BINARY, "rb") as stream:
                binary = stream.read()
        source_sha = hashlib.sha256(binary).hexdigest()
        with lab.open_sftp() as sftp:
            sftp.putfo(io.BytesIO(binary), CLIENT_BINARY)
        command(lab, f"chmod 700 {CLIENT_BINARY}")
        installed_sha = command(lab, f"sha256sum {CLIENT_BINARY} | awk '{{print $1}}'").strip()
        version = command(lab, f"{CLIENT_BINARY} --version 2>&1 | head -1").strip()
        if installed_sha != source_sha or version != f"qeli {VERSION}":
            raise RuntimeError("lab Linux client binary does not match the gate-passed release")
        results.append(f"BINARY PASS sha256={source_sha} version={version}")

        command(lab, f"cp --preserve=all /etc/resolv.conf {RESOLV_BACKUP}")
        baseline_resolv = command(lab, "sha256sum /etc/resolv.conf | awk '{print $1}'").strip()
        baseline_dns = dns_resolution(lab, "baseline physical network")
        results.append(f"BASELINE DNS PASS -> {baseline_dns}")

        lab_capture_pid = start_capture(lab, LAB_CAPTURE)
        prod_capture_pid = start_capture(prod, PROD_CAPTURE)
        results.append("PACKET CAPTURE START PASS [lab + production]")

        egress = command(
            lab,
            "curl -4fsS --max-time 12 https://api.ipify.org 2>/dev/null || "
            "curl -4fsS --max-time 12 https://ifconfig.me/ip 2>/dev/null",
        ).strip()
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", egress):
            raise RuntimeError("could not determine lab egress IP for lockout cleanup")
        command(prod, f"/usr/local/bin/qeli unblock {egress} >/dev/null 2>&1 || true")

        for name, proto, port in PROFILES:
            profile_path = LINKS / f"user01__{name}.qeli"
            if not profile_path.is_file():
                raise RuntimeError(f"missing current production link: {profile_path}")
            config = ini_from_link(profile_path)
            remote_config = f"{REMOTE_PREFIX}-{name}.conf"
            remote_log = f"{REMOTE_PREFIX}-{name}.log"
            with lab.open_sftp() as sftp:
                sftp.putfo(io.BytesIO(config.encode()), remote_config)
            command(lab, f"chmod 600 {remote_config}")
            command(
                lab,
                f": > {remote_log}; RUST_LOG=debug nohup {CLIENT_BINARY} client -c {remote_config} "
                f">{remote_log} 2>&1 </dev/null & echo $! >{PID_FILE}",
            )
            pid_text = command(lab, f"cat {PID_FILE}").strip()
            if not pid_text.isdigit():
                raise RuntimeError(f"Linux client did not start for {name}")
            current_pid = int(pid_text)

            log_text = ""
            for _ in range(40):
                time.sleep(1)
                log_text = command(lab, f"cat {remote_log}")
                if "Auth OK" in log_text and "transport core state: Running" in log_text:
                    break
                if not command(lab, f"kill -0 {current_pid} 2>/dev/null && echo alive || echo dead").endswith("alive"):
                    break
            ip_match = re.search(
                r"Auth OK(?: \(plain\))?, (?:assigned )?IP(?::)?\s*([0-9.]+)",
                log_text,
            )
            push = re.search(r"server push: DNS ([0-9.]+):53 ACCEPTED", log_text)
            if ip_match is None or push is None or f"dns=[{push.group(1)}:53]" not in log_text:
                raise RuntimeError(f"Linux {name} did not authenticate/apply pushed DNS:\n{log_text[-3000:]}")
            gateway_match = re.search(r"server push: ip=[^ ]+ gw=([0-9.]+)", log_text)
            if gateway_match is None:
                raise RuntimeError(f"Linux {name} did not report the server gateway")
            ping = command(
                lab,
                f"ping -c 2 -W 2 {gateway_match.group(1)} 2>/dev/null || true",
            )
            received = re.search(r"(\d+) received", ping)
            if received is None or int(received.group(1)) == 0:
                raise RuntimeError(f"Linux {name} cannot reach its tunnel gateway")
            resolved = dns_resolution(lab, f"{name} tunnel")

            command(lab, f"kill -TERM {current_pid} 2>/dev/null || true")
            for _ in range(20):
                time.sleep(0.5)
                if command(
                    lab,
                    f"kill -0 {current_pid} 2>/dev/null && echo alive || echo stopped",
                ).endswith("stopped"):
                    break
            else:
                command(lab, f"kill -KILL {current_pid} 2>/dev/null || true")
                raise RuntimeError(f"Linux {name} did not stop gracefully within 10s")
            current_pid = None

            after_resolv = command(lab, "sha256sum /etc/resolv.conf | awk '{print $1}'").strip()
            if after_resolv != baseline_resolv:
                raise RuntimeError(f"Linux {name} did not restore /etc/resolv.conf")
            physical = dns_resolution(lab, f"after {name} disconnect")
            (EVIDENCE / f"linux-prod-{name}.log").write_text(log_text, encoding="utf-8")
            line = (
                f"MODE PASS {name} {proto}:{port} ip={ip_match.group(1)} "
                f"dns={push.group(1)} resolved={resolved} physical={physical}"
            )
            print(line, flush=True)
            results.append(line)

        (EVIDENCE / "linux-prod-matrix-result.txt").write_text(
            "RESULT: PASS\n" + "\n".join(results) + "\n",
            encoding="utf-8",
        )
        print("LINUX_PROD_MATRIX_RESULT: PASS")
        return 0
    except Exception as error:
        results.append(f"FAIL: {error}")
        (EVIDENCE / "linux-prod-matrix-result.txt").write_text(
            "RESULT: FAIL\n" + "\n".join(results) + "\n",
            encoding="utf-8",
        )
        raise
    finally:
        if current_pid is not None:
            try:
                command(lab, f"kill -TERM {current_pid} 2>/dev/null || true; sleep 1")
            except Exception:
                pass
        try:
            command(lab, f"cp --preserve=all {RESOLV_BACKUP} /etc/resolv.conf 2>/dev/null || true")
        except Exception:
            pass
        if management_route_added:
            try:
                command(lab, "ip route del 192.168.50.0/24 2>/dev/null || true")
            except Exception:
                pass
        capture_errors = []
        if lab_capture_pid is not None:
            try:
                stop_capture(
                    lab,
                    lab_capture_pid,
                    LAB_CAPTURE,
                    EVIDENCE / "linux-prod-matrix-lab.pcap",
                )
            except Exception as error:
                capture_errors.append(f"lab pcap: {error}")
        if prod_capture_pid is not None:
            try:
                stop_capture(
                    prod,
                    prod_capture_pid,
                    PROD_CAPTURE,
                    EVIDENCE / "linux-prod-matrix-prod.pcap",
                )
            except Exception as error:
                capture_errors.append(f"production pcap: {error}")
        if capture_errors:
            print("CAPTURE COLLECTION WARNING: " + "; ".join(capture_errors), file=sys.stderr)
        source.close()
        lab.close()
        prod.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"LINUX_PROD_MATRIX_RESULT: FAIL ({error})", file=sys.stderr)
        raise SystemExit(1)
