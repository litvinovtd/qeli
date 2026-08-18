#!/usr/bin/env python3
"""Android manual-disconnect, DNS-push, wake, and long-session E2E against prod.

Requires the ignored production qeli:// profile (or QELI_PROD_PROFILE), a running lab
Android emulator, pinned SSH host keys, and QELI_LAB_PASS/QELI_PROD_PASS/QELI_PROD_HOST.
The injected profile deliberately omits dns_servers: DNS must come only from server push.
Logs and packet captures are written below the current version's release evidence directory.
"""

import io
import json
import os
import re
import shlex
import sys
import time
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from xml.sax.saxutils import escape

import paramiko

import ssh_hostkey


ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "qeli" / "Cargo.toml").open("rb") as manifest:
    VERSION = tomllib.load(manifest)["package"]["version"]
ADB_OVERRIDE = os.environ.get("QELI_ADB", "").strip()
ADB_RESOLVED: str | None = None
LAB_HOST = os.environ.get("QELI_LAB_IP", "10.66.116.11")
PROD_HOST = os.environ.get("QELI_PROD_HOST", "").strip()
PROFILE_PATH = Path(
    os.environ.get(
        "QELI_PROD_PROFILE",
        ROOT / "release/prod-client-configs/allmodes/user01__reality-tls.qeli",
    )
)
MATRIX_PROFILE_PATHS = tuple(
    ROOT / f"release/prod-client-configs/allmodes/user01__{name}.qeli"
    for name in (
        "reality",
        "fake-tls",
        "obfs-ws",
        "obfs-none",
        "plain",
        "udp-fake-tls",
        "udp-quic",
        "udp-obfs",
        "obfs-awg",
    )
)
EVIDENCE = ROOT / "release" / "dist" / f"v{VERSION}" / "evidence"
DNS_NAME = os.environ.get("QELI_E2E_DNS_NAME", "example.com")


def connect(host: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    ssh_hostkey.harden(client, host)
    client.connect(
        host,
        username="root",
        password=password,
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


if not PROD_HOST:
    raise SystemExit("QELI_PROD_HOST is required")
if not PROFILE_PATH.is_file():
    raise SystemExit(f"production profile is missing: {PROFILE_PATH}")

lab = connect(LAB_HOST, os.environ["QELI_LAB_PASS"])
prod = connect(PROD_HOST, os.environ["QELI_PROD_PASS"])
events: list[str] = []
captures: list[tuple[paramiko.SSHClient, int, str, Path]] = []
run_prod_log_line = 0
run_prod_since = 0
original_auto_time: str | None = None


def remote(
    client: paramiko.SSHClient,
    command: str,
    timeout: int = 90,
    check: bool = True,
) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    result = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if status != 0 and check:
        detail = (result + error).strip()
        raise RuntimeError(f"remote command failed ({status}): {command}\n{detail[-2000:]}")
    return (result + error).rstrip()


def adb(command: str, timeout: int = 90, check: bool = True) -> str:
    global ADB_RESOLVED
    if ADB_RESOLVED is None:
        candidate = ADB_OVERRIDE or "adb"
        quoted = shlex.quote(candidate)
        probe = (
            f"command -v {quoted} 2>/dev/null || "
            f"([ -x {quoted} ] && printf '%s\\n' {quoted})"
        )
        if not ADB_OVERRIDE:
            legacy = "/root/android-sdk/platform-tools/adb"
            probe += f" || ([ -x {legacy} ] && printf '%s\\n' {legacy})"
        resolved = remote(lab, probe, check=False).splitlines()
        if not resolved:
            raise RuntimeError(
                "adb was not found on the remote Android lab host; set QELI_ADB to its remote path"
            )
        ADB_RESOLVED = shlex.quote(resolved[0].strip())
    return remote(lab, f"{ADB_RESOLVED} {command}", timeout, check=check)


def log(message: str) -> None:
    print(message, flush=True)
    events.append(message)


def ui_dump() -> str:
    for _ in range(5):
        dump = adb("exec-out uiautomator dump /dev/tty 2>/dev/null")
        if "<hierarchy" in dump:
            return dump
        time.sleep(1)
    return ""


def tap_label(labels: tuple[str, ...], dump: str | None = None) -> str:
    view = dump if dump is not None else ui_dump()
    for label in labels:
        match = re.search(
            r'(?:text|content-desc)="'
            + re.escape(label)
            + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            view,
            re.IGNORECASE,
        )
        if match:
            x = (int(match.group(1)) + int(match.group(3))) // 2
            y = (int(match.group(2)) + int(match.group(4))) // 2
            adb(f"shell input tap {x} {y}")
            return f"{label}@{x},{y}"
    raise RuntimeError(f"none of the UI labels is visible: {labels}")


def vpn_log() -> str:
    return adb("logcat -d -s VpnSvc:D '*:S'")


def wait_auth(expected_count: int, timeout: int = 45) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = vpn_log()
        # Auth precedes VpnService.Builder.establish()/NetworkPlan ACK. DNS is not usable
        # until that platform step finishes, and fast UDP handshakes can expose the gap.
        if (
            text.count("Auth OK, IP") >= expected_count
            and text.count("Native NetworkPlan") >= expected_count
        ):
            return text
        if "Refusing to connect" in text or "FATAL" in text:
            raise RuntimeError("Android transport failed:\n" + text[-4000:])
        time.sleep(1)
    raise RuntimeError("timed out waiting for Android Auth OK + NetworkPlan APPLIED:\n" + vpn_log()[-4000:])


def dns_resolves(stage: str) -> str:
    # Android toybox prints the resolved numeric address in the PING header even when the
    # destination filters ICMP. That isolates resolver health from ICMP reachability.
    # A resolved host may legitimately drop ICMP. Preserve ping's header even when toybox
    # exits 1 so this remains a DNS check rather than an accidental ICMP reachability gate.
    result = adb(f"shell ping -c 1 -W 4 {DNS_NAME} 2>&1", timeout=15, check=False)
    resolved = re.search(r"(?m)^PING\s+\S+\s+\(([0-9.]+)\)", result)
    if not resolved:
        resolved = re.search(r"(?m)^PING\s+([0-9.]+)\s+", result)
    if not resolved:
        raise RuntimeError(f"DNS failed at {stage}: {result[-1000:]}")
    log(f"DNS PASS [{stage}] -> {resolved.group(1)}")
    return result


def profile_ping(stage: str) -> None:
    tap_label(("Ping",))
    deadline = time.time() + 15
    while time.time() < deadline:
        view = ui_dump()
        if re.search(r"reachable\s*[·.]\s*\d+\s*ms", view, re.IGNORECASE):
            log(f"PROFILE PING PASS [{stage}]")
            return
        if "unreachable" in view.lower():
            raise RuntimeError(f"profile ping is unreachable at {stage}")
        time.sleep(1)
    raise RuntimeError(f"profile ping did not complete at {stage}")


def wait_disconnected(timeout: int = 30) -> float:
    started = time.monotonic()
    deadline = time.time() + timeout
    while time.time() < deadline:
        view = ui_dump()
        if "Disconnected" in view or "Tap to connect" in view:
            service = adb("shell dumpsys activity services com.qeli/.VpnServiceImpl")
            if "ServiceRecord" not in service:
                return time.monotonic() - started
        time.sleep(0.5)
    raise RuntimeError("Android did not complete native VPN teardown")


def start_capture(
    client: paramiko.SSHClient,
    remote_path: str,
    local_name: str,
    capture_filter: str,
) -> None:
    command = (
        "nohup timeout 900 tcpdump -i any -nn -s 256 -w "
        + remote_path
        + " "
        + capture_filter
        + " >"
        + remote_path
        + ".log 2>&1 </dev/null & echo $!"
    )
    pid_text = remote(client, command).splitlines()[-1]
    if not pid_text.isdigit():
        raise RuntimeError(f"tcpdump did not start: {pid_text}")
    captures.append((client, int(pid_text), remote_path, EVIDENCE / local_name))


def stop_and_pull_captures() -> None:
    for client, pid, remote_path, local_path in captures:
        remote(client, f"kill -INT {pid} 2>/dev/null || true; sleep 2")
        with client.open_sftp() as sftp:
            stat = sftp.stat(remote_path)
            if stat.st_size <= 24:
                raise RuntimeError(f"empty packet capture: {remote_path}")
            sftp.get(remote_path, str(local_path))
        log(f"PCAP PASS [{local_path.name}] {local_path.stat().st_size} bytes")
    captures.clear()


def collect_evidence(result: str) -> None:
    """Persist diagnostics on PASS and FAIL; collection errors stay visible in the report."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    collection_errors: list[str] = []
    try:
        client_log = vpn_log()
        (EVIDENCE / "android-prod-lifecycle-client.log").write_text(
            client_log,
            encoding="utf-8",
        )
    except Exception as error:
        collection_errors.append(f"client log: {error}")
    try:
        server_file_log = remote(
            prod,
            f"tail -n +{run_prod_log_line + 1} /var/log/qeli/server.log 2>/dev/null || true",
        )
        server_journal = remote(
            prod,
            f"journalctl -u qeli.service --since=@{run_prod_since} --no-pager 2>/dev/null || true",
        )
        (EVIDENCE / "android-prod-lifecycle-server.log").write_text(
            server_file_log + "\n\n--- JOURNAL ---\n" + server_journal,
            encoding="utf-8",
        )
    except Exception as error:
        collection_errors.append(f"server log: {error}")
    try:
        stop_and_pull_captures()
    except Exception as error:
        collection_errors.append(f"pcap: {error}")
    (EVIDENCE / "android-prod-lifecycle-result.txt").write_text(
        f"RESULT: {result}\n"
        + "\n".join(events)
        + ("\nCOLLECTION ERRORS:\n" + "\n".join(collection_errors) if collection_errors else "")
        + "\n",
        encoding="utf-8",
    )


def production_ini(profile_path: Path = PROFILE_PATH) -> str:
    link = profile_path.read_text(encoding="utf-8").strip()
    parsed = urlsplit(link)
    if parsed.scheme != "qeli" or not parsed.hostname or not parsed.username:
        raise RuntimeError("QELI_PROD_PROFILE is not a qeli:// client link")
    if parsed.hostname != PROD_HOST:
        raise RuntimeError("production profile host differs from QELI_PROD_HOST")
    query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    required = ("proto", "mode", "key")
    missing = [key for key in required if not query.get(key)]
    if missing:
        raise RuntimeError(f"production profile is missing {missing}")
    lines = [
        "# PROD E2E: no client dns_servers",
        "[qeli]",
        f"server = {parsed.hostname}:{parsed.port or 443}",
        f"proto = {query['proto']}",
        f"user = {unquote(parsed.username)}",
        f"pass = {unquote(parsed.password or '')}",
        f"key = {query['key']}",
        f"mode = {query['mode']}",
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
    lines.extend(("gateway = true", "timeout = 30", "reconnect = true", ""))
    return "\n".join(lines)


def inject(profile: str, name: str = "PROD lifecycle no-client-DNS") -> None:
    payload = {"active": 0, "profiles": [{"name": name, "json": profile}]}
    xml = (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
        '    <string name="profiles_json">'
        + escape(json.dumps(payload))
        + "</string>\n</map>\n"
    )
    adb("shell am force-stop com.qeli")
    adb("shell pm clear com.qeli")
    adb("shell appops set com.qeli ACTIVATE_VPN allow")
    adb("shell appops set com.qeli ACTIVATE_PLATFORM_VPN allow")
    adb("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
    with lab.open_sftp() as sftp:
        sftp.putfo(io.BytesIO(xml.encode()), "/root/vpn-lifecycle.xml")
    adb("push /root/vpn-lifecycle.xml /data/local/tmp/vpn-lifecycle.xml")
    adb("shell run-as com.qeli mkdir shared_prefs")
    adb("shell run-as com.qeli cp /data/local/tmp/vpn-lifecycle.xml shared_prefs/vpn.xml")


def sync_emulator_clock() -> None:
    """REALITY tokens expire after ±120s; resumed AVD snapshots commonly have stale time."""
    global original_auto_time
    host_epoch = remote(lab, "date +%s").strip()
    if not host_epoch.isdigit():
        raise RuntimeError(f"could not read the lab host clock: {host_epoch!r}")
    original_auto_time = adb("shell settings get global auto_time").strip()
    # A resumed AVD may publish an old virtual-network time immediately after VPN teardown.
    # If Android's automatic clock remains enabled it silently overwrites the explicit date
    # below between connection generations, making every later REALITY token look stale.
    adb("shell settings put global auto_time 0")
    result = adb(f"shell date -u -s @{host_epoch}")
    guest_epoch = adb("shell date +%s").strip()
    if not guest_epoch.isdigit() or abs(int(guest_epoch) - int(host_epoch)) > 5:
        raise RuntimeError(f"Android clock synchronization failed: {result} / {guest_epoch}")
    time.sleep(2)
    stable_epoch = adb("shell date +%s").strip()
    if not stable_epoch.isdigit() or abs(int(stable_epoch) - int(host_epoch)) > 8:
        raise RuntimeError(f"Android clock did not remain stable: {stable_epoch}")
    log("CLOCK PASS [Android guest aligned for REALITY anti-replay]")


def assert_emulator_clock(stage: str) -> None:
    host_epoch = remote(lab, "date +%s").strip()
    guest_epoch = adb("shell date +%s").strip()
    if not host_epoch.isdigit() or not guest_epoch.isdigit():
        raise RuntimeError(f"could not compare Android clock at {stage}")
    if abs(int(guest_epoch) - int(host_epoch)) > 8:
        raise RuntimeError(f"Android clock drifted before {stage}: {guest_epoch} vs {host_epoch}")


def unblock_lab_source() -> None:
    egress = remote(
        lab,
        "curl -4fsS --max-time 12 https://api.ipify.org 2>/dev/null || "
        "curl -4fsS --max-time 12 https://ifconfig.me/ip 2>/dev/null",
    ).strip()
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", egress):
        raise RuntimeError(f"could not determine the lab egress IPv4 address: {egress!r}")
    remote(prod, f"/usr/local/bin/qeli unblock {egress} >/dev/null 2>&1 || true")
    log("AUTH LOCKOUT CLEANUP PASS [lab egress only]")


def launch_app() -> None:
    adb("logcat -c")
    adb("shell am start -n com.qeli/.MainActivity")
    time.sleep(5)
    view = ui_dump()
    if "always run in background" in view.lower():
        tap_label(("ALLOW", "Allow"), view)
        time.sleep(2)


def verify_connected_generation(text: str, stage: str) -> str:
    pushed_dns = re.search(
        r"server push: DNS ([0-9.]+):53 ACCEPTED into NetworkPlan",
        text,
    )
    if pushed_dns is None:
        raise RuntimeError(f"the server-pushed DNS resolver was not accepted for {stage}")
    required = (
        "Shared native transport active: ABI 0x1000a",
        f"dns=[{pushed_dns.group(1)}:53]",
        "Rust owns the TUN payload",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise RuntimeError(f"native/DNS markers are missing for {stage}: {missing}")
    ip_match = re.search(r"Auth OK, IP ([0-9.]+)", text)
    if ip_match is None:
        raise RuntimeError(f"assigned tunnel IP is missing for {stage}")
    ping = remote(prod, f"ping -c 2 -W 2 {ip_match.group(1)} 2>/dev/null || true")
    received = re.search(r"(\d+) received", ping)
    if received is None or int(received.group(1)) == 0:
        raise RuntimeError(f"prod could not ping Android tunnel IP for {stage}")
    log(f"ANDROID MODE PASS [{stage}] DNS push + reverse tunnel ping")
    return ip_match.group(1)


def connect_ui(expected_auth: int) -> str:
    assert_emulator_clock(f"connect generation {expected_auth}")
    tap_label(("Connect", "CONNECT", "Tap to connect"))
    text = wait_auth(expected_auth)
    dns_resolves(f"connected generation {expected_auth}")
    return text


def disconnect_ui(stage: str) -> None:
    tap_label(("Disconnect", "DISCONNECT", "Tap to disconnect"))
    elapsed = wait_disconnected()
    log(f"DISCONNECT PASS [{stage}] native teardown {elapsed:.2f}s")
    dns_resolves(f"physical network after {stage}")
    profile_ping(f"after {stage}")


def main() -> int:
    global run_prod_log_line, run_prod_since
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    missing_profiles = [str(path) for path in MATRIX_PROFILE_PATHS if not path.is_file()]
    if missing_profiles:
        raise RuntimeError(f"production matrix profiles are missing: {missing_profiles}")
    if "tcpdump" not in remote(prod, "command -v tcpdump || true"):
        raise RuntimeError("tcpdump is unavailable on production")
    if "tcpdump" not in remote(lab, "command -v tcpdump || true"):
        raise RuntimeError("tcpdump is unavailable on the lab client")
    stamp = int(time.time())
    run_prod_log_line = int(
        remote(prod, "wc -l < /var/log/qeli/server.log 2>/dev/null || echo 0") or 0
    )
    run_prod_since = int(remote(prod, "date +%s"))
    start_capture(
        prod,
        f"/tmp/qeli-{VERSION.replace('.', '')}-prod-{stamp}.pcap",
        "android-prod-lifecycle-prod.pcap",
        "port 443 or portrange 8443-8451 or port 53",
    )
    start_capture(
        lab,
        f"/tmp/qeli-{VERSION.replace('.', '')}-lab-{stamp}.pcap",
        "android-prod-lifecycle-lab.pcap",
        f"host {PROD_HOST} or port 53",
    )

    sync_emulator_clock()
    unblock_lab_source()
    inject(production_ini())
    launch_app()
    dns_resolves("baseline physical network")
    profile_ping("baseline physical network")

    first = connect_ui(1)
    verify_connected_generation(first, "reality-tls lifecycle generation 1")
    log("SERVER-PUSH DNS PASS [no dns_servers in client profile]")

    disconnect_ui("cycle 1")
    connect_ui(2)
    disconnect_ui("cycle 2")
    connect_ui(3)

    before_wake = vpn_log().count("Auth OK, IP")
    adb("shell input keyevent 223")
    time.sleep(6)
    adb("shell input keyevent 224")
    adb("shell input keyevent 82")
    wait_auth(before_wake + 1, timeout=45)
    wake_log = vpn_log()
    if "Device woke after" not in wake_log:
        raise RuntimeError("screen-off/wake reconnect marker was not observed")
    dns_resolves("after screen wake reconnect")
    log("WAKE PASS [screen-off reconnect authenticated]")

    # Hold the final generation and sample DNS repeatedly. This catches a resolver that is
    # installed correctly at establish() but stops after idle/heartbeat processing.
    for seconds in (15, 30, 45, 60, 75, 90):
        time.sleep(15)
        dns_resolves(f"long session +{seconds}s")
    log("LONG SESSION PASS [90s, six DNS samples]")

    disconnect_ui("cycle 3 / final")

    # Smoke every other production transport with the exact current share links. Each app
    # reset starts a fresh native owner, and every disconnect verifies that physical DNS and
    # the profile reachability check recover before the next transport starts.
    for profile_path in MATRIX_PROFILE_PATHS:
        mode_name = profile_path.stem.removeprefix("user01__")
        inject(production_ini(profile_path), f"PROD {mode_name} no-client-DNS")
        launch_app()
        profile_ping(f"{mode_name} pre-connect")
        mode_log = connect_ui(1)
        verify_connected_generation(mode_log, mode_name)
        (EVIDENCE / f"android-prod-{mode_name}.log").write_text(
            mode_log,
            encoding="utf-8",
        )
        disconnect_ui(f"{mode_name} final")
    log("ANDROID PROD MATRIX PASS [all 9 profiles]")

    collect_evidence("PASS")
    print("\nE2E_RESULT: PASS")
    return 0


if __name__ == "__main__":
    if os.environ.get("QELI_E2E_SERVER_LOG_ONLY") == "1":
        try:
            print(remote(prod, "tail -n 220 /var/log/qeli/server.log; journalctl -u qeli.service --since=-10min --no-pager"))
        finally:
            lab.close()
            prod.close()
        raise SystemExit(0)
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"\nE2E_RESULT: FAIL ({error})", file=sys.stderr)
        collect_evidence(f"FAIL ({error})")
        raise
    finally:
        # Exact capture PIDs only; leave unrelated tcpdump processes untouched.
        for connection, pid, _, _ in captures:
            try:
                remote(connection, f"kill -INT {pid} 2>/dev/null || true")
            except Exception:
                pass
        if original_auto_time in ("0", "1"):
            try:
                adb(f"shell settings put global auto_time {original_auto_time}")
            except Exception:
                pass
        lab.close()
        prod.close()
