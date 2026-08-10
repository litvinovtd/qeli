#!/usr/bin/env python3
"""Current Android TCP/UDP smoke test against the canonical lab server.

The Android client stores flat INI profiles.  The legacy JSON profile body was
retired, so this test deliberately exercises the same import/migration path as
the application.  Both transports must authenticate and carry a reverse ping.
"""

import io
import re
import sys
import time
from xml.sax.saxutils import escape

from lab_common import LAB_CLI, LAB_SRV, connect

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


cc = connect(LAB_CLI)
sc = connect(LAB_SRV)
ADB = "/root/android-sdk/platform-tools/adb"
SERVER_IP = "10.66.116.10"
APK = "/root/android-project/app/build/outputs/apk/debug/app-debug.apk"
EMULATOR = "/root/android-sdk/emulator/emulator"


def adb(command, timeout=60):
    _, stdout, stderr = cc.exec_command(f"{ADB} {command}", timeout=timeout)
    return (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).rstrip()


def client(command, timeout=60):
    _, stdout, stderr = cc.exec_command(command, timeout=timeout)
    return (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).rstrip()


def server(command, timeout=60):
    _, stdout, stderr = sc.exec_command(command, timeout=timeout)
    return (
        stdout.read().decode("utf-8", "replace")
        + stderr.read().decode("utf-8", "replace")
    ).rstrip()


def read_remote_bytes(client_connection, path):
    with client_connection.open_sftp() as sftp:
        with sftp.open(path, "rb") as stream:
            return stream.read()


def ensure_emulator():
    """Start the lab AVD after a VM reboot and wait for a completed Android boot."""
    if not re.search(r"(?m)^\S+\s+device$", adb("devices")):
        print("[emulator] no device after lab reboot; starting AVD test")
        launch = client(
            "rm -f /root/qeli-e2e-emulator.log; "
            f"setsid nohup {EMULATOR} -avd test -no-window -no-audio -no-boot-anim "
            "-gpu swiftshader_indirect -no-snapshot-save "
            ">/root/qeli-e2e-emulator.log 2>&1 </dev/null & echo $!"
        )
        launch_lines = launch.splitlines()
        if not launch_lines or not launch_lines[-1].isdigit():
            raise RuntimeError(f"Android emulator did not start: {launch}")

    for _ in range(90):
        devices = adb("devices")
        booted = adb("shell getprop sys.boot_completed 2>/dev/null").strip()
        if re.search(r"(?m)^\S+\s+device$", devices) and booted == "1":
            adb("shell input keyevent 82")
            print("[emulator] boot completed")
            return
        time.sleep(2)
    raise RuntimeError(
        "Android emulator did not complete boot:\n"
        + client("tail -80 /root/qeli-e2e-emulator.log 2>/dev/null")
    )


def ini_profile(name, port, proto, route_local, server_key, mode="fake-tls", extra=()):
    return "\n".join(
        [
            f"# {name}",
            "[qeli]",
            f"server = {SERVER_IP}:{port}",
            f"proto = {proto}",
            "user = e2e-android",
            "pass = testpass123",
            f"key = {server_key}",
            f"mode = {mode}",
            "sni = www.cloudflare.com",
            f"route_local = {'true' if route_local else 'false'}",
            "dns = 1.1.1.1",
            *extra,
            "",
        ]
    )


def inject(name, profile):
    payload = {"active": 0, "profiles": [{"name": name, "json": profile}]}
    import json

    xml = (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
        '    <string name="profiles_json">'
        + escape(json.dumps(payload))
        + "</string>\n</map>\n"
    )

    adb("shell am force-stop com.qeli")
    # ProfileStore migrates vpn.xml only when its encrypted store is empty.
    adb("shell pm clear com.qeli")
    adb("shell appops set com.qeli ACTIVATE_VPN allow")
    adb("shell appops set com.qeli ACTIVATE_PLATFORM_VPN allow")
    adb("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
    sftp = cc.open_sftp()
    sftp.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml")
    sftp.close()
    adb("push /root/vpn.xml /data/local/tmp/vpn.xml")
    adb("shell run-as com.qeli mkdir shared_prefs")
    adb("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")


def ui_dump():
    for _ in range(4):
        dump = adb("exec-out uiautomator dump /dev/tty 2>/dev/null")
        if "<hierarchy" in dump:
            return dump
        time.sleep(1)
    return ""


def tap_label(labels, dump):
    for label in labels:
        match = re.search(
            r'(?:text|content-desc)="'
            + re.escape(label)
            + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            dump,
            re.IGNORECASE,
        )
        if match:
            x = (int(match.group(1)) + int(match.group(3))) // 2
            y = (int(match.group(2)) + int(match.group(4))) // 2
            adb(f"shell input tap {x} {y}")
            return f"{label} @{x},{y}"
    return None


def run(name, port, proto, route_local, server_key, mode="fake-tls", extra=()):
    print(f"\n===== {name} =====")
    inject(
        name,
        ini_profile(name, port, proto, route_local, server_key, mode=mode, extra=extra),
    )
    adb("logcat -c")
    adb("shell am start -n com.qeli/.MainActivity")
    time.sleep(7)
    dump = ui_dump()

    # Some AVD images show this once per installation.  It is unrelated to VPN
    # consent, but it covers the application until answered.
    if "always run in background" in dump.lower():
        tapped = tap_label(["ALLOW", "Allow"], dump)
        if not tapped:
            raise RuntimeError("background-run dialog is present but ALLOW was not found")
        time.sleep(2)
        dump = ui_dump()

    if name not in dump:
        raise RuntimeError(f"injected INI profile {name!r} is not active in the UI")
    tapped = tap_label(["Connect", "CONNECT", "Tap to connect"], dump)
    if not tapped:
        raise RuntimeError("Connect control was not found in the current UI")
    print("tap:", tapped)

    client_log = ""
    for _ in range(15):
        time.sleep(2)
        client_log = adb(
            "logcat -d | grep -iE 'VpnSvc|Auth OK|identity verified|TUN ready|ERR|FATAL' | tail -80"
        )
        if "Auth OK" in client_log:
            break
    print("client log:\n" + (client_log or "(none)"))

    required_core_markers = (
        "Shared native transport active: ABI 0x1000a",
        "Native transport platform dispatcher active",
        "Rust owns the TUN payload",
    )
    missing_core_markers = [
        marker for marker in required_core_markers if marker not in client_log
    ]
    if missing_core_markers:
        raise RuntimeError(
            f"{name}: shared-core ABI 1.10 native transport path was not active; "
            f"missing {missing_core_markers}"
        )
    lower_log = client_log.lower()
    if (
        "native transport core unavailable" in lower_log
        or "native transport event dispatcher failed" in lower_log
    ):
        raise RuntimeError(f"{name}: shared transport core retired during the e2e run")

    ip_match = re.search(r"Auth OK, IP (\d+\.\d+\.\d+\.\d+)", client_log)
    if not ip_match:
        raise RuntimeError(f"{name}: Auth OK with assigned tunnel IP was not observed")

    ping = server(f"ping -c3 -W2 {ip_match.group(1)}")
    print(f"server -> client {ip_match.group(1)}:\n{ping}")
    received = re.search(r"(\d+) received", ping)
    if not received or int(received.group(1)) == 0:
        raise RuntimeError(f"{name}: tunnel did not return the server ping")
    adb("shell am force-stop com.qeli")


route_line = "route = 192.168.99.0/24 gateway=10.9.0.1"
temp_begin = "# BEGIN qeli Android native transport matrix"
temp_end = "# END qeli Android native transport matrix"
user_begin = "# BEGIN qeli Android e2e user"
user_end = "# END qeli Android e2e user"
# Argon2id hash of the intentionally public lab-only password "testpass123".
test_password_hash = (
    "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$"
    "CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
)
obfs_key = "android-native-obfs-e2e-key"
temp_transport_profiles = f"""
{temp_begin}
[profile:e2e-plain]
bind.address = 0.0.0.0
bind.port = 1444
bind.transport = tcp
tun.name = e2eplain0
tun.address = 10.9.2.1
tun.mtu = 1400
pool.cidr = 10.9.2.0/24
pool.exclude = 10.9.2.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = 10.9.2.1
dns.upstream = 1.1.1.1
obf.mode = plain

[profile:e2e-obfs-tcp]
bind.address = 0.0.0.0
bind.port = 1445
bind.transport = tcp
tun.name = e2eobfst0
tun.address = 10.9.3.1
tun.mtu = 1400
pool.cidr = 10.9.3.0/24
pool.exclude = 10.9.3.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = 10.9.3.1
dns.upstream = 1.1.1.1
obf.mode = obfs
obf.obfs_key = {obfs_key}
obf.obfs_fronting = none

[profile:e2e-udp]
bind.address = 0.0.0.0
bind.port = 1443
bind.transport = udp
tun.name = e2eudp0
tun.address = 10.9.1.1
tun.mtu = 1400
pool.cidr = 10.9.1.0/24
pool.exclude = 10.9.1.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = 10.9.1.1
dns.upstream = 1.1.1.1
obf.mode = fake-tls
obf.tls.server_name = www.cloudflare.com
obf.padding.enabled = true
obf.padding.min_bytes = 32
obf.padding.max_bytes = 512

[profile:e2e-obfs-udp]
bind.address = 0.0.0.0
bind.port = 1446
bind.transport = udp
tun.name = e2eobfsu0
tun.address = 10.9.4.1
tun.mtu = 1400
pool.cidr = 10.9.4.0/24
pool.exclude = 10.9.4.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = 10.9.4.1
dns.upstream = 1.1.1.1
obf.mode = obfs
obf.obfs_key = {obfs_key}
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.traffic_shaping.enabled = true
obf.traffic_shaping.idle_gap_mean_ms = 200
obf.traffic_shaping.idle_gap_min_ms = 30
obf.traffic_shaping.idle_gap_max_ms = 1500
obf.traffic_shaping.budget_bytes_per_sec = 65536
obf.traffic_shaping.min_size = 80
obf.traffic_shaping.max_size = 600
{temp_end}
"""


def clean_test_config(config):
    output = []
    inside_temp = False
    for line in config.splitlines():
        if line.strip() == temp_begin:
            inside_temp = True
            continue
        if line.strip() == temp_end:
            inside_temp = False
            continue
        if not inside_temp and route_line not in line:
            output.append(line)
    return "\n".join(output).rstrip() + "\n"


def clean_test_user(config):
    output = []
    inside_temp = False
    for line in config.splitlines():
        if line.strip() == user_begin:
            inside_temp = True
            continue
        if line.strip() == user_end:
            inside_temp = False
            continue
        if not inside_temp:
            output.append(line)
    return "\n".join(output).rstrip() + "\n"


def identity_key(profile):
    listing = server(
        "/opt/qeli-src/target/debug/qeli show-identity --config /etc/qeli/server.conf"
    )
    match = re.search(
        rf"(?m)^{re.escape(profile)}\s+\S+\s+([0-9a-f]{{64}})\s*$", listing
    )
    if not match:
        raise RuntimeError(f"public identity key for profile {profile!r} was not found:\n{listing}")
    return match.group(1)


original_server_bytes = read_remote_bytes(sc, "/etc/qeli/server.conf")
original_users_bytes = read_remote_bytes(sc, "/etc/qeli/users.conf")
original_server_config = original_server_bytes.decode("utf-8")
original_users_config = original_users_bytes.decode("utf-8")
passed = False
try:
    ensure_emulator()
    install = adb(f"install -r -d {APK}", timeout=180)
    print("[install]", install)
    if "Success" not in install:
        raise RuntimeError(f"current lab APK was not installed: {install}")

    config = clean_test_config(original_server_config)
    lines = []
    for line in config.splitlines():
        lines.append(line)
        if line.strip() == "[profile:tcp]":
            lines.append(route_line)
    prepared = "\n".join(lines).rstrip() + "\n" + temp_transport_profiles
    sftp = sc.open_sftp()
    with sftp.open("/etc/qeli/server.conf", "w") as stream:
        stream.write(prepared)
    users = clean_test_user(original_users_config)
    users += (
        f"\n{user_begin}\n[user:e2e-android]\n"
        f"password_hash = {test_password_hash}\nenabled = true\n{user_end}\n"
    )
    with sftp.open("/etc/qeli/users.conf", "w") as stream:
        stream.write(users)
    sftp.close()
    state = server("systemctl restart qeli-server; sleep 3; systemctl is-active qeli-server")
    if not state.endswith("active"):
        raise RuntimeError(f"canonical server failed to restart: {state}")

    run("TCP local", 443, "tcp", True, identity_key("tcp"))
    run("TCP plain", 1444, "tcp", False, identity_key("e2e-plain"), mode="plain")
    run(
        "TCP obfs",
        1445,
        "tcp",
        False,
        identity_key("e2e-obfs-tcp"),
        mode="obfs",
        extra=(f"obfs_key = {obfs_key}", "front = none"),
    )
    run("UDP fake-TLS", 1443, "udp", False, identity_key("e2e-udp"))
    run(
        "UDP obfs + heartbeat/shaping",
        1446,
        "udp",
        False,
        identity_key("e2e-obfs-udp"),
        mode="obfs",
        extra=(f"obfs_key = {obfs_key}",),
    )
    passed = True
finally:
    adb("shell am force-stop com.qeli")
    sftp = sc.open_sftp()
    with sftp.open("/etc/qeli/server.conf", "wb") as stream:
        stream.write(original_server_bytes)
    with sftp.open("/etc/qeli/users.conf", "wb") as stream:
        stream.write(original_users_bytes)
    sftp.close()
    print("\n[cleanup]", server("systemctl restart qeli-server; sleep 2; systemctl is-active qeli-server"))
    cc.close()
    sc.close()

print("\n========== RESULT: PASS (Android native transport matrix) ==========")
sys.exit(0 if passed else 1)
