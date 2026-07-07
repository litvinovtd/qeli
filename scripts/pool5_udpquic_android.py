#!/usr/bin/env python3
"""Verify the udp-quic profile from the Android EMULATOR (.11) against a LAB server
(.10), and emit the exact working server + client configs.

Server: a single [profile:udp-quic] (fake-tls over UDP + QUIC masking) on :4443.
Client: the 0.7.8 APK, profile injected as legacy plaintext prefs (migrated to the
encrypted store on launch): protocol=udp, mode=fake-tls, quic.enabled=true, pinned key.
Confirms VpnSvc 'Auth OK' + a held Connected session.
"""
import os, sys, io, json, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
ADB = "/root/android-sdk/platform-tools/adb"
SRV = "10.66.116.10"
BIN = "/opt/qeli-src/target/release/qeli"
CONF = "/etc/qeli/udpq-test.conf"
PORT = 4443
# testpass123 (argon2id) — same hash used across the bench/pool harnesses
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
APK = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-android\dist\app-debug.apk"

SERVER_CONF = f"""[auth]
require_client_key_proof = false
bind_static_to_session = true

[logging]
level = info
file = /var/log/qeli/server.log

[profile:udp-quic]
identity_key = /etc/qeli/identity/udp-quic.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = udp
tun.name = vpnq0
tun.address = 10.9.20.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
tun.queues = 0
pool.cidr = 10.9.20.0/24
pool.exclude = 10.9.20.1
routing.forward_private = true
routing.nat.enabled = false
dns.enabled = true
dns.listen = 10.9.20.1
dns.upstream = 1.1.1.1
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.quic.enabled = true

[user:phone]
password_hash = {HASH}
enabled = true
"""


def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=PW, timeout=25, look_for_keys=False, allow_agent=False)
    return c


def main():
    s = conn(SRV); cl = conn("10.66.116.11")
    def rs(cmd, t=60): _i, o, e = s.exec_command(cmd, timeout=t); return (o.read()+e.read()).decode("utf-8", "replace").strip()
    def a(cmd, t=180): _i, o, e = cl.exec_command(f"{ADB} {cmd}", timeout=t); return (o.read()+e.read()).decode("utf-8", "replace").strip()

    # ── 1. deploy + start the udp-quic server ────────────────────────────────
    print("server bin:", rs(f"install -m755 {BIN} /usr/local/bin/qeli; /usr/local/bin/qeli --version"))
    rs("systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; ip link del vpnq0 2>/dev/null; true")
    rs("mkdir -p /etc/qeli/identity /var/log/qeli")
    s.open_sftp().putfo(io.BytesIO(SERVER_CONF.encode()), CONF)
    rs(f"rm -f /var/log/qeli/server.log; nohup /usr/local/bin/qeli server --config {CONF} >/tmp/uq.log 2>&1 & echo ok")
    time.sleep(4)
    listen = rs(f"ss -lunH | grep -c ':{PORT}'")
    key = ""
    ident = rs(f"/usr/local/bin/qeli show-identity --config {CONF} 2>&1")
    m = re.search(r"[0-9a-f]{64}", ident); key = m.group(0) if m else ""
    print(f"udp :{PORT} listening: {listen} | identity pubkey: {key[:16]}…")
    boot = rs("grep -iE 'error|panic|listening' /tmp/uq.log /var/log/qeli/server.log 2>/dev/null | tail -3")
    print("server boot:", boot or "(no listen line?)")
    if not (listen.isdigit() and int(listen) >= 1) or not key:
        print("SERVER NOT UP — aborting"); rs("systemctl start qeli-server.service 2>/dev/null; true"); return

    # ── 2. Android client config (JSON for injection + qeli:// + INI to hand out) ─
    cfg = {
        "server": {"address": SRV, "port": PORT, "protocol": "udp"},
        "auth": {"username": "phone", "password": "testpass123",
                 "server_public_key": key, "bind_static_to_session": True},
        "routing": {"mode": "split-tunnel", "add_default_gateway": False},
        "obfuscation": {"mode": "fake-tls", "sni": "www.microsoft.com", "quic": {"enabled": True}},
    }
    link = f"qeli://phone:testpass123@{SRV}:{PORT}?proto=udp&mode=fake-tls&key={key}&sni=www.microsoft.com&quic=1#udp-quic-lab"

    # ── 3. install APK + inject the profile into the emulator ────────────────
    sf = cl.open_sftp(); sf.put(APK, "/root/app-debug.apk"); sf.close()
    print("\n[install]", a("install -r /root/app-debug.apk") or "(ok)")
    print("app ver:", a("shell dumpsys package com.qeli | grep versionName | head -1").strip())
    a("shell pm clear com.qeli")
    profiles = {"active": 0, "profiles": [{"name": "udp-quic LAB", "json": json.dumps(cfg)}]}
    from xml.sax.saxutils import escape
    xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
           '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
    cl.open_sftp().putfo(io.BytesIO(xml.encode()), "/root/vpn.xml")
    a("push /root/vpn.xml /data/local/tmp/vpn.xml")
    a("shell run-as com.qeli mkdir -p shared_prefs 2>/dev/null; true")
    a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")
    a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS 2>/dev/null; true")
    a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
    a("logcat -c"); a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)

    # dismiss any dialog, dump UI, tap TAP TO CONNECT
    a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true"); ui = a("shell cat /sdcard/ui.xml")
    if 'text="ALLOW"' in ui:
        for mm in re.finditer(r'text="ALLOW"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
            a(f"shell input tap {(int(mm.group(1))+int(mm.group(3)))//2} {(int(mm.group(2))+int(mm.group(4)))//2}"); time.sleep(1)
            a("shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; true"); ui = a("shell cat /sdcard/ui.xml"); break
    print("profile loaded in UI:", "udp-quic" in ui.lower())
    for mm in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
        if re.search(r"tap to connect", mm.group(1), re.I):
            a(f"shell input tap {(int(mm.group(2))+int(mm.group(4)))//2} {(int(mm.group(3))+int(mm.group(5)))//2}")
            print(f"tapped '{mm.group(1)}'"); break

    # ── 4. observe: VpnSvc Auth OK + held ────────────────────────────────────
    time.sleep(22)
    trace = a("logcat -d 2>/dev/null | grep -aE 'VpnSvc' | tail -40")
    print("\n=== VpnSvc trace ===\n" + ("\n".join(trace.splitlines()[-16:]) or "(none)"))
    n_auth = len(re.findall(r"Auth OK", trace)); n_net = len(re.findall(r"Network changed", trace))
    a("shell uiautomator dump /sdcard/ui3.xml >/dev/null 2>&1; true"); ui3 = a("shell cat /sdcard/ui3.xml")
    st = [t for t in re.findall(r'text="([^"]+)"', ui3) if t.upper() in ("CONNECTED", "DISCONNECTED", "CONNECTING")]
    print(f"\n>>> Auth OK={n_auth}  Network-changed={n_net}  UI-state={st[:2]}")
    # server side
    print("server AUTH log:", rs("grep -iE 'AUTH OK|connected|udp-quic' /var/log/qeli/server.log | tail -4"))
    a("shell am force-stop com.qeli")
    rs("pkill -9 -x qeli; systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()

    ok = n_auth >= 1
    print("\n===== RESULT:", "PASS — emulator connected to udp-quic (Auth OK)" if ok else "FAIL", "=====")
    print("\n--- SERVER config (/etc/qeli/server.conf) ---\n" + SERVER_CONF)
    print("--- CLIENT (Android JSON) ---\n" + json.dumps(cfg, indent=2))
    print("\n--- CLIENT qeli:// link (paste/scan into app) ---\n" + link)


if __name__ == "__main__":
    main()
