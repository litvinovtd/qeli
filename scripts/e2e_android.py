#!/usr/bin/env python3
"""E2E for the refactored Android client: inject TCP+UDP profiles, drive Connect
via uiautomator, verify the server logs AUTH OK on the right profile and the
tunnel carries traffic (server pings the client's assigned tunnel IP)."""
import os
import sys, io, json, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

CLI = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
SRV = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
ADB = "/root/android-sdk/platform-tools/adb"
SRVIP = "10.66.116.10"


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c

cc = conn(CLI); sc = conn(SRV)
def a(cmd, t=60):  # adb on client VM
    i, o, e = cc.exec_command(f"{ADB} {cmd}", timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=60):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()


def cfg(name, port, proto):
    return json.dumps({
        "name": name,
        "server": {"address": SRVIP, "port": port, "protocol": proto},
        "auth": {"username": "phone", "password": "testpass123"},
        "routing": {"mode": "full-tunnel", "add_default_gateway": True},
        "dns": {"servers": ["1.1.1.1"]},
        "obfuscation": {"mode": "fake-tls", "sni": "www.cloudflare.com"},
    })


def inject(active):
    profiles = {"active": active, "profiles": [
        {"name": "TCP test", "json": cfg("TCP test", 443, "tcp")},
        {"name": "UDP test", "json": cfg("UDP test", 1443, "udp")},
    ]}
    pj = json.dumps(profiles)
    xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
           '    <string name="profiles_json">' + escape(pj) + "</string>\n</map>\n")
    a("shell am force-stop com.qeli")
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); sf.close()
    a("push /root/vpn.xml /data/local/tmp/vpn.xml")
    a("shell run-as com.qeli mkdir shared_prefs")
    a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")


def _dump():
    a("shell uiautomator dump /sdcard/u.xml")
    return a("shell cat /sdcard/u.xml")

def _tap_bounds(b):
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", b)
    x = (int(m.group(1)) + int(m.group(3))) // 2
    y = (int(m.group(2)) + int(m.group(4))) // 2
    a(f"shell input tap {x} {y}")
    return f"@ {x},{y}"

def tap_id(rid):
    dump = _dump()
    m = re.search(rid + r'"[^>]*bounds="(\[[^"]*\])"', dump)
    if not m:
        m = re.search(r'bounds="(\[[^"]*\])"[^>]*' + rid + '"', dump)
    return f"tap {rid} {_tap_bounds(m.group(1))}" if m else f"NOT FOUND: {rid}"

def tap_text(text):
    dump = _dump()
    for m in re.finditer(r'(?:text|content-desc)="([^"]*)"[^>]*bounds="(\[[^"]*\])"', dump):
        if text.lower() == m.group(1).strip().lower():
            return f"tap '{text}' {_tap_bounds(m.group(2))}"
    return f"NOT FOUND: {text}"


def run(profile_label, expect_profile):
    print(f"\n===== {profile_label} =====")
    base = int(ssh("wc -l < /var/log/qeli/server_live.log") or 0)
    a("logcat -c")
    a("shell am start -n com.qeli/.MainActivity"); time.sleep(5)
    a("shell input tap 160 370"); print("tapped Connect @160,370"); time.sleep(4)
    # VPN consent dialog (only first time): tap its accept button if present
    cur = _dump()
    if "vpndialogs" in cur or "connection request" in cur.lower():
        r = tap_text("OK")
        if "NOT FOUND" in r: r = tap_text("Allow")
        print("consent:", r)
    time.sleep(9)
    cl = a("logcat -d -s VpnSvc:D | grep -iE 'Connecting|Auth OK|identity verified|TUN ready|ERR|FATAL' | tail -8")
    print("client logcat:\n" + (cl or "(none)"))
    new = ssh(f"tail -n +{base+1} /var/log/qeli/server_live.log | grep -iE 'AUTH OK|connected on profile'")
    print("server log:\n" + (new or "(no new AUTH lines)"))
    m = re.search(r"IP: (10\.9\.\d+\.\d+)", new)
    if m:
        tun = "vpn1" if expect_profile == "udp" else "vpn0"
        print(f"server->client ping {m.group(1)} via {tun}:",
              ssh(f"ping -c3 -W2 -I {tun} {m.group(1)} | tail -2"))
    a("shell am force-stop com.qeli"); time.sleep(3)


a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS")
inject(0); run("TCP", "tcp")
inject(1); run("UDP", "udp")
cc.close(); sc.close()
