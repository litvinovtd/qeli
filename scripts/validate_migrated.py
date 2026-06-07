#!/usr/bin/env python3
"""Validate the migrated INI on the lab: load it with the NEW binary and dump
the parsed config via /api/config to confirm every stealth field survived the
TOML->INI migration. Uses a port/tun-modified copy so it can't clash with the
running lab server."""
import os
import paramiko, io, time, json

LAB = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
BIN = "/opt/qeli-src/target/debug/qeli"
LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\prod-maxobf-migrated.conf"

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(LAB[0], username=LAB[1], password=LAB[2], timeout=20, look_for_keys=False, allow_agent=False)
def sh(cmd, t=40):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def launch(cmd):
    ch = c.get_transport().open_session(); ch.exec_command(cmd); time.sleep(2); ch.close()

# upload real migrated config
sf = c.open_sftp(); sf.put(LOCAL, "/tmp/maxobf-migrated.conf")
# make a validation copy: free port/tun/pool + temp identity + web on 18099
orig = open(LOCAL, encoding="utf-8").read()
val = (orig
       .replace("bind.port = 443", "bind.port = 8443")
       .replace("tun.name = vpn0", "tun.name = vpnval")
       .replace("tun.address = 10.9.0.1", "tun.address = 10.99.0.1")
       .replace("pool.cidr = 10.9.0.0/24", "pool.cidr = 10.99.0.0/24")
       .replace("pool.exclude = 10.9.0.1", "pool.exclude = 10.99.0.1")
       .replace("identity_key = /etc/qeli/identity/maxobf.key", "identity_key = /tmp/val-maxobf.key")
       .replace("routing.nat.enabled = true", "routing.nat.enabled = false")
       .replace("[logging]", "[web]\nenabled = true\nbind = 127.0.0.1\nport = 18099\n\n[logging]"))
sf.putfo(io.BytesIO(val.encode()), "/tmp/maxobf-val.conf"); sf.close()

# 1. structural parse via show-identity (uses the REAL migrated.conf)
print("=== show-identity (real migrated.conf) ===")
print(sh(f"{BIN} show-identity --config /tmp/maxobf-migrated.conf 2>&1"))

# 2. start the validation copy, dump /api/config
sh("pkill -9 -f 'maxobf-val.conf'; sleep 1; true")
launch(f"cd /tmp && RUST_LOG=warn setsid nohup {BIN} server -c /tmp/maxobf-val.conf "
       f"> /tmp/val.log 2>&1 < /dev/null &")
time.sleep(4)
print("\n=== startup log ===")
print(sh("grep -iE 'listening|error|panic|profile' /tmp/val.log | head"))
cfg = sh("curl -s -m 6 http://127.0.0.1:18099/api/config")
sh("pkill -9 -f 'maxobf-val.conf'; ip link del vpnval 2>/dev/null; true")

print("\n=== parsed config assertions ===")
try:
    d = json.loads(cfg)["config"]
    p = d["profiles"][0]
    obf = p["obfuscation"]
    checks = {
        "profile name": (p["name"], "maxobf"),
        "bind transport": (p["bind"]["transport"], "tcp"),
        "require_client_key_proof": (d["auth"]["require_client_key_proof"], True),
        "obf.mode": (obf["mode"], "fake-tls"),
        "tls.server_name": (obf["tls"]["server_name"], "www.microsoft.com"),
        "reality.enabled": (obf["tls"]["reality_proxy"]["enabled"], True),
        "reality.target": (obf["tls"]["reality_proxy"]["target"], "www.microsoft.com"),
        "padding.min": (obf["padding"]["min_bytes"], 40),
        "padding.max": (obf["padding"]["max_bytes"], 400),
        "heartbeat.interval": (obf["heartbeat"]["interval_ms"], 15000),
        "anti_fp.enabled": (obf["anti_fingerprinting"]["enabled"], True),
        "max_clients": (p["performance"]["connection"]["max_clients"], 64),
        "idle_timeout": (p["performance"]["connection"]["idle_timeout_secs"], 0),
        "users count": (len(d["auth"]["users"]), 6),
    }
    ok = True
    for name, (got, want) in checks.items():
        good = got == want
        ok = ok and good
        print(f"  [{'OK' if good else 'XX'}] {name}: {got}" + ("" if good else f" (expected {want})"))
    print("\nUSERS:", [u["username"] for u in d["auth"]["users"]])
    print("\n=> MIGRATION", "VALID" if ok else "HAS MISMATCHES")
except Exception as ex:
    print("could not parse /api/config:", ex, "\nraw:", cfg[:400])
c.close()
