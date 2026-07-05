#!/usr/bin/env python3
"""Capture the obfs client->server bytes of BOTH clients connecting to PROD :243:
  - the Rust CLI 0.7.6 (works → reference), captured on the .11 host
  - the 0.7.6 Android app (fails), captured INSIDE the emulator (/system/bin/tcpdump)
Pulls both pcaps locally for a byte-level WS-frame diff (junk + nonce + first data).
"""
import os, io, time, paramiko
PW = os.environ.get("QELI_LAB_PASS", "")
PROD = "YOUR_PROD_HOST"
DL = r"C:\Users\litvi\AppData\Local\Temp\claude\C--Users-litvi-Documents-api-dev-autocash-ru\f0a9a9ed-a799-4cc9-beaa-51baa0d8cfce\scratchpad"
ADB = "/root/android-sdk/platform-tools/adb"


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("10.66.116.11", username="root", password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


c = conn()
def r(cmd, t=60):
    _i, o, e = c.exec_command(cmd, timeout=t); return (o.read() + e.read()).decode("utf-8", "replace").strip()
def a(cmd, t=60):
    return r(f"{ADB} {cmd}", t)


# ── 1. RUST CLI capture (host .11) ─────────────────────────────────────────────
conf = f"""[qeli]
server = {PROD}:243
proto = tcp
user = user08
pass = aoV6bCeVRnNM4v1k
key = 010045e56dc5dad8d54b5b8e4a9792ed4e12cf33f80421d45c0d0d48dda9260b
mode = obfs
obfs_key = cf61795367f10bdf59b075c32c9cf92d
front = websocket
awg = true
jc = 4
jmin = 40
jmax = 200
dev = vpn9
[logging]
level = info
"""
c.open_sftp().putfo(io.BytesIO(conf.encode()), "/tmp/rustawg.conf")
r("pkill -9 -f rustawg 2>/dev/null; pkill -9 tcpdump 2>/dev/null; ip link del vpn9 2>/dev/null; rm -f /tmp/rust.pcap /tmp/rustawg.log /var/lib/qeli/known_hosts; true")
egress = r(f"ip route get {PROD} | grep -oE 'dev [a-z0-9]+' | awk '{{print $2}}' | head -1") or "any"
r(f"nohup tcpdump -i {egress} -s0 -w /tmp/rust.pcap 'host {PROD} and tcp port 243' >/dev/null 2>&1 & echo $! >/tmp/tcpd.pid")
time.sleep(1)
r("nohup /usr/local/bin/qeli client --config /tmp/rustawg.conf >/tmp/rustawg.log 2>&1 & echo ok")
time.sleep(5)
print("[rust] Auth OK:", "Auth OK" in r("grep -F 'Auth OK' /tmp/rustawg.log || true"))
r("pkill -9 -f rustawg 2>/dev/null; sleep 1; kill $(cat /tmp/tcpd.pid) 2>/dev/null; sleep 1; ip link del vpn9 2>/dev/null; true")
print("[rust] pcap:", r("ls -la /tmp/rust.pcap 2>/dev/null | awk '{print $5\" bytes\"}'"))

# ── 2. ANDROID capture (inside emulator) ───────────────────────────────────────
a("root", 30); time.sleep(2)
a("shell pkill tcpdump 2>/dev/null; true")
a("shell rm -f /data/local/tmp/and.pcap 2>/dev/null; true")
_i, o, _e = c.exec_command(f"{ADB} shell tcpdump -i any -s0 -w /data/local/tmp/and.pcap 'tcp port 243' >/dev/null 2>&1 &")
time.sleep(2)
a("shell am start -n com.qeli/.MainActivity"); time.sleep(3)
a("shell input tap 60 128"); time.sleep(1)                     # Connection tab
a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
a("shell input tap 160 260"); time.sleep(7)                    # Connect
a("shell pkill tcpdump 2>/dev/null; true"); time.sleep(1)
a("shell am force-stop com.qeli")
a("pull /data/local/tmp/and.pcap /tmp/and.pcap", 30)
print("[android] pcap:", r("ls -la /tmp/and.pcap 2>/dev/null | awk '{print $5\" bytes\"}'"))

# ── 3. pull both pcaps local ───────────────────────────────────────────────────
sf = c.open_sftp()
for name in ("rust.pcap", "and.pcap"):
    try: sf.get(f"/tmp/{name}", os.path.join(DL, name)); print("saved", name)
    except Exception as ex: print("pull fail", name, ex)
sf.close(); c.close()
print("[done]")
