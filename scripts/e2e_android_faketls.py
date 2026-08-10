#!/usr/bin/env python3
"""Android-client e2e for the fake-tls (default TCP) profile: emulator (com.qeli)
on .11 -> fake-tls server on .10 (TCP :8443). Installs the freshly-built APK,
injects a fake-tls JSON profile, drives Connect, verifies Auth OK + assigned IP +
a server->client ping through the tunnel. Leaves the canonical :443 service alone.

Pass ``--kill-switch`` to prove the Android policy binding as well: the first connect must
fail without system lockdown; after the test arms Always-on VPN + lockdown, the same profile
must produce and ACK a Rust NetworkPlan with ``kill_switch=true``. The system settings are
restored during cleanup.
"""
import os, sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko
from xml.sax.saxutils import escape

PW = os.environ.get("QELI_LAB_PASS", "")
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
ADB = "/root/android-sdk/platform-tools/adb"
QELI = "/opt/qeli-src/target/release/qeli"
APK = "/root/android-project/app/build/outputs/apk/debug/app-debug.apk"
DIR = "/root/ftls-test"
CONF = f"{DIR}/server-ftls.conf"
LOG = f"{DIR}/srv-ftls.log"
PORT = 8443
TUNIF = "ftls0"
NET = "10.62.0"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
USER, PASS = "admin", "testpass123"
if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--kill-switch"):
    raise SystemExit("usage: e2e_android_faketls.py [--kill-switch]")
KILL_SWITCH = len(sys.argv) == 2


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


sc = conn(SRV); cc = conn(CLI)
def ssh(cmd, t=60):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def csh(cmd, t=120):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def a(cmd, t=120):
    return csh(f"{ADB} {cmd}", t)
def launch_srv(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()


SERVER_CONF = f"""[auth]
require_client_key_proof = false

[logging]
level = info
file = {LOG}

[profile:ftls]
identity_key = {DIR}/id.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = {TUNIF}
tun.address = {NET}.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = {NET}.0/24
pool.exclude = {NET}.1
routing.forward_private = true
routing.nat.enabled = true
dns.enabled = true
dns.listen = {NET}.1
dns.upstream = 1.1.1.1
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
obf.padding.enabled = true

[user:{USER}]
password_hash = {HASH}
enabled = true
"""


def ui_dump():
    for _ in range(4):
        d = a("exec-out uiautomator dump /dev/tty 2>/dev/null")
        if "<hierarchy" in d or "<node" in d:
            return d
        time.sleep(1.5)
    return ""


def find_tap(labels, dump=None):
    if dump is None:
        dump = ui_dump()
    for lb in labels:
        m = re.search(r'(?:text|content-desc)="' + re.escape(lb) + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', dump, re.I)
        if m:
            x = (int(m.group(1)) + int(m.group(3))) // 2; y = (int(m.group(2)) + int(m.group(4))) // 2
            a(f"shell input tap {x} {y}"); print(f"  tapped '{lb}' @{x},{y}")
            return True
    return False


def set_system_lockdown(enabled):
    """Drive the real Android VPN settings UI; raw Settings.Secure writes do not refresh Vpn."""
    if enabled:
        # Seed list discovery only. This does NOT make VpnService.isAlwaysOn true (the negative
        # test above proves that); the preference click below is what calls the live VpnManager.
        a("shell settings put secure always_on_vpn_app com.qeli")
        a("shell settings put secure always_on_vpn_lockdown 1")
    a("shell am start -a android.settings.VPN_SETTINGS >/dev/null")
    time.sleep(2)
    dump = ui_dump()
    # ACTION_VPN_SETTINGS may be delivered to an already-open Qeli detail Activity instead
    # of recreating the list. Accept either entry state.
    if "Always-on VPN" not in dump:
        if not find_tap(["Settings"], dump):
            raise RuntimeError("Qeli VPN settings button not found")
        time.sleep(2)
        dump = ui_dump()

    def switch_states(ui):
        return [v == "true" for v in re.findall(
            r'class="android\.widget\.Switch"[^>]*checked="(true|false)"', ui
        )]

    states = switch_states(dump)
    if len(states) < 2:
        raise RuntimeError("Always-on/lockdown switches not found")
    always_on, lockdown = states[:2]
    if enabled:
        # The raw values used to make Qeli visible can make the widgets LOOK checked without
        # updating the live Vpn object. Force a real OFF -> ON cycle through the preference
        # callbacks so isAlwaysOn/isLockdownEnabled test system state, not database paint.
        if lockdown:
            if not find_tap(["Block connections without VPN"], dump):
                raise RuntimeError("Block connections without VPN row not found")
            time.sleep(2); dump = ui_dump()
        states = switch_states(dump)
        if states and states[0]:
            if not find_tap(["Always-on VPN"], dump):
                raise RuntimeError("Always-on VPN row not found")
            time.sleep(2); dump = ui_dump()
        states = switch_states(dump)
        always_on = states[0] if states else False
        if not always_on:
            if not find_tap(["Always-on VPN"], dump):
                raise RuntimeError("Always-on VPN row not found")
            time.sleep(2); dump = ui_dump()
        states = switch_states(dump)
        if len(states) < 2 or not states[1]:
            if not find_tap(["Block connections without VPN"], dump):
                raise RuntimeError("Block connections without VPN row not found")
            time.sleep(2); dump = ui_dump()
            if "Require VPN connection?" in dump:
                if not find_tap(["TURN ON"], dump):
                    raise RuntimeError("lockdown confirmation button not found")
                time.sleep(2); dump = ui_dump()
    else:
        if lockdown:
            if not find_tap(["Block connections without VPN"], dump):
                raise RuntimeError("Block connections without VPN row not found")
            time.sleep(2); dump = ui_dump()
        states = switch_states(dump)
        if states and states[0]:
            if not find_tap(["Always-on VPN"], dump):
                raise RuntimeError("Always-on VPN row not found")
            time.sleep(2); dump = ui_dump()
    final = switch_states(dump)
    if len(final) < 2 or final[0] != enabled or final[1] != enabled:
        raise RuntimeError(f"system VPN switches did not reach requested state: {final}")
    a("shell am force-stop com.android.settings")
    return final


# ── 0. install the freshly-built APK ─────────────────────────────────────────
print("=== 0. install rebuilt APK ===")
print("  ", a(f"install -r -d {APK}", t=180).strip()[-60:])
print("  installed:", a("shell dumpsys package com.qeli | grep -E 'versionName|versionCode' | head -2"))

# ── A. fake-tls server on .10 ────────────────────────────────────────────────
print("\n=== A. start fake-tls server on .10 ===")
ssh(f"mkdir -p {DIR}; pkill -9 -f 'ftls-test' 2>/dev/null; sleep 2; ip link del {TUNIF} 2>/dev/null; rm -f {LOG}; true")
ssh("sysctl -w net.ipv4.ip_forward=1 >/dev/null; true")
sf = sc.open_sftp(); sf.putfo(io.BytesIO(SERVER_CONF.encode()), CONF); sf.close()
pub = ""
for line in ssh(f"{QELI} show-identity --config {CONF} 2>&1").splitlines():
    m = re.search(r"[0-9a-f]{64}", line)
    if m: pub = m.group(0); break
print("[srv] server pubkey:", pub or "??")
launch_srv(f"RUST_LOG=info setsid nohup {QELI} server -c {CONF} >{DIR}/srv.out 2>&1 </dev/null & echo $! >{DIR}/srv.pid")
up = False
for _ in range(15):
    time.sleep(1)
    if ssh(f"ss -tlnp | grep -c ':{PORT}'").strip() not in ("", "0"):
        up = True; break
t0 = ""
for _ in range(8):
    t0 = ssh(f"ip -br a show {TUNIF} 2>/dev/null")
    if NET in t0: break
    time.sleep(1)
print("[srv] tcp :%d listening = %s | %s = %s" % (PORT, up, TUNIF, t0.strip() or "NOT-UP"))
if not up or not pub or NET not in t0:
    print(ssh(f"tail -20 {LOG} {DIR}/srv.out")); sc.close(); cc.close(); sys.exit(1)

# ── B. inject fake-tls profile + connect ─────────────────────────────────────
print("\n=== B. inject fake-tls profile + connect ===")
profile = f"""# TCP fake-TLS e2e
[qeli]
server = {SRV[0]}:{PORT}
proto = tcp
user = {USER}
pass = {PASS}
key = {pub}
mode = fake-tls
sni = www.microsoft.com
gateway = true
dns = 1.1.1.1
{"kill_switch = true" if KILL_SWITCH else ""}
"""
profiles = {"active": 0, "profiles": [{"name": "FAKE-TLS e2e", "json": profile}]}
xml = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
       '    <string name="profiles_json">' + escape(json.dumps(profiles)) + "</string>\n</map>\n")
a("shell am force-stop com.qeli")
a("shell pm clear com.qeli")
a("shell appops set com.qeli ACTIVATE_VPN allow 2>/dev/null; true")
a("shell appops set com.qeli ACTIVATE_PLATFORM_VPN allow 2>/dev/null; true")
a("shell pm grant com.qeli android.permission.POST_NOTIFICATIONS 2>/dev/null; true")
if KILL_SWITCH:
    # pm clear above removes this package's active VPN/Always-on assignment. Also clear the
    # persisted strings for an emulator image that retained them; do not open the VPN settings
    # UI yet, because Android lists Qeli there only after the first prepare/connect request.
    a("shell settings put secure always_on_vpn_lockdown 0")
    a("shell settings delete secure always_on_vpn_app")
    a("shell am force-stop com.android.settings")
cf = cc.open_sftp(); cf.putfo(io.BytesIO(xml.encode()), "/root/vpn.xml"); cf.close()
a("push /root/vpn.xml /data/local/tmp/vpn.xml")
a("shell run-as com.qeli mkdir shared_prefs 2>/dev/null; true")
a("shell run-as com.qeli cp /data/local/tmp/vpn.xml shared_prefs/vpn.xml")

base = int(ssh(f"wc -l < {LOG}") or 0)
a("logcat -c")
a("shell am start -n com.qeli/.MainActivity"); time.sleep(7)
scr = ui_dump()
print("  [profile on screen]:", "FAKE-TLS e2e" in scr,
      "| [Connect present]:", bool(re.search(r'(?:text|content-desc)="(?:Connect|Подключить)', scr, re.I)))
if not find_tap(["Connect", "Подключить", "Подключиться", "CONNECT", "Tap to connect"], scr):
    print("  Connect not found -> fixed tap @160,260"); a("shell input tap 160 260")

kill_switch_refused = not KILL_SWITCH
kill_switch_armed = not KILL_SWITCH
if KILL_SWITCH:
    time.sleep(3)
    rejected_log = a(
        "logcat -d | grep -iE 'Refusing unprotected kill-switch|SECURITY:.*Kill switch' | tail -8"
    )
    kill_switch_refused = "Refusing unprotected kill-switch connection" in rejected_log
    print("  [kill-switch without lockdown]:", "REFUSED" if kill_switch_refused else "NOT REFUSED")
    if rejected_log:
        print(rejected_log)

    # Use the same system UI a user does. Directly writing Settings.Secure changes the stored
    # strings but does not update the live per-user Vpn object, so isAlwaysOn correctly remains
    # false; that shortcut would test the database, not the kill switch.
    set_system_lockdown(True)
    state = a(
        "shell 'printf app=; settings get secure always_on_vpn_app; "
        "printf lockdown=; settings get secure always_on_vpn_lockdown'"
    )
    print("  [system policy armed]:", state.replace("\n", " "))
    a("logcat -c")
    # This test deliberately began with a live foreground error-service. Android keeps the
    # pre-policy VpnService instance's always-on/lockdown snapshot stale, so exercise the
    # guarantee that matters: kill the app and let the OS restart it under lockdown. A normal
    # user enables these switches while Qeli is stopped and enters this fresh-instance path
    # directly; the forced process death also proves protection survives a crash.
    pid = a("shell pidof com.qeli").strip()
    if pid:
        print("  [crash simulation]: killing pre-policy Qeli process", pid)
        a(f"shell kill -9 {pid}")
    time.sleep(7)
    armed_log = a("logcat -d | grep -iE 'kill switch active|Always-on VPN start' | tail -8")
    if "kill switch active" not in armed_log.lower():
        print("  system did not redeliver promptly -> return to Qeli and retry Connect")
        a("shell am start -n com.qeli/.MainActivity >/dev/null")
        time.sleep(3)
        retry = ui_dump()
        if not find_tap(["Tap to retry", "Connect", "Подключить", "Подключиться"], retry):
            print("  retry control not found -> fixed Qeli coordinate @160,260")
            a("shell input tap 160 260")

# A freshly-installed emulator occasionally consumes the first accessibility-driven tap
# while the activity is still settling.  Do not wait 36 seconds and report a transport
# failure when the VPN service never started: check the service itself (not another
# uiautomator dump, which can crash accessibility), then retry the stable button coordinate.
time.sleep(2)
service_dump = a("shell dumpsys activity services com.qeli 2>/dev/null")
if "VpnServiceImpl" not in service_dump:
    print("  VPN service did not start after the first tap -> retry @160,260")
    a("shell input tap 160 260")

authok = False; cip = None
for i in range(18):
    time.sleep(2)
    new = ssh(f"tail -n +{base+1} {LOG}")
    if not authok and "AUTH OK" in new:
        authok = True; print(f"  [srv] AUTH OK (~{2*(i+1)}s)")
    m = re.search(r"(%s\.\d+)" % NET.replace('.', r'\.'), new)
    if m and not m.group(1).endswith(".1"):
        cip = m.group(1); break

# ── C. verify ────────────────────────────────────────────────────────────────
print("\n=== C. verify ===")
lc = a("logcat -d | grep -iE 'VpnSvc|Auth OK|assigned|Established|error|exception' | tail -14")
print("client logcat:\n" + (lc or "(none)"))
if KILL_SWITCH:
    # Keep the security evidence independent of the short diagnostic tail above. A normal
    # authenticated plan emits enough pushed-parameter lines to move the early "active" line
    # outside that window even though the guarded plan was successfully ACKed.
    security_log = a(
        "logcat -d | grep -iE 'kill switch active|kill_switch=true|Native NetworkPlan.*APPLIED' | tail -20"
    )
    security_lower = security_log.lower()
    kill_switch_armed = (
        "kill switch active" in security_lower and
        "kill_switch=true" in security_lower and
        "native networkplan" in security_lower and
        "applied" in security_lower
    )
    print("kill-switch evidence:\n" + (security_log or "(none)"))
    print("  [kill-switch with lockdown]:", "ACKED" if kill_switch_armed else "NOT ACKED")
new = ssh(f"tail -n +{base+1} {LOG}")
print("server log (new, tail):\n" + ("\n".join(new.splitlines()[-8:]) or "(empty)"))
cip = cip or f"{NET}.2"
print(f"\n[ping] server -> client {cip} via {TUNIF}:")
ping = ssh(f"ping -c4 -W2 -I {TUNIF} {cip} 2>&1 | tail -4")
print(ping)
mrx = re.search(r"(\d+) received", ping)
passed = (
    authok and bool(mrx) and int(mrx.group(1)) > 0 and
    kill_switch_refused and kill_switch_armed
)

# ── D. cleanup ───────────────────────────────────────────────────────────────
print("\n=== D. cleanup ===")
if KILL_SWITCH:
    set_system_lockdown(False)
a("shell am force-stop com.qeli")
pid = ssh(f"cat {DIR}/srv.pid 2>/dev/null").strip()
if pid: ssh(f"kill -9 {pid} 2>/dev/null; true")
ssh(f"pkill -9 -f '{CONF}' 2>/dev/null; ip link del {TUNIF} 2>/dev/null; true")
sc.close(); cc.close()
label = "PASS (fake-tls tunnel up, ping OK"
if KILL_SWITCH:
    label += ", kill-switch fail-closed + ACK verified"
label += ")"
print("\n================ RESULT:", label if passed else "SEE LOGS ABOVE", "================")
sys.exit(0 if passed else 1)
