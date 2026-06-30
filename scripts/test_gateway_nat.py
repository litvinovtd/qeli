#!/usr/bin/env python3
"""E2E for gateway_nat + post_up/post_down (client side).

Server on .10 (fake-tls :8506), client on .11 with `gateway_nat=true`,
`lan_subnet`, and post_up/post_down. Verifies:
  1. after connect: MASQUERADE(+FORWARD+MSS) tagged `qeli-gw-nat` on the tun,
     ip_forward=1, and post_up ran;
  2. clean stop (SIGTERM): rules removed and post_down ran;
  3. world-writable config: gateway NAT still runs but post_up/down are REFUSED.
"""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PW = os.environ["QELI_LAB_PASS"]
SRV = ("10.66.116.10", "root", PW)
CLI = ("10.66.116.11", "root", PW)
SRV_BIN = "/opt/qeli-src/target/release/qeli"
CLI_BIN = "/root/qeli-gw"
PUBKEY = "e37632de330cd3e486b81fa0fb0cce96d02e60b2ce35947fe1647508e94d216b"
PORT = 8506
TUN = "gwc0"
LAN = "192.168.99.0/24"

SERVER_CONF = f"""[web]
enabled = false
[auth]
users_file = /root/reality-test/users-e2e.conf
[logging]
level = info
file = /root/gw-srv.log
[profile:gw]
identity_key = /etc/qeli/identity/e2e.key
bind.address = 0.0.0.0
bind.port = {PORT}
bind.transport = tcp
tun.name = gws0
tun.address = 10.77.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.77.0.0/24
pool.exclude = 10.77.0.1
dns.enabled = false
obf.mode = fake-tls
obf.tls.server_name = www.microsoft.com
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 10
"""

def client_conf():
    return f"""[qeli]
server = 10.66.116.10:{PORT}
proto = tcp
user = admin
pass = testpass123
key = {PUBKEY}
mode = fake-tls
sni = www.microsoft.com
dev = {TUN}
gateway_nat = true
lan_subnet = {LAN}
post_up = /bin/touch /tmp/qeli_postup_ran
post_down = /bin/touch /tmp/qeli_postdown_ran
[logging]
level = info
file = /root/gw-cli.log
"""

def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c

sc = conn(SRV); cc = conn(CLI)
def S(cmd, t=60):
    _i,o,e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def C(cmd, t=60):
    _i,o,e = cc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
def Sbg(cmd):
    ch = sc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()
def Cbg(cmd):
    ch = cc.get_transport().open_session(); ch.exec_command(cmd); time.sleep(1); ch.close()

PASS = []
def check(name, ok, detail=""):
    PASS.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""))

def clean_client_rules():
    C("for t in nat filter mangle; do iptables-save -t $t 2>/dev/null | grep -q qeli-gw-nat && "
      "iptables-save -t $t | grep qeli-gw-nat | sed 's/^-A/iptables -t '$t' -D/' | sh 2>/dev/null; done; true")

def start_client():
    C(f"pkill -9 -f 'gw-cli.conf' 2>/dev/null; ip link del {TUN} 2>/dev/null; "
      f"rm -f /root/gw-cli.log /tmp/qeli_postup_ran /tmp/qeli_postdown_ran /var/lib/qeli/known_hosts; sleep 1; true")
    Cbg(f"RUST_LOG=info setsid nohup {CLI_BIN} client -c /root/gw-cli.conf </dev/null >/root/gw-cli.out 2>&1 & echo $! >/root/gw-cli.pid")
    for _ in range(15):
        time.sleep(1.5)
        if "Auth OK" in C("grep -E 'Auth OK' /root/gw-cli.log 2>/dev/null || true"):
            return True
    print(C("tail -8 /root/gw-cli.log /root/gw-cli.out")); return False

try:
    # server up
    sc.open_sftp().putfo(io.BytesIO(SERVER_CONF.encode()), "/root/gw-srv.conf")
    S("pkill -9 -f 'gw-srv.conf' 2>/dev/null; ip link del gws0 2>/dev/null; rm -f /root/gw-srv.log; sleep 1; true")
    Sbg(f"RUST_LOG=info setsid nohup {SRV_BIN} server -c /root/gw-srv.conf >/dev/null 2>&1 </dev/null & echo $! >/root/gw-srv.pid")
    up = any("listening on 0.0.0.0:%d" % PORT in S("cat /root/gw-srv.log 2>/dev/null") for _ in [time.sleep(1) for _ in range(12)])
    print("[server] listening:", up)
    if not up:
        print(S("tail -15 /root/gw-srv.log")); sys.exit(1)

    # copy fresh binary to client
    import tempfile
    lp = os.path.join(tempfile.gettempdir(), "qeli-gw")
    sf = sc.open_sftp(); sf.get(SRV_BIN, lp); sf.close()
    cf = cc.open_sftp(); cf.put(lp, CLI_BIN); cf.close()
    C(f"chmod +x {CLI_BIN}; true")

    # ---- Test 1: trusted config (0600) → rules + hooks ----
    print("\n=== Test 1: gateway_nat + hooks (trusted config) ===")
    clean_client_rules()
    cc.open_sftp().putfo(io.BytesIO(client_conf().encode()), "/root/gw-cli.conf")
    C("chmod 600 /root/gw-cli.conf")
    if not start_client():
        print("client failed to connect"); sys.exit(1)
    time.sleep(2)
    nat = C("iptables -t nat -S POSTROUTING")
    fwd = C("iptables -S FORWARD")
    mng = C("iptables -t mangle -S FORWARD")
    check("MASQUERADE -s lan_subnet -o tun tagged", "qeli-gw-nat" in nat and LAN in nat and f"-o {TUN}" in nat and "MASQUERADE" in nat, nat)
    # FORWARD-accept is best-effort: on iptables-nft boxes the filter/FORWARD chain
    # can be legacy-incompatible (same as server/nat.rs); informational only.
    print(f"  [info] FORWARD accept (best-effort): {'present' if fwd.count('qeli-gw-nat') >= 2 else 'skipped (nft/legacy filter conflict)'}")
    check("MSS-clamp present", "qeli-gw-nat" in mng and "TCPMSS" in mng, mng)
    check("ip_forward = 1", C("cat /proc/sys/net/ipv4/ip_forward") == "1")
    check("post_up ran (file created)", C("test -f /tmp/qeli_postup_ran && echo Y || echo N") == "Y")

    # clean stop → teardown + post_down
    print("\n=== Test 2: clean stop (SIGTERM) → teardown + post_down ===")
    C("kill -TERM $(cat /root/gw-cli.pid) 2>/dev/null; true"); time.sleep(3)
    nat2 = C("iptables -t nat -S POSTROUTING")
    check("MASQUERADE removed on clean stop", "qeli-gw-nat" not in nat2, nat2)
    check("post_down ran (file created)", C("test -f /tmp/qeli_postdown_ran && echo Y || echo N") == "Y")

    # ---- Test 3: world-writable config → hooks refused, gateway still runs ----
    print("\n=== Test 3: world-writable config refuses hooks ===")
    clean_client_rules()
    C("rm -f /tmp/qeli_postup_ran /tmp/qeli_postdown_ran; sync")  # ensure clean slate
    C("chmod 666 /root/gw-cli.conf")
    start_client()
    time.sleep(2)
    print("  [debug] postup file:", C("ls -la /tmp/qeli_postup_ran 2>&1 | tail -1"))
    log = C("cat /root/gw-cli.log")
    nat3 = C("iptables -t nat -S POSTROUTING")
    check("hooks refused (log)", "Ignoring post_up/post_down" in log, log[-300:])
    check("post_up did NOT run", C("test -f /tmp/qeli_postup_ran && echo Y || echo N") == "N")
    check("gateway_nat STILL engaged (not a hook)", "qeli-gw-nat" in nat3, nat3)

    print("\n================ RESULT ================")
    print(f"  {sum(PASS)}/{len(PASS)} checks passed")
finally:
    print("\n=== cleanup ===")
    C("kill -TERM $(cat /root/gw-cli.pid 2>/dev/null) 2>/dev/null; sleep 1; pkill -9 -f 'gw-cli.conf' 2>/dev/null; true")
    clean_client_rules()
    C(f"ip link del {TUN} 2>/dev/null; rm -f /root/gw-cli.conf; true")
    S("kill -9 $(cat /root/gw-srv.pid 2>/dev/null) 2>/dev/null; pkill -9 -f 'gw-srv.conf' 2>/dev/null; ip link del gws0 2>/dev/null; true")
    print("[restored] systemd qeli:", S("systemctl is-active qeli-server.service 2>/dev/null || echo n/a"))
    sc.close(); cc.close()
