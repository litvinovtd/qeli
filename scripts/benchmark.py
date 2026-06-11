"""Comprehensive qeli load test across every wire mode (flat-INI configs).

Run from the local machine (paramiko) against the 2-VM lab:
    SERVER 10.66.116.10   CLIENT 10.66.116.11
Produces release/benchmark_results.json and prints a summary.

Per mode: bring up a dedicated tunnel, ping (latency/jitter/loss), then TCP
throughput up+down (iperf3, retransmits + iperf CPU + sampled qeli process
%CPU/RSS), or for UDP a bitrate sweep measuring loss.

Modes include the no-obfuscation `plain` (raw) tunnel and real-TLS `reality-tls`.
"""
import os
import sys, io, os, json, time, socket, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

# Lab test-VM creds — override via env (QELI_LAB_SERVER / QELI_LAB_CLIENT /
# QELI_LAB_PASS) before publishing this repo. Defaults are throwaway lab VMs.
_PW = os.environ.get("QELI_LAB_PASS", "")
SERVER = (os.environ.get("QELI_LAB_SERVER", "10.66.116.10"), "root", _PW)
CLIENT = (os.environ.get("QELI_LAB_CLIENT", "10.66.116.11"), "root", _PW)
BIN = "/usr/local/bin/qeli"
SRC_BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"
PASS = "testpass123"

def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c

def out(c, cmd, t=120):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

def put(c, path, text):
    sf = c.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()

def up(ip):
    try:
        s = socket.create_connection((ip, 22), timeout=4); s.close(); return True
    except Exception:
        return False

def wait_up():
    for _ in range(30):
        if up(SERVER[0]) and up(CLIENT[0]):
            time.sleep(2); return True
        time.sleep(5)
    return False

# ── config builders (flat-INI) ──────────────────────────────────────────────
def server_ini(m):
    udp = m["transport"] == "udp"
    net = "10.10.0" if udp else "10.9.0"
    lines = [
        "[auth]",
        f"require_client_key_proof = {str(m.get('require_proof', False)).lower()}",
        "",
        "[logging]",
        "level = info",
        "file = /var/log/qeli/server.log",
        "",
        "[profile:bench]",
        "identity_key = /etc/qeli/identity/bench.key",
        "bind.address = 0.0.0.0",
        f"bind.port = {m['port']}",
        f"bind.transport = {m['transport']}",
        f"tun.name = {'vpn1' if udp else 'vpn0'}",
        f"tun.address = {net}.1",
        "tun.netmask = 255.255.255.0",
        "tun.mtu = 1400",
        "tun.device_type = tun",
        f"pool.cidr = {net}.0/24",
        f"pool.exclude = {net}.1",
        "routing.forward_private = true",
        "routing.nat.enabled = false",
        "dns.enabled = false",
        f"obf.mode = {m['server_mode']}",
        "obf.tls.server_name = www.cloudflare.com",
        f"obf.tls.reality_proxy.enabled = {str(m.get('reality', False)).lower()}",
        "obf.tls.reality_proxy.target = www.cloudflare.com",
        "obf.tls.reality_proxy.target_port = 443",
        f"obf.tls.reality_proxy.real_tls = {str(m.get('real_tls', False)).lower()}",
    ]
    if m.get("short_id"):
        lines.append(f"obf.tls.reality_proxy.short_ids = {m['short_id']}")
    if m.get("obfs_key"):
        lines.append(f"obf.obfs_key = {m['obfs_key']}")
    lines += [
        f"obf.padding.enabled = {str(m.get('padding', False)).lower()}",
        "obf.padding.min_bytes = 32",
        "obf.padding.max_bytes = 256",
        "obf.padding.randomize = true",
        "obf.padding.probability = 0.8",
        f"obf.fragmentation.enabled = {str(m.get('frag', False)).lower()}",
        "obf.heartbeat.enabled = true",
        "obf.heartbeat.interval_ms = 15000",
        f"obf.quic.enabled = {str(m.get('quic', False)).lower()}",
        "perf.tcp.nodelay = true",
        "perf.tcp.keepalive_secs = 60",
        "perf.tun.read_buffer_size = 65535",
        "perf.connection.max_clients = 128",
        "perf.connection.handshake_timeout_secs = 10",
        "perf.connection.idle_timeout_secs = 0",
        "",
        "[user:bench]",
        f"password_hash = {HASH}",
        "enabled = true",
    ]
    return "\n".join(lines) + "\n"

def client_ini(m, server_key):
    lines = [
        "[qeli]",
        f"server = {SERVER[0]}:{m['port']}",
        f"proto = {m['transport']}",
        "user = bench",
        f"pass = {PASS}",
        f"mode = {m['client_mode']}",
    ]
    if m.get("require_proof") or m["client_mode"] == "reality-tls" or m.get("reality"):
        lines.append(f"key = {server_key}")
    if m.get("short_id"):
        # 0.7.0 requires reality_proxy short_ids; both fake-tls and reality-tls
        # clients seal the REALITY short_id into the (browser-like) ClientHello
        # session_id (client/mod.rs), so the server recognises us via the sid,
        # not the retired ALPN-absence heuristic.
        lines.append(f"reality_sid = {m['short_id']}")
    if m["client_mode"] == "reality-tls" or m.get("reality"):
        lines.append("sni = www.cloudflare.com")
    if m.get("obfs_key"):
        lines.append(f"obfs_key = {m['obfs_key']}")
    if m.get("quic"):
        lines.append("quic = true")
    lines += ["", "[logging]", "level = info"]
    return "\n".join(lines) + "\n"

def identity_pubkey(s):
    o = out(s, f"{BIN} show-identity --config /etc/qeli/bench-server.conf 2>&1")
    m = re.search(r"[0-9a-f]{64}", o)
    return m.group(0) if m else ""

# ── measurement ──────────────────────────────────────────────────────────--
def iperf_tcp(cl, sip, reverse):
    # Remote `timeout 40` hard-kills a wedged iperf3 (e.g. a stalled reverse
    # stream) so a single flap can't hang the SSH read and abort the whole sweep;
    # SSH read timeout (t=55) is the backstop above it.
    flag = "-R" if reverse else ""
    o = ""
    try:
        o = out(cl, f"timeout 40 iperf3 -c {sip} -t 12 -i 0 {flag} --json", t=55)
        j = json.loads(o); e = j["end"]
        return {"mbps": round(e["sum_received"]["bits_per_second"] / 1e6, 1),
                "retransmits": e["sum_sent"].get("retransmits"),
                "cpu_client": round(e["cpu_utilization_percent"]["host_total"], 1),
                "cpu_server": round(e["cpu_utilization_percent"]["remote_total"], 1)}
    except Exception as ex:
        return {"error": str(ex), "raw": o[:200]}

def iperf_udp_sweep(cl, sip, rates):
    res = {}
    for b in rates:
        o = ""
        try:
            o = out(cl, f"timeout 15 iperf3 -c {sip} -u -b {b}M -l 1200 -t 5 -i 0 --json", t=30)
            su = json.loads(o)["end"]["sum"]
            res[f"{b}M"] = {"mbps": round(su["bits_per_second"] / 1e6, 1),
                            "loss_pct": round(su.get("lost_percent", 0), 2)}
        except Exception as ex:
            res[f"{b}M"] = {"error": str(ex), "raw": o[:120]}
    return res

def start_qeli_sampler(c, tag):
    # Sample the busiest qeli process (the data-plane worker) every 2s for ~12s.
    out(c, f"rm -f /tmp/{tag}.smp; nohup sh -c 'for i in $(seq 1 6); do "
           f"ps --no-headers -o %cpu,rss -C qeli | sort -rn | head -1; sleep 2; done' "
           f">/tmp/{tag}.smp 2>&1 & echo ok")

def read_qeli_sampler(c, tag):
    raw = out(c, f"cat /tmp/{tag}.smp 2>/dev/null || true")
    cpus, rss = [], []
    for line in raw.splitlines():
        p = line.split()
        if len(p) >= 2:
            try:
                cpus.append(float(p[0])); rss.append(int(p[1]))
            except ValueError:
                pass
    if not cpus:
        return {}
    return {"qeli_cpu_avg_pct": round(sum(cpus) / len(cpus), 1),
            "qeli_cpu_max_pct": max(cpus),
            "qeli_rss_mb": round(max(rss) / 1024, 1)}

def run_mode(s, cl, m):
    udp = m["transport"] == "udp"
    sip = "10.10.0.1" if udp else "10.9.0.1"
    print(f"\n##### MODE: {m['name']} ({m['transport']}, client_mode={m['client_mode']}) #####")
    out(s, "pkill -9 -x qeli; sleep 1; true")
    # 0.7.0 made TOFU server-key pins persistent on disk (/var/lib/qeli/known_hosts).
    # Each bench mode is a fresh independent tunnel, so clear the pin store first —
    # otherwise a stale :443 pin from a prior run rejects this run's bench identity.
    out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; rm -f /var/lib/qeli/known_hosts; sleep 1; true")
    put(s, "/etc/qeli/bench-server.conf", server_ini(m))
    server_key = identity_pubkey(s) if (m.get("require_proof") or m["client_mode"] == "reality-tls" or m.get("reality")) else ""
    put(cl, "/etc/qeli/bench-client.conf", client_ini(m, server_key))
    out(s, f"rm -f /var/log/qeli/server.log; nohup {BIN} server --config /etc/qeli/bench-server.conf >/tmp/qs.log 2>&1 & echo ok")
    time.sleep(3)
    out(cl, f"rm -f /tmp/qc.log; nohup {BIN} client --config /etc/qeli/bench-client.conf >/tmp/qc.log 2>&1 & echo ok")
    # Poll for Auth OK (reality* server start + the client's 4s reconnect backoff can
    # push success past a single fixed wait) instead of one sleep(5)+check.
    ok = False
    for _ in range(10):
        time.sleep(1.5)
        if "Auth OK" in out(cl, "grep -E 'Auth OK' /tmp/qc.log || true"):
            ok = True; break
    if not ok:
        print("  CONNECT FAILED:", out(cl, "tail -n 4 /tmp/qc.log"), "||SRV||", out(s, "tail -n 8 /tmp/qs.log /var/log/qeli/server.log"))
        out(s, "pkill -9 -x qeli"); out(cl, "pkill -9 -x qeli")
        return {"error": "connect failed", "client_mode": m["client_mode"]}
    ping = out(cl, f"ping -c 20 -i 0.2 -q {sip}")
    rtt = next((l for l in ping.splitlines() if "rtt" in l or "min/avg" in l), "")
    loss = next((l for l in ping.splitlines() if "packet loss" in l), "")
    out(s, f"pkill -9 iperf3; sleep 1; nohup iperf3 -s -B {sip} >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    r = {"client_mode": m["client_mode"], "server_mode": m["server_mode"],
         "ping_rtt": rtt.strip(),
         "ping_loss": loss.split(",")[2].strip() if "," in loss else loss.strip()}
    if udp:
        r["udp_sweep"] = iperf_udp_sweep(cl, sip, [100, 200, 300, 400, 500])
    else:
        start_qeli_sampler(s, "up")
        r["tcp_up"] = iperf_tcp(cl, sip, False)
        r["tcp_up"].update(read_qeli_sampler(s, "up"))
        r["tcp_down"] = iperf_tcp(cl, sip, True)
    out(s, "pkill -9 iperf3; true")
    out(cl, "pkill -9 -x qeli; sleep 1; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null")
    out(s, "pkill -9 -x qeli")
    print("  ", json.dumps(r, ensure_ascii=False))
    return r

MODES = [
    {"name": "tcp-plain-raw",  "transport": "tcp", "port": 443,  "client_mode": "plain",       "server_mode": "plain"},
    {"name": "tcp-faketls",    "transport": "tcp", "port": 443,  "client_mode": "fake-tls",    "server_mode": "fake-tls"},
    {"name": "tcp-padding",    "transport": "tcp", "port": 443,  "client_mode": "fake-tls",    "server_mode": "fake-tls", "padding": True},
    {"name": "tcp-frag",       "transport": "tcp", "port": 443,  "client_mode": "fake-tls",    "server_mode": "fake-tls", "padding": True, "frag": True},
    {"name": "tcp-obfs",       "transport": "tcp", "port": 443,  "client_mode": "obfs",        "server_mode": "obfs", "obfs_key": "benchkey", "padding": True},
    {"name": "tcp-reality",    "transport": "tcp", "port": 443,  "client_mode": "fake-tls",    "server_mode": "fake-tls", "reality": True, "short_id": "0123456789abcdef"},
    {"name": "tcp-reality-tls","transport": "tcp", "port": 443,  "client_mode": "reality-tls", "server_mode": "fake-tls", "reality": True, "real_tls": True, "short_id": "0123456789abcdef", "require_proof": True},
    # NB: there is no `udp-plain-raw` row. The `plain` (raw) wire mode is TCP-only
    # by design — see server/mod.rs (`plain (raw) wire mode is TCP-only`). On UDP a
    # raw datagram stream is high-entropy with no structure, i.e. the exact
    # "fully encrypted traffic" signature DPI (GFW/TSPU) flags — so it would hurt
    # censorship resistance with zero throughput gain (the AEAD, not the 5-byte
    # fake-TLS header, is the bottleneck). The UDP baseline below is fake-tls.
    {"name": "udp-faketls",    "transport": "udp", "port": 4443, "client_mode": "fake-tls",    "server_mode": "fake-tls"},
    {"name": "udp-padding",    "transport": "udp", "port": 4443, "client_mode": "fake-tls",    "server_mode": "fake-tls", "padding": True},
    {"name": "udp-quic",       "transport": "udp", "port": 4443, "client_mode": "fake-tls",    "server_mode": "fake-tls", "quic": True},
]

def baseline(s, cl):
    print("\n##### BASELINE (no VPN, direct .11->.10) #####")
    out(s, "pkill -9 iperf3; sleep 1; nohup iperf3 -s >/tmp/is.log 2>&1 & echo ok"); time.sleep(1)
    r = {"tcp": iperf_tcp(cl, SERVER[0], False),
         "udp_sweep": iperf_udp_sweep(cl, SERVER[0], [500, 1000])}
    out(s, "pkill -9 iperf3")
    print("  ", json.dumps(r, ensure_ascii=False))
    return r

def main():
    print("Waiting for VMs...")
    if not wait_up():
        print("VMs not up"); return
    s = conn(SERVER); cl = conn(CLIENT)
    # Free the port: stop the systemd instance for the duration of the bench.
    out(s, "systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli 2>/dev/null; true")
    # Install the freshly-built release binary on both VMs.
    out(s, f"install -m755 {SRC_BIN} {BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, BIN); cf.close()
    out(cl, f"chmod 755 {BIN}; mkdir -p /etc/qeli")
    out(s, "mkdir -p /etc/qeli /etc/qeli/identity /var/log/qeli")
    sha = out(s, f"sha256sum {BIN} | cut -c1-16")
    ver = out(s, f"{BIN} --version 2>&1")
    print("binary:", ver, sha)

    results = {"meta": {"date": out(s, "date -u +%Y-%m-%dT%H:%M:%SZ"), "sha256_16": sha, "version": ver,
                        "server": out(s, "uname -r"), "iperf3": out(s, "iperf3 --version | head -1")},
               "baseline": baseline(s, cl), "modes": {}}
    for m in MODES:
        # Isolate each mode: a transient hang/raise records an error for that one
        # mode and the sweep continues (the lab still gets restored at the end).
        try:
            results["modes"][m["name"]] = run_mode(s, cl, m)
        except Exception as ex:
            print(f"  !! mode {m['name']} raised: {ex}")
            results["modes"][m["name"]] = {"error": f"exception: {ex}"}
            try:
                out(s, "pkill -9 -x qeli; pkill -9 iperf3; true")
                out(cl, "pkill -9 -x qeli; ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; true")
            except Exception:
                pass
    out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf")
    out(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close(); cl.close()
    open(r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\benchmark_results.json", "w", encoding="utf-8").write(json.dumps(results, indent=2, ensure_ascii=False))
    print("\n===== saved release/benchmark_results.json =====")

if __name__ == "__main__":
    main()
