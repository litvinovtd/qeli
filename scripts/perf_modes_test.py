#!/usr/bin/env python3
"""Phase B — throughput of every qeli wire mode, lab(.11) client -> PROD server,
over the real internet path (RTT ~32ms, 0% loss). Measures TCP goodput *inside*
the tunnel with iperf3 (download via -R and upload), for each of the 9 prod
profiles. Enables all profiles on prod (backup + 1 restart; 0 clients connected
now), runs the sweep, then restores the reality-tls-only config. try/finally
guarantees prod is restored.

Client is split-tunnel by default (no default-route takeover) → SSH to .11 stays
up and only 10.9.x.0/24 routes through the tunnel."""
import os, sys, io, time, re, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

PROD = ("YOUR_PROD_HOST", "root", os.environ.get("QELI_PROD_PASS", ""))
LAB = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
CONF = "/etc/qeli/server-maxobf.conf"
BAK = "/etc/qeli/server-maxobf.conf.perfbak"
QCLI = "/root/qeli-l3/qeli"
LINKS = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\prod-client-configs\allmodes"
USER, PW = "user01", "NA4BLbbHIpIpyJ5y"

# profile -> (port, server_tun_ip). order = test order.
PROFILES = [
    ("plain",        8447, "10.9.5.1"),
    ("reality-tls",  443,  "10.9.0.1"),
    ("reality",      8443, "10.9.1.1"),
    ("fake-tls",     8444, "10.9.2.1"),
    ("obfs-ws",      8445, "10.9.3.1"),
    ("obfs-none",    8446, "10.9.4.1"),
    ("udp-fake-tls", 8448, "10.9.6.1"),
    ("udp-quic",     8449, "10.9.7.1"),
    ("udp-obfs",     8450, "10.9.8.1"),
]


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def parse_link(path):
    """qeli://user:pass@host:port?proto=&mode=&key=&sni=&rsid=&obfs=&front=&quic= -> dict"""
    txt = open(path, encoding="utf-8").read().strip().splitlines()[0]
    q = txt.split("?", 1)[1].split("#", 1)[0]
    d = {}
    for kv in q.split("&"):
        k, _, v = kv.partition("=")
        d[k] = v
    return d


def client_ini(mode_params):
    p = mode_params
    lines = ["[qeli]",
             f"server = YOUR_PROD_HOST:{p['port']}",
             f"proto = {p['proto']}",
             f"user = {USER}", f"pass = {PW}",
             f"key = {p['key']}",
             f"mode = {p['mode']}"]
    if p.get("sni"):        lines.append(f"sni = {p['sni']}")
    if p.get("rsid"):       lines.append(f"reality_sid = {p['rsid']}")
    if p.get("obfs"):       lines.append(f"obfs_key = {p['obfs']}")
    if p.get("front"):      lines.append(f"front = {p['front']}")
    if p.get("quic") in ("1", "true"): lines.append("quic = true")
    lines += ["[logging]", "level = info", "file = /root/perf-cli.log"]
    return "\n".join(lines) + "\n"


def main():
    sc = conn(PROD); lc = conn(LAB)
    def P(cmd, t=120):
        i, o, e = sc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
    def L(cmd, t=120):
        i, o, e = lc.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()
    def kill_client():
        L("kill -9 $(cat /root/perf-cli.pid 2>/dev/null) 2>/dev/null; true")
    def clean_tuns(before):
        after = set(L("ip -o link show | awk -F': ' '{print $2}'").split())
        for ifc in after - before:
            ifc = ifc.split('@')[0]
            if ifc and ifc != "lo":
                L(f"ip link del {ifc} 2>/dev/null; true")

    results = {}
    before_links = set()
    try:
        # ── prod prep: enable all profiles, restart, iperf3 -s ──
        print("=== PROD: enable all profiles + restart ===")
        print("[clients connected now]", P("ss -tn state established '( sport = :443 )' 2>/dev/null | grep -c ESTAB"))
        P(f"cp -n {CONF} {BAK}; cp {CONF} {BAK}.$(date +%s)")  # backup (keep first .perfbak stable)
        P(f"sed -i 's/^enabled = false$/enabled = true/' {CONF}")
        print("[enabled profiles]", P(f"grep -c '^enabled = true' {CONF}"))
        P("systemctl restart qeli.service"); time.sleep(6)
        print("[listening ports]", P("ss -ltn | grep -oE ':(443|844[0-9]|8450)' | sort -u | tr '\\n' ' '"))
        print("[udp ports]", P("ss -lun | grep -oE ':(844[89]|8450)' | sort -u | tr '\\n' ' '"))
        # per-profile pubkeys from log
        pk = {}
        for line in P("grep \"server identity public key\" /var/log/qeli/server.log | tail -20").splitlines():
            m = re.search(r"Profile '([^']+)'.*pin on client\): ([0-9a-f]{64})", line)
            if m: pk[m.group(1)] = m.group(2)
        print("[pubkeys]", {k: v[:12]+".." for k, v in pk.items()})
        P("pkill -9 iperf3 2>/dev/null; iperf3 -s -D --logfile /root/iperf3.log; sleep 1")
        print("[iperf3 -s]", P("ss -ltn | grep -q :5201 && echo running || echo FAILED"))

        # ── lab prep ──
        L("cp -n /etc/resolv.conf /root/resolv.perfbak 2>/dev/null; true")
        before_links.update(L("ip -o link show | awk -F': ' '{print $2}'").split())

        # ── sweep ──
        for name, port, stun in PROFILES:
            link = parse_link(os.path.join(LINKS, f"user01__{name}.qeli"))
            params = dict(port=port, proto=link.get("proto","tcp"), mode=link.get("mode","fake-tls"),
                          key=pk.get(name) or link.get("key",""), sni=link.get("sni"),
                          rsid=link.get("rsid"), obfs=link.get("obfs"), front=link.get("front"),
                          quic=link.get("quic"))
            print(f"\n===== {name} ({params['proto']}:{port}, mode={params['mode']}) =====")
            sf = lc.open_sftp(); sf.putfo(io.BytesIO(client_ini(params).encode()), "/root/perf-cli.conf"); sf.close()
            kill_client(); clean_tuns(before_links)
            L("rm -f /root/perf-cli.log /root/perf-cli.out; sleep 1; true")
            L(f"nohup {QCLI} client -c /root/perf-cli.conf </dev/null >/root/perf-cli.out 2>&1 & echo $! >/root/perf-cli.pid; sleep 0.5")
            # wait for tunnel up (assigned IP)
            cip = None
            for _ in range(18):
                time.sleep(1)
                lg = L("cat /root/perf-cli.log /root/perf-cli.out 2>/dev/null")
                m = re.search(r"(?:assigned IP|client_ip|IP)\s*[:=]?\s*(10\.9\.\d+\.\d+)", lg)
                if m: cip = m.group(1); break
                if "rror" in lg or "refused" in lg.lower() or "failed" in lg.lower():
                    if "10.9." not in lg: break
            if not cip:
                tail = L("tail -5 /root/perf-cli.log /root/perf-cli.out 2>/dev/null")
                print(f"  CONNECT FAIL:\n{tail}")
                results[name] = {"status": "connect-fail"}
                kill_client(); clean_tuns(before_links)
                continue
            print(f"  tunnel up, client IP {cip}; iperf3 -> {stun}")
            # download (server->client) and upload (client->server), 6s, omit slow start
            dn = L(f"iperf3 -c {stun} -t 6 -O 1 -R -J --connect-timeout 8000 2>/dev/null", t=30)
            up = L(f"iperf3 -c {stun} -t 6 -O 1 -J --connect-timeout 8000 2>/dev/null", t=30)
            def mbps(j):
                try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"]/1e6, 1)
                except Exception: return None
            d, u = mbps(dn), mbps(up)
            rtt = L(f"ping -c5 -i0.2 -W2 {stun} 2>/dev/null | tail -1")
            print(f"  DOWN {d} Mbps | UP {u} Mbps | {rtt}")
            results[name] = {"down": d, "up": u, "port": port, "proto": params["proto"], "rtt": rtt}
            kill_client(); clean_tuns(before_links); time.sleep(1)

        # ── raw ceiling (no tunnel): temp-open 5201 on prod fw, iperf3 direct ──
        print("\n===== RAW (no tunnel) ceiling =====")
        P("iptables -I INPUT -p tcp --dport 5201 -j ACCEPT")
        raw_dn = L("iperf3 -c YOUR_PROD_HOST -t 6 -O 1 -R -J 2>/dev/null", t=30)
        raw_up = L("iperf3 -c YOUR_PROD_HOST -t 6 -O 1 -J 2>/dev/null", t=30)
        def mbps2(j):
            try: return round(json.loads(j)["end"]["sum_received"]["bits_per_second"]/1e6, 1)
            except Exception: return None
        results["__raw__"] = {"down": mbps2(raw_dn), "up": mbps2(raw_up)}
        print(f"  RAW DOWN {results['__raw__']['down']} Mbps | UP {results['__raw__']['up']} Mbps")
        P("iptables -D INPUT -p tcp --dport 5201 -j ACCEPT 2>/dev/null; true")

    finally:
        # ── restore everything ──
        print("\n=== RESTORE ===")
        kill_client()
        L("cp -f /root/resolv.perfbak /etc/resolv.conf 2>/dev/null; true")
        clean_tuns(before_links)
        P("pkill -9 iperf3 2>/dev/null; iptables -D INPUT -p tcp --dport 5201 -j ACCEPT 2>/dev/null; true")
        P(f"cp -f {BAK} {CONF}")
        P("systemctl restart qeli.service"); time.sleep(5)
        print("[prod restored] active:", P("systemctl is-active qeli.service"),
              "| :443", P("ss -ltn | grep -q :443 && echo up || echo DOWN"),
              "| extra ports", P("ss -ltn | grep -cE ':(844[0-9]|8450)'"))
        sc.close(); lc.close()

    print("\n================= RESULTS (Mbps, lab.11 -> PROD) =================")
    raw = results.get("__raw__", {})
    print(f"{'mode':14} {'proto':5} {'DOWN':>8} {'UP':>8}   notes")
    print(f"{'RAW(no tun)':14} {'tcp':5} {str(raw.get('down')):>8} {str(raw.get('up')):>8}")
    for name, _, _ in PROFILES:
        r = results.get(name, {})
        if r.get("status") == "connect-fail":
            print(f"{name:14} {'?':5} {'FAIL':>8} {'FAIL':>8}   connect-fail")
        else:
            print(f"{name:14} {r.get('proto','?'):5} {str(r.get('down')):>8} {str(r.get('up')):>8}")
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
