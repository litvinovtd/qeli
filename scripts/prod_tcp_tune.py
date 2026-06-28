#!/usr/bin/env python3
"""Apply TCP reality-tls throughput tuning on PROD (reversible):
  A) sysctl: BBR + fq qdisc + bigger TCP buffers + tcp_mtu_probing (no restart)
  B) reality-tls profile: tun.mtu 1400->1280, obf.padding off (1 qeli restart)
  C) outer-port MSS clamp on the TCP listening ports (443/8443/8444/8445) so the
     large post-quantum reality/fake-tls ClientHello fits LTE (no PMTU black hole on
     the OUTER handshake — the in-tunnel vpn+ clamp does not cover it)
Backs up the config + writes /etc/sysctl.d/99-qeli-perf.conf so everything is
revertible. Prints before/after."""
import os, sys, io, re, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

CONF = "/etc/qeli/server-maxobf.conf"
BAK = "/etc/qeli/server-maxobf.conf.pretune"
SYSCTL = "/etc/sysctl.d/99-qeli-perf.conf"

SYSCTL_BODY = """# qeli reality-tls TCP:443 throughput tuning (reversible; delete this file + reboot/sysctl --system to revert)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
"""


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("YOUR_PROD_HOST", username="root", password=os.environ["QELI_PROD_PASS"],
              timeout=25, look_for_keys=False, allow_agent=False)
    return c


def edit_reality_tls(text):
    """Within the [profile:reality-tls] section only: tun.mtu->1280, padding off."""
    lines = text.splitlines(keepends=True)
    out = []
    in_rt = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("[profile:"):
            in_rt = (s == "[profile:reality-tls]")
        elif s.startswith("[") and s.endswith("]"):
            in_rt = False
        if in_rt:
            if re.match(r"\s*tun\.mtu\s*=", ln):
                ln = "tun.mtu = 1280\n"
            elif re.match(r"\s*obf\.padding\.enabled\s*=", ln):
                ln = "obf.padding.enabled = false\n"
        out.append(ln)
    return "".join(out)


c = conn()
def r(cmd, t=90):
    i, o, e = c.exec_command(cmd, timeout=t); return (o.read().decode("utf-8","replace")+e.read().decode("utf-8","replace")).strip()

print("=========== BEFORE ===========")
print("[cc]", r("sysctl -n net.ipv4.tcp_congestion_control"),
      "| [qdisc]", r("sysctl -n net.core.default_qdisc"),
      "| [rmem_max]", r("sysctl -n net.core.rmem_max"),
      "| [mtu_probing]", r("sysctl -n net.ipv4.tcp_mtu_probing"))
print("[reality-tls tun.mtu]", r(f"awk '/\\[profile:reality-tls\\]/{{f=1}} /^\\[profile:/&&!/reality-tls/{{f=0}} f&&/tun.mtu/' {CONF}"))
print("[reality-tls padding]", r(f"awk '/\\[profile:reality-tls\\]/{{f=1}} /^\\[profile:/&&!/reality-tls/{{f=0}} f&&/obf.padding.enabled/' {CONF}"))

# ── A. sysctl (no restart) ──
print("\n=========== APPLY A (sysctl BBR/buffers/mtu_probing) ===========")
r("modprobe tcp_bbr")
r("echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf")
sf = c.open_sftp(); sf.putfo(io.BytesIO(SYSCTL_BODY.encode()), SYSCTL); sf.close()
print(r(f"sysctl -p {SYSCTL} 2>&1"))
print("[bbr in available now]", r("sysctl -n net.ipv4.tcp_available_congestion_control"))

# ── B. config (tun.mtu + padding) + restart ──
print("\n=========== APPLY B (reality-tls tun.mtu=1280 + padding off) ===========")
r(f"cp -n {CONF} {BAK}")  # keep first backup as the true pre-tune original
sf = c.open_sftp()
orig = sf.open(CONF).read().decode("utf-8")
new = edit_reality_tls(orig)
sf.putfo(io.BytesIO(new.encode()), CONF); sf.close()
print("[clients connected pre-restart]", r("ss -tn state established '( sport = :443 )' 2>/dev/null | grep -c ESTAB"))
print("[restart]", r("systemctl restart qeli.service && echo OK"))
time.sleep(5)

# ── C. outer-port MSS clamp (LTE: the big PQ reality/fake-tls ClientHello fits) ──
# The vpn+ FORWARD clamp above is for IN-TUNNEL traffic only. reality-tls (real_tls)
# sends a real Chrome ClientHello carrying X25519MLKEM768 (~1700 B) over the OUTER TCP
# to :443, where the server otherwise advertises ~1460 (WAN MTU 1500); on LTE that
# 1460-byte segment black-holes. Clamp the MSS the server advertises on its TCP ports.
print("\n=========== APPLY C (outer-port MSS clamp 1340) ===========")
OUTER_MSS = 1340
OUTER_PORTS = (443, 8443, 8444, 8445)  # bind.port of the TCP profiles
for p in OUTER_PORTS:
    rule = f"-p tcp --sport {p} --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {OUTER_MSS}"
    # idempotent: add only if not already present (-C succeeds => already there)
    r(f"iptables -t mangle -C OUTPUT {rule} 2>/dev/null || iptables -t mangle -A OUTPUT {rule}")
r("iptables-save > /etc/iptables/rules.v4 2>/dev/null; true")
print(f"[outer MSS rules present]",
      r(r"iptables -t mangle -S OUTPUT | grep -cE 'sport (443|844[345]) .*TCPMSS --set-mss 1340'"), "of 4")

print("\n=========== AFTER ===========")
print("[cc]", r("sysctl -n net.ipv4.tcp_congestion_control"),
      "| [qdisc]", r("sysctl -n net.core.default_qdisc"),
      "| [rmem_max]", r("sysctl -n net.core.rmem_max"),
      "| [wmem_max]", r("sysctl -n net.core.wmem_max"),
      "| [mtu_probing]", r("sysctl -n net.ipv4.tcp_mtu_probing"))
print("[reality-tls tun.mtu]", r(f"awk '/\\[profile:reality-tls\\]/{{f=1}} /^\\[profile:/&&!/reality-tls/{{f=0}} f&&/tun.mtu/' {CONF}"))
print("[reality-tls padding]", r(f"awk '/\\[profile:reality-tls\\]/{{f=1}} /^\\[profile:/&&!/reality-tls/{{f=0}} f&&/obf.padding.enabled/' {CONF}"))
print("[qeli.service]", r("systemctl is-active qeli.service"), "| [:443]", r("ss -ltn | grep -q :443 && echo up || echo DOWN"))
print("[server pushed mtu in log]", r("grep -iE 'mtu|push' /var/log/qeli/server.log | tail -2"))
print("[default cc for new conns]", r("sysctl -n net.ipv4.tcp_congestion_control"))
c.close()
print("\n[done] Revert:")
print("  A/B: rm /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system ;",
      "cp", BAK, CONF, "&& systemctl restart qeli.service")
print("  C:   for p in 443 8443 8444 8445; do iptables -t mangle -D OUTPUT -p tcp --sport $p",
      "--tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340; done && iptables-save > /etc/iptables/rules.v4")
