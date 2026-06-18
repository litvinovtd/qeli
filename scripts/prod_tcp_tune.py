#!/usr/bin/env python3
"""Apply TCP:443 reality-tls throughput tuning on PROD (reversible):
  A) sysctl: BBR + fq qdisc + bigger TCP buffers + tcp_mtu_probing (no restart)
  B) reality-tls profile: tun.mtu 1400->1280, obf.padding off (1 qeli restart)
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
print("\n[done] Revert: rm /etc/sysctl.d/99-qeli-perf.conf /etc/modules-load.d/qeli-bbr.conf && sysctl --system ; cp", BAK, CONF, "&& systemctl restart qeli.service")
