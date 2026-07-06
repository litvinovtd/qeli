#!/usr/bin/env python3
"""Full functional test of the REWORKED install-reality-server.sh (0.7.7):
profile choice (reality-tls/fake-tls), port choice + panel-port guard, DNS safety,
random short_id, users+links, MSS clamp + sysctl, web panel, service up.

Runs in a systemd-PID1 container on the Docker host (.142) with the freshly-built
0.7.7 .deb via QELI_DEB (offline). Three cases:
  A) reality-tls on a custom port 8443  — full verification
  B) fake-tls on the default port 443   — profile-diff verification
  C) QELI_PORT=8080 (panel port)        — must be refused (guard)
"""
import os, sys, io, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
DOCK = (os.environ["QELI_DOCKER_HOST"], "root", os.environ["QELI_DOCKER_PASS"])
DEB_REMOTE = "/opt/qeli-src/debian/qeli_0.7.7_amd64.deb"
INSTALLER = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\install-reality-server.sh"
DOMAINS = ["github.com", "cloudflare.com", "google.com"]
EXAMPLE_SID = "0123456789abcdef"  # the sample short_id from the template — must be replaced


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=420):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def shq(s): return "'" + s.replace("'", "'\\''") + "'"


def fresh_container(d, name):
    run(d, f"docker rm -f {name} 2>/dev/null; true")
    run(d, f"docker run -d --name {name} --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw "
           f"--tmpfs /run --tmpfs /run/lock qeli-systemd:test /sbin/init >/dev/null 2>&1; true")
    for _ in range(15):
        if "running" in run(d, f"docker exec {name} systemctl is-system-running 2>&1 || true"):
            break
        time.sleep(2)
    run(d, f"docker cp /root/qeli.deb {name}:/root/qeli.deb; docker cp /root/install-reality-server.sh {name}:/root/install-reality-server.sh")
    dex(d, name, "apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq adduser procps iproute2 iptables >/dev/null 2>&1; "
                 "mkdir -p /etc/sysctl.d /etc/modules-load.d /etc/iptables; echo ready")


def dex(d, ct, cmd, t=420):
    return run(d, f"docker exec {ct} bash -lc {shq(cmd)}", t)


def main():
    # pull fresh 0.7.7 deb from .10 -> docker host
    c10 = conn(LAB10); buf = io.BytesIO(); c10.open_sftp().getfo(DEB_REMOTE, buf); c10.close()
    d = conn(DOCK)
    sf = d.open_sftp(); buf.seek(0); sf.putfo(buf, "/root/qeli.deb")
    with open(INSTALLER, "rb") as f:
        sf.putfo(io.BytesIO(f.read().replace(b"\r\n", b"\n")), "/root/install-reality-server.sh")
    sf.close()
    print("deb bytes:", run(d, "stat -c%s /root/qeli.deb"))
    # ensure systemd image exists
    run(d, "docker image inspect qeli-systemd:test >/dev/null 2>&1 || ("
           "docker rm -f qsetup 2>/dev/null; docker run --name qsetup debian:trixie bash -c "
           "'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus iproute2 >/dev/null 2>&1' "
           "&& docker commit qsetup qeli-systemd:test >/dev/null && docker rm qsetup >/dev/null)", t=300)

    results = {}

    # ── C) port guard: QELI_PORT=8080 must be refused (fast — dies before install) ──
    print("\n===== [C] port guard: QELI_PORT=8080 (panel port) must be refused =====")
    fresh_container(d, "qeli-c")
    gout = dex(d, "qeli-c", "QELI_PROFILE=reality-tls QELI_PORT=8080 QELI_DEB=/root/qeli.deb bash /root/install-reality-server.sh 203.0.113.7 2>&1 | tail -4")
    guard_ok = "reserved for the web panel" in gout
    results["port-guard"] = guard_ok
    print("  refused 8080:", guard_ok, "|", gout.replace("\n", " ")[-120:])
    run(d, "docker rm -f qeli-c >/dev/null 2>&1; true")

    # ── A) reality-tls on custom port 8443 — full run ──
    print("\n===== [A] reality-tls on custom port 8443 — full install =====")
    fresh_container(d, "qeli-a")
    base_dns = all("FAIL" not in dex(d, "qeli-a", f"getent hosts {x} | head -1 || echo FAIL") for x in DOMAINS)
    print("  baseline DNS ok:", base_dns)
    inst = dex(d, "qeli-a", "QELI_PROFILE=reality-tls QELI_PORT=8443 QELI_DEB=/root/qeli.deb bash /root/install-reality-server.sh 203.0.113.7 2>&1 | tail -16", t=480)
    print(inst)
    A = {}
    A["service"] = dex(d, "qeli-a", "systemctl is-active qeli 2>&1") == "active"
    A["version"] = dex(d, "qeli-a", "qeli --version 2>&1")
    A["dns"] = all("FAIL" not in dex(d, "qeli-a", f"getent hosts {x} | head -1 || echo FAIL") for x in DOMAINS)
    A["no_resolved"] = dex(d, "qeli-a", "dpkg -l systemd-resolved 2>/dev/null | grep -c '^ii' || true").strip() == "0"
    A["profile"] = "[profile:reality-tls]" in dex(d, "qeli-a", "cat /etc/qeli/server.conf")
    A["port"] = dex(d, "qeli-a", "grep -m1 '^bind.port' /etc/qeli/server.conf")
    sid = dex(d, "qeli-a", "grep '^obf.tls.reality_proxy.short_ids' /etc/qeli/server.conf | awk '{print $NF}'")
    A["random_sid"] = bool(sid) and sid != EXAMPLE_SID
    A["listen"] = dex(d, "qeli-a", "ss -ltnH 2>/dev/null | grep -c ':8443' || true").strip()
    A["users"] = dex(d, "qeli-a", "ls /etc/qeli/client-links/phone*.qeli 2>/dev/null | wc -l").strip()
    A["link"] = dex(d, "qeli-a", "head -1 /etc/qeli/client-links/phone1.qeli 2>/dev/null")
    A["mss"] = "8443" in dex(d, "qeli-a", "iptables -t mangle -S OUTPUT 2>/dev/null | grep -i tcpmss")
    A["sysctl"] = dex(d, "qeli-a", "test -f /etc/sysctl.d/99-qeli-perf.conf && echo yes || echo no").strip() == "yes"
    A["panel"] = ("password_hash" in dex(d, "qeli-a", "grep -c password_hash /etc/qeli/server.conf") or
                  dex(d, "qeli-a", "grep -c '^password_hash' /etc/qeli/server.conf").strip() != "0")
    A["panel_bind"] = "0.0.0.0" in dex(d, "qeli-a", "grep -A1 '^\\[web\\]' /etc/qeli/server.conf; grep '^bind = 0.0.0.0' /etc/qeli/server.conf")
    print("\n  --- reality-tls verification ---")
    for k, v in A.items(): print(f"    {k:12}: {v}")
    link_ok = A["link"].startswith("qeli://") and ":8443" in A["link"] and "mode=reality-tls" in A["link"] and "rsid=" in A["link"]
    A_pass = (A["service"] and A["dns"] and A["no_resolved"] and A["profile"] and "8443" in A["port"]
              and A["random_sid"] and A["listen"] != "0" and A["users"] == "5" and link_ok and A["mss"] and A["sysctl"])
    results["reality-tls"] = A_pass
    print("  link valid (reality-tls:8443+rsid):", link_ok, "| A PASS:", A_pass)
    run(d, "docker rm -f qeli-a >/dev/null 2>&1; true")

    # ── B) fake-tls on default port 443 — profile-diff check ──
    print("\n===== [B] fake-tls on default port 443 =====")
    fresh_container(d, "qeli-b")
    instb = dex(d, "qeli-b", "QELI_PROFILE=fake-tls QELI_DEB=/root/qeli.deb bash /root/install-reality-server.sh 203.0.113.7 2>&1 | tail -6", t=480)
    B = {}
    B["service"] = dex(d, "qeli-b", "systemctl is-active qeli 2>&1") == "active"
    B["profile"] = "[profile:fake-tls]" in dex(d, "qeli-b", "cat /etc/qeli/server.conf")
    B["port"] = dex(d, "qeli-b", "grep -m1 '^bind.port' /etc/qeli/server.conf")
    B["no_reality"] = dex(d, "qeli-b", "grep -c 'reality_proxy.enabled = true' /etc/qeli/server.conf || true").strip() == "0"
    B["link"] = dex(d, "qeli-b", "head -1 /etc/qeli/client-links/phone1.qeli 2>/dev/null")
    B["listen443"] = dex(d, "qeli-b", "ss -ltnH 2>/dev/null | grep -c ':443' || true").strip()
    print("  ", instb.replace("\n", " ")[-150:])
    for k, v in B.items(): print(f"    {k:12}: {v}")
    b_link_ok = B["link"].startswith("qeli://") and "mode=fake-tls" in B["link"] and "rsid=" not in B["link"]
    B_pass = B["service"] and B["profile"] and "443" in B["port"] and B["no_reality"] and b_link_ok and B["listen443"] != "0"
    results["fake-tls"] = B_pass
    print("  fake-tls link (no rsid):", b_link_ok, "| B PASS:", B_pass)
    run(d, "docker rm -f qeli-b >/dev/null 2>&1; true")

    print("\n===== INSTALLER TEST SUMMARY =====")
    for k, v in results.items(): print(f"  {k:14}: {'PASS' if v else 'FAIL'}")
    print(f"\n>>> {sum(results.values())}/{len(results)} cases PASS")
    d.close()


if __name__ == "__main__":
    main()
