#!/usr/bin/env python3
"""POOL 0 — validate the qeli one-shot installer does NOT break DNS.

Root cause (historical): the .deb `Recommends: systemd-resolved`; a plain
`apt-get install qeli.deb` pulls it in, which repoints /etc/resolv.conf to the
systemd stub mid-install and breaks resolution. Fix: install-reality-server.sh
uses `apt-get install --no-install-recommends`.

Test on the Docker host (YOUR_DOCKER_HOST) inside a systemd-PID1 container (so
systemd-resolved could actually activate — the bug only manifests with systemd):
  1. baseline: resolv.conf + resolve several domains
  2. PROOF of risk: `apt-get install -s <deb>` shows systemd-resolved WOULD be pulled
  3. run the real installer (QELI_DEB=<local deb>)
  4. verify: domains still resolve, systemd-resolved NOT installed, resolv.conf
     intact, qeli.service active
"""
import os, sys, io
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LAB10 = ("10.66.116.10", "root", os.environ["QELI_LAB_PASS"])
DOCK = (os.environ["QELI_DOCKER_HOST"], "root", os.environ["QELI_DOCKER_PASS"])
DEB_REMOTE = "/opt/qeli-src/debian/qeli_0.7.6_amd64.deb"
INSTALLER = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\install-reality-server.sh"
CT = "qeli-inst"
DOMAINS = ["github.com", "cloudflare.com", "google.com", "api.github.com"]


def conn(h):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h[0], username=h[1], password=h[2], timeout=25, look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, t=300):
    _i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def dex(c, cmd, t=300):
    # run inside the container via bash -lc, escaping single quotes
    return run(c, f"docker exec {CT} bash -lc {shq(cmd)}", t)


def shq(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    # 0. pull the .deb from .10, push to the docker host + installer
    c10 = conn(LAB10); buf = io.BytesIO(); c10.open_sftp().getfo(DEB_REMOTE, buf); c10.close()
    d = conn(DOCK)
    sf = d.open_sftp(); buf.seek(0); sf.putfo(buf, "/root/qeli.deb")
    with open(INSTALLER, "rb") as f: sf.putfo(io.BytesIO(f.read().replace(b"\r\n", b"\n")), "/root/install-reality-server.sh")
    sf.close()
    print("deb bytes:", run(d, "stat -c%s /root/qeli.deb"), "| installer bytes:", run(d, "stat -c%s /root/install-reality-server.sh"))

    # 1. build a systemd image (debian:trixie + systemd), fresh container as PID1
    run(d, f"docker rm -f {CT} 2>/dev/null; true")
    print("\n[setup] building systemd image (debian:trixie + systemd)...")
    print(run(d, "docker image inspect qeli-systemd:test >/dev/null 2>&1 && echo 'image exists' || ("
                 "docker rm -f qsetup 2>/dev/null; "
                 "docker run --name qsetup debian:trixie bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus iproute2 >/dev/null 2>&1 && echo built' "
                 "&& docker commit qsetup qeli-systemd:test >/dev/null && docker rm qsetup >/dev/null && echo committed)", t=300))
    run(d, f"docker run -d --name {CT} --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw "
           f"--tmpfs /run --tmpfs /run/lock qeli-systemd:test /sbin/init >/dev/null 2>&1; true")
    # wait for systemd to be up
    import time
    ok = False
    for _ in range(15):
        st = run(d, f"docker exec {CT} systemctl is-system-running 2>&1 || true")
        if st in ("running", "degraded") or "running" in st:
            ok = True; break
        time.sleep(2)
    print("[setup] systemd status:", run(d, f"docker exec {CT} systemctl is-system-running 2>&1 || true"), "(ok=%s)" % ok)
    # copy the deb + installer INTO the container (docker exec can't see host paths)
    run(d, f"docker cp /root/qeli.deb {CT}:/root/qeli.deb; docker cp /root/install-reality-server.sh {CT}:/root/install-reality-server.sh")
    print("[setup] in-container files:", dex(d, "ls -la /root/qeli.deb /root/install-reality-server.sh 2>&1 | awk '{print $5,$NF}'"))
    # a real server has `adduser` (base system); minimal debian:trixie lacks it and the
    # qeli.postinst needs it. Install it so the postinst succeeds (see release finding:
    # the .deb should `Depends: adduser`).
    dex(d, "apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq adduser procps >/dev/null 2>&1; "
           "mkdir -p /etc/sysctl.d /etc/modules-load.d /etc/iptables; echo done")

    # 2. baseline DNS
    print("\n=== [1] BASELINE (before install) ===")
    print("resolv.conf:", dex(d, "readlink -f /etc/resolv.conf; head -3 /etc/resolv.conf"))
    for dom in DOMAINS:
        print(f"  resolve {dom}:", dex(d, f"getent hosts {dom} | head -1 || echo FAIL"))
    print("systemd-resolved installed?:", dex(d, "dpkg -l systemd-resolved 2>/dev/null | grep -c '^ii' || true"))

    # 3. PROOF: plain apt install WOULD pull systemd-resolved
    print("\n=== [2] RISK PROOF: `apt-get install -s ./qeli.deb` (default, WITH recommends) ===")
    sim = dex(d, "cd /root && apt-get update -qq >/dev/null 2>&1; apt-get install -s ./qeli.deb 2>&1 | grep -iE 'systemd-resolved|Inst systemd-resolved' | head -3")
    print("  would-pull systemd-resolved:", sim or "(not shown — check apt output)")

    # 4. run the REAL installer (uses --no-install-recommends)
    print("\n=== [3] RUN installer (QELI_DEB=/root/qeli.deb, dummy public host) ===")
    inst = dex(d, "QELI_DEB=/root/qeli.deb bash /root/install-reality-server.sh 203.0.113.7 2>&1 | tail -20", t=420)
    print(inst)

    # 5. verify DNS survived + no systemd-resolved + service up
    print("\n=== [4] POST-INSTALL VERIFY ===")
    print("resolv.conf:", dex(d, "readlink -f /etc/resolv.conf; head -3 /etc/resolv.conf"))
    res = {}
    for dom in DOMAINS:
        out = dex(d, f"getent hosts {dom} | head -1 || echo FAIL")
        res[dom] = ("FAIL" not in out and out.strip() != "")
        print(f"  resolve {dom}:", "OK" if res[dom] else "FAIL", "-", out)
    sr = dex(d, "dpkg -l systemd-resolved 2>/dev/null | grep -c '^ii' || true")
    svc = dex(d, "systemctl is-active qeli 2>&1 || true")
    ver = dex(d, "qeli --version 2>&1 || echo NOPATH")
    print("systemd-resolved installed (want 0):", sr)
    print("qeli.service:", svc, "| version:", ver)
    all_dns = all(res.values())
    print("\n>>> DNS survived:", all_dns, "| systemd-resolved avoided:", sr.strip() == "0", "| service active:", svc == "active")

    # 6. cleanup
    run(d, f"docker rm -f {CT} >/dev/null 2>&1; true")
    d.close()
    print("\n[cleanup] container removed. GATE:", "PASS" if (all_dns and sr.strip() == "0" and svc == "active") else "CHECK")


if __name__ == "__main__":
    main()
