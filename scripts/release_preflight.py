#!/usr/bin/env python3
"""Release preflight — run this BEFORE cutting a release, from the release branch.

Two gates that a 64-bit-only lab build misses (this is exactly how the 0.7.12
mipsel/armv7 router regression reached asset-packaging: CI was red on dev for four
commits, but the local jemalloc gate stayed green and nobody looked at CI):

  1. CI green  — the latest CI run on the branch must be `success`. Since the
                 keenetic-cross matrix builds every shipped router arch
                 (aarch64 + armv7 + mipsel), a green CI already guarantees the
                 32-bit clients compile. Needs `gh` authenticated.
  2. 32-bit    — optional belt-and-suspenders: cross-build the mipsel + armv7
                 router client on the lab, independent of CI. Runs only when
                 QELI_LAB_PASS is set; host from QELI_LAB_SERVER (default .10).

Exit non-zero if any gate fails, so it can front a release script.

  python scripts/release_preflight.py [branch]      # branch default: current
"""
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BRANCH = sys.argv[1] if len(sys.argv) > 1 else subprocess.run(
    ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True
).stdout.strip()

failures = []

# ── Gate 1: CI green on the branch ───────────────────────────────────────────
print(f"=== Gate 1: latest CI run on '{BRANCH}' ===")
try:
    out = subprocess.run(
        ["gh", "run", "list", "--branch", BRANCH, "--workflow", "CI", "--limit", "1",
         "--json", "conclusion,status,headSha,databaseId"],
        capture_output=True, text=True, check=True,
    ).stdout
    runs = json.loads(out)
    if not runs:
        failures.append("no CI run found for the branch")
        print("  ! no CI run found")
    else:
        r = runs[0]
        print(f"  {r['headSha'][:8]}  status={r['status']}  conclusion={r['conclusion']}")
        if r["status"] != "completed":
            failures.append(f"CI still running ({r['status']})")
        elif r["conclusion"] != "success":
            failures.append(f"CI conclusion={r['conclusion']}")
            # name the failed jobs so the operator knows what to fix
            jobs = subprocess.run(
                ["gh", "run", "view", str(r["databaseId"]), "--json", "jobs"],
                capture_output=True, text=True,
            ).stdout
            for j in json.loads(jobs or "{}").get("jobs", []):
                if j.get("conclusion") not in ("success", "skipped", None):
                    print(f"    FAILED: {j['name']} = {j['conclusion']}")
except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
    failures.append(f"gh query failed: {e}")
    print(f"  ! {e}")

# ── Gate 2: 32-bit router cross-build on the lab (optional) ──────────────────
lab_pass = os.environ.get("QELI_LAB_PASS", "")
if not lab_pass:
    print("\n=== Gate 2: 32-bit lab build — SKIPPED (QELI_LAB_PASS unset) ===")
else:
    print("\n=== Gate 2: 32-bit router cross-build on the lab ===")
    try:
        import paramiko
    except ImportError:
        print("  ! paramiko not installed — skipping"); paramiko = None
    if paramiko is not None:
        host = os.environ.get("QELI_LAB_SERVER", "10.66.116.10")
        src = os.environ.get("QELI_LAB_SRC", "/opt/qeli-src")
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, username="root", password=lab_pass, timeout=25,
                  look_for_keys=False, allow_agent=False)

        def sh(cmd, t=2400):
            i, o, e = c.exec_command(cmd, timeout=t)
            return o.channel.recv_exit_status(), (o.read() + e.read()).decode("utf-8", "replace")

        env = "export PATH=/root/.cargo/bin:$PATH; "
        common = "--release --bin qeli-client --no-default-features --features client-bin"
        builds = {
            "armv7": f"{env} cd {src} && cargo zigbuild {common} --target armv7-unknown-linux-musleabihf",
            "mipsel": f"{env} cd {src} && RUSTFLAGS='-C link-arg=-msoft-float' cargo +nightly zigbuild "
                      f"-Z build-std=std,panic_abort {common} --target mipsel-unknown-linux-musl",
        }
        for arch, cmd in builds.items():
            rc, out = sh(cmd)
            ok = rc == 0   # a build error makes cargo exit non-zero
            print(f"  {arch}: {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"32-bit {arch} build failed")
                print("\n".join(l for l in out.splitlines() if l.startswith("error"))[:600])
        c.close()

# ── verdict ──────────────────────────────────────────────────────────────────
print("\n===== PREFLIGHT =====")
if failures:
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("PASS — safe to release")
