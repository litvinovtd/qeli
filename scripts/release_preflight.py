#!/usr/bin/env python3
"""Release preflight — run this BEFORE cutting a release, from the release branch.

Gates that a 64-bit-only lab build misses (this is exactly how the 0.7.12
mipsel/armv7 router regression reached asset-packaging: CI was red on dev for four
commits, but the local jemalloc gate stayed green and nobody looked at CI):

  1. CI green  — the latest CI run on the branch must be `success`. Since the
                 keenetic-cross matrix builds every shipped router arch
                 (aarch64 + armv7 + mipsel), a green CI already guarantees the
                 32-bit clients compile. Needs `gh` authenticated.
  2. 32-bit    — optional belt-and-suspenders: cross-build the mipsel + armv7
                 router client on the lab, independent of CI. Runs only when
                 QELI_LAB_PASS is set; host from QELI_LAB_SERVER (default .10).
                 The lab checkout must be AT the commit being released — the gate
                 prints the SHA it actually built and fails on any divergence.
  3. OpenWrt   — the feed Makefile's PKG_SOURCE_VERSION must pin the commit being
                 released and PKG_MIRROR_HASH must be a real sha256, not the
                 unmatchable placeholder (which makes the router package unbuildable).
                 Local-only; no network or lab needed.

Exit non-zero if any gate fails, so it can front a release script.

  python scripts/release_preflight.py [branch]      # branch default: current

Environment:
  QELI_LAB_PASS           enables gate 2 (SSH password for root on the lab host)
  QELI_LAB_SERVER         lab host (default 10.66.116.10)
  QELI_LAB_SRC            checkout on the lab host (default /opt/qeli-src)
  QELI_LAB_TRUST_NEW_HOST=1
                          accept a host key that is not in known_hosts (off by default)
"""
import hashlib
import json
import os
import subprocess
import sys
import ssh_hostkey

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BRANCH = sys.argv[1] if len(sys.argv) > 1 else subprocess.run(
    ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True
).stdout.strip()

# Identity of the sources a qeli binary is built from. Deliberately the same recipe on
# both sides so the two are comparable: `sha256sum` every file under the crate's src/ plus
# Cargo.toml and Cargo.lock, sort those lines, hash the result. See gate 2. (O8)
#
# Paths are relative TO THE CRATE, not to the repository root, and that is load-bearing. The
# digest hashes "<sha>  <path>" lines, so the two sides only agree if they name the files the
# same way — and QELI_LAB_SRC points at the crate directory (/opt/qeli-src holds Cargo.toml),
# because that is what gate 2 then cd's into to run cargo. The remote half used to look for
# `qeli/src` inside it, which does not exist there: `find` matched nothing, the digest was a
# constant, and it never equalled the local one. The mismatch reads as "the lab is out of
# date", and its handler SKIPS the cross-builds — so the gate could not fail and could not
# pass, it simply never ran. Silence like that is worse than a red gate.
# CR bytes are stripped before hashing, on both sides. `.gitattributes` says `* text=auto
# eol=lf`, so git normalises line endings itself and a CRLF-only difference cannot exist
# between two commits — but it routinely exists between a WORKING TREE and a checkout, which
# is what these two digests actually compare. Two web templates carry CRLF in this Windows
# checkout and LF in the lab's clone, and without this the gate reported "the lab tree is not
# the tree being released" over a line ending. Nothing is lost: a difference git cannot record
# is not a difference the release can ship.
FP_FILES = ("Cargo.toml", "Cargo.lock")
FP_TREE = "src"
LOCAL_CRATE = "qeli"          # where the crate lives inside this repository
REMOTE_FINGERPRINT = (
    "{ find " + FP_TREE + " -type f -print; "
    "for f in " + " ".join(FP_FILES) + "; do [ -f \"$f\" ] && printf '%s\\n' \"$f\"; done; } "
    "| while IFS= read -r f; do "
    "printf '%s  %s\\n' \"$(tr -d '\\r' < \"$f\" | sha256sum | cut -d' ' -f1)\" \"$f\"; done "
    "| LC_ALL=C sort | sha256sum"
    # The per-file lines are sorted, so the order the files are visited in does not
    # matter; only the set of (digest, path) pairs does.
)


def source_fingerprint(base: str) -> str:
    """Local half of REMOTE_FINGERPRINT — byte-for-byte the same digest.

    `base` is the repository root; paths are emitted crate-relative so they match the remote
    half, which runs inside the crate directory.
    """
    crate = os.path.join(base, LOCAL_CRATE)
    rels = []
    for root, dirs, files in os.walk(os.path.join(crate, FP_TREE)):
        for name in files:
            rels.append(os.path.relpath(os.path.join(root, name), crate).replace(os.sep, "/"))
    rels += [r for r in FP_FILES if os.path.isfile(os.path.join(crate, r))]
    lines = []
    for rel in rels:
        with open(os.path.join(crate, rel), "rb") as fh:
            data = fh.read().replace(b"\r", b"")   # same rule as `tr -d '\r'` remotely
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {rel}\n")
    return hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()


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
        # WHICH COMMIT was green matters as much as whether it was green. The run's headSha
        # was printed and then ignored, so a run from an earlier push on the same branch
        # satisfied this gate for a commit CI had never seen — exactly the case a release
        # gate exists to catch, and invisible because the output looked identical either way.
        # (Audit 2026-07-29, #3.)
        local_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()
        if local_head and r.get("headSha") and r["headSha"] != local_head:
            failures.append(
                f"CI ran on {r['headSha'][:8]}, not on the commit being released "
                f"({local_head[:8]}) — push and let CI finish first"
            )
            print(f"  ! CI covered {r['headSha'][:8]}, HEAD is {local_head[:8]}")
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
        c = paramiko.SSHClient()
        ssh_hostkey.harden(c, host)
        try:
            c.connect(host, username="root", password=lab_pass, timeout=25,
                      look_for_keys=False, allow_agent=False)
            connected = True
        except Exception as e:                      # noqa: BLE001 — any failure is a gate failure
            connected = False
            failures.append(f"lab connect failed: {e}")
            print(f"  ! cannot reach {host}: {e}")
            print("    (unknown host key? add it to ~/.ssh/known_hosts, or set QELI_LAB_TRUST_NEW_HOST=1)")

    if paramiko is not None and connected:
        def sh(cmd, t=2400):
            i, o, e = c.exec_command(cmd, timeout=t)
            return o.channel.recv_exit_status(), (o.read() + e.read()).decode("utf-8", "replace")

        # WHICH tree is being built? This gate compiles on ANOTHER machine and never
        # checked that the checkout there is the code being released — a lab tree days
        # behind the branch produced a green gate certifying source that is not in the
        # release. The identity actually built is printed and a divergence is fatal.
        #
        # The lab tree is fed by SFTP push, not by git, so a commit SHA is often absent
        # there; the decidable identity is a fingerprint over the sources that go into
        # the binary (qeli/src + Cargo.toml + Cargo.lock), computed the same way on both
        # sides. The commit SHA is printed too whenever either side has one.
        # (Audit 2026-07-27, O8)
        local_sha = subprocess.run(
            ["git", "rev-parse", BRANCH], capture_output=True, text=True,
        ).stdout.strip()
        local_dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "qeli/src", "qeli/Cargo.toml", "qeli/Cargo.lock"],
            capture_output=True, text=True,
        ).stdout.strip()
        _, lab_sha = sh(f"git -C {src} rev-parse HEAD 2>/dev/null || true", t=60)
        lab_sha = lab_sha.strip()
        local_fp = source_fingerprint(ROOT)
        _, lab_fp_out = sh(f"cd {src} && " + REMOTE_FINGERPRINT, t=120)
        lab_fp = lab_fp_out.strip().split()[0] if lab_fp_out.strip() else ""

        print(f"  releasing  : {local_sha or '<unknown>'}  ({BRANCH})"
              f"{'  [LOCAL TREE DIRTY]' if local_dirty else ''}")
        print(f"  lab {src} : {lab_sha or '<not a git checkout>'}")
        print(f"  source fingerprint  local={local_fp[:16] or '<none>'}  lab={lab_fp[:16] or '<none>'}")
        if local_dirty:
            print("  ! the local qeli sources differ from the last commit — what gets released")
            print("    is the COMMIT, so commit before relying on this gate.")

        if not local_fp or not lab_fp or local_fp != lab_fp:
            failures.append(
                f"lab tree does not match the tree being released "
                f"(local {local_fp[:16] or '<none>'} vs lab {lab_fp[:16] or '<none>'})"
            )
            print("  ! SKIPPING the cross-builds: building a different tree proves nothing.")
            print(f"    Push the release sources to {host}:{src} first (or point QELI_LAB_SRC")
            print(f"    at a checkout of {local_sha or BRANCH}), then re-run.")
        else:
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
                print(f"  {arch}: {'OK' if ok else 'FAIL'}  (from {local_sha[:8]})")
                if not ok:
                    failures.append(f"32-bit {arch} build failed")
                    print("\n".join(l for l in out.splitlines() if l.startswith("error"))[:600])
        c.close()

# ── Gate 3: OpenWrt package pin ──────────────────────────────────────────────
# The feed Makefile pins the source by SHA and verifies the generated tarball by
# PKG_MIRROR_HASH. Both are release-time facts: the SHA is the commit being tagged, and
# the hash only exists once that tarball has been produced. Left stale, the package
# either builds a DIFFERENT tree than the release or refuses to build at all — and the
# all-zero placeholder is deliberately unmatchable, so nothing catches it until someone
# tries to build for a router. Checked here because this is the one script that runs
# with the release commit in hand. (Audit 2026-07-30, #2.)
print("\n=== Gate 3: OpenWrt package pin ===")
OWRT_MK = os.path.join(ROOT, "qeli-openwrt", "Makefile")
PLACEHOLDER_HASH = "0" * 64
try:
    with open(OWRT_MK, encoding="utf-8") as fh:
        mk = fh.read()

    def mk_var(name):
        for line in mk.splitlines():
            if line.startswith(f"{name}:="):
                return line.split(":=", 1)[1].strip()
        return None

    pkg_hash = mk_var("PKG_MIRROR_HASH")
    pkg_sha = mk_var("PKG_SOURCE_VERSION")
    pkg_ver = mk_var("PKG_VERSION")
    # A git failure must FAIL the check, not skip it.
    #
    # The exit code was ignored and only `stdout` read, so anything that stopped git from
    # answering — a dubious-ownership refusal, a detached worktree, git missing from PATH —
    # left `head` empty, and the `if head and ...` below then quietly skipped the comparison.
    # The one gate that catches a stale PKG_SOURCE_VERSION was therefore disabled by an
    # unrelated environment problem, and disabled SILENTLY: preflight printed the Makefile's
    # SHA and reported no mismatch, which reads as "the pin is correct".
    # (Audit 2026-08-02, §8 of the follow-up.)
    head_proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT
    )
    head = head_proc.stdout.strip()
    if head_proc.returncode != 0 or not head:
        detail = head_proc.stderr.strip() or f"exit {head_proc.returncode}"
        failures.append(
            "release_preflight: cannot read HEAD via git "
            f"({detail}) — refusing to skip the OpenWrt PKG_SOURCE_VERSION comparison, "
            "which is the only check that catches the router package building an older tree"
        )

    print(f"  PKG_VERSION={pkg_ver}  PKG_SOURCE_VERSION={(pkg_sha or '')[:8]}  "
          f"PKG_MIRROR_HASH={'<placeholder>' if pkg_hash == PLACEHOLDER_HASH else (pkg_hash or '')[:16]}")

    if pkg_hash is None or pkg_sha is None or pkg_ver is None:
        failures.append("qeli-openwrt/Makefile: could not read PKG_VERSION/PKG_SOURCE_VERSION/PKG_MIRROR_HASH")
    else:
        if pkg_hash == PLACEHOLDER_HASH:
            failures.append(
                "qeli-openwrt/Makefile: PKG_MIRROR_HASH is still the placeholder — the router "
                "package cannot build. Produce it from an OpenWrt buildroot with "
                "`make package/qeli/download V=s && sha256sum dl/qeli-<ver>.tar.xz` "
                "(or `make package/qeli/check FIXUP=1`). Never set it to `skip`."
            )
        elif pkg_hash.lower() == "skip":
            failures.append("qeli-openwrt/Makefile: PKG_MIRROR_HASH=skip disables tarball verification")
        elif len(pkg_hash) != 64 or not all(ch in "0123456789abcdef" for ch in pkg_hash.lower()):
            failures.append(f"qeli-openwrt/Makefile: PKG_MIRROR_HASH is not a sha256 ({pkg_hash!r})")

        if head and pkg_sha != head:
            # The pin can never equal the commit that sets it: writing a SHA into this file
            # produces a new commit with a different SHA. Demanding equality made this gate
            # unsatisfiable, and an unsatisfiable gate gets bypassed — which is worse than a
            # gate that asks the decidable question.
            #
            # What the check is FOR is that the router package compiles the sources being
            # released. The package builds only qeli/ (Build/Compile cd's into
            # $(PKG_BUILD_DIR)/qeli; the init/config files come from the feed clone, not the
            # tarball), so the question is whether the pinned commit carries the same qeli/
            # tree as the release. A pin left over from an earlier version still fails — that
            # tree differs — which is the case this gate exists to catch.
            def tree_of(rev):
                # `<commit>:<path>` already resolves to the subtree's OID; appending
                # ^{tree} makes git look for a PATH literally named "qeli^{tree}".
                p = subprocess.run(["git", "rev-parse", rev],
                                   capture_output=True, text=True, cwd=ROOT)
                return p.stdout.strip() if p.returncode == 0 else ""

            pin_tree, head_tree = tree_of(f"{pkg_sha}:qeli"), tree_of("HEAD:qeli")
            if not pin_tree:
                failures.append(
                    f"qeli-openwrt/Makefile: PKG_SOURCE_VERSION pins {pkg_sha[:8]}, which this "
                    f"repository does not contain — the package would build an unknown tree"
                )
            elif not head_tree:
                failures.append("cannot read HEAD:qeli — refusing to skip the OpenWrt pin comparison")
            elif pin_tree != head_tree:
                failures.append(
                    f"qeli-openwrt/Makefile: PKG_SOURCE_VERSION pins {pkg_sha[:8]}, whose qeli/ "
                    f"tree ({pin_tree[:8]}) is not the one being released ({head_tree[:8]}) — "
                    f"the router package would build different sources"
                )
            else:
                print(f"  pin {pkg_sha[:8]} != HEAD {head[:8]}, but its qeli/ tree matches "
                      f"({pin_tree[:8]}) — the package builds the released sources")

        # The version in the feed Makefile has to name the release it ships.
        crate_ver = None
        try:
            with open(os.path.join(ROOT, "qeli", "Cargo.toml"), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("version"):
                        crate_ver = line.split("=", 1)[1].strip().strip('"')
                        break
        except OSError:
            pass
        if crate_ver and pkg_ver != crate_ver:
            failures.append(
                f"qeli-openwrt/Makefile: PKG_VERSION={pkg_ver} but the crate is {crate_ver}"
            )
except OSError as e:
    failures.append(f"qeli-openwrt/Makefile unreadable: {e}")
    print(f"  ! {e}")

# ── verdict ──────────────────────────────────────────────────────────────────
print("\n===== PREFLIGHT =====")
if failures:
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("PASS — safe to release")
