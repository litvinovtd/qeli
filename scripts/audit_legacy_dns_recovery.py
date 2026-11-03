#!/usr/bin/env python3
"""Exercise legacy DNS startup refusal in fresh Linux net/mount/PID namespaces.

Requires root, unshare, mount, ip and a built Qeli worker. Never uses the host resolver,
state, /run or /var/log: every client runs after private mounts are installed.
Artifacts are retained. Baseline failures are intentional; exit 1 means checks failed.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

CASES = ["none", "file", "absent", "symlink-snapshot", "unknown-original",
         "malformed", "holder-only", "live-holder", "locked-holder", "dangling-backup",
         "fifo-backup", "directory-backup"]


def snapshot(path):
    try:
        md = path.lstat()
    except FileNotFoundError:
        return None
    result = {"mode": stat.S_IMODE(md.st_mode), "type": stat.S_IFMT(md.st_mode),
              "inode": md.st_ino, "size": md.st_size}
    if stat.S_ISLNK(md.st_mode):
        result["target"] = os.readlink(path)
    elif stat.S_ISREG(md.st_mode):
        result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def child(args):
    work = args.output.resolve()
    # These mounts are only executed after the parent entered all three namespaces.
    assert os.readlink("/proc/self/ns/mnt") != args.parent_mount
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    for name, target in [("etc", "/etc"), ("state", "/var/lib"), ("run", "/run"), ("log", "/var/log")]:
        source = work/name
        source.mkdir(mode=0o700)
        subprocess.run(["mount", "--bind", str(source), target], check=True)
    Path("/var/lib/qeli").mkdir(mode=0o700)
    Path("/var/log/qeli").mkdir(mode=0o700)
    Path("/etc/qeli").mkdir(mode=0o700)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    resolv = Path("/etc/resolv.conf")
    resolv.write_text("# managed by the administrator\nnameserver 192.0.2.53\n")
    backup = Path("/var/lib/qeli/dns-backup.json")
    holders = backup.with_name("dns-holders")
    lock = backup.with_name("dns-holders.lock")
    payloads = {
        "file": {"kind": "file", "content": "nameserver 198.51.100.53\n", "mode": 420},
        "absent": {"kind": "absent"},
        "symlink-snapshot": {"kind": "symlink", "target": "unrelated-resolver"},
        "unknown-original": {"kind": "managed-no-original"},
        "live-holder": {"kind": "file", "content": "nameserver 198.51.100.53\n"},
        "locked-holder": {"kind": "file", "content": "nameserver 198.51.100.53\n"},
    }
    if args.case in payloads:
        backup.write_text(json.dumps(payloads[args.case])); backup.chmod(0o600)
    if args.case == "malformed":
        backup.write_bytes(b"{truncated"); backup.chmod(0o600)
    if args.case == "holder-only":
        holders.write_text("2147483647\n"); holders.chmod(0o600)
    if args.case == "live-holder":
        holders.write_text(str(os.getpid())+"\n"); holders.chmod(0o600)
    held = None
    if args.case == "locked-holder":
        held = lock.open("w"); lock.chmod(0o600); fcntl.flock(held, fcntl.LOCK_EX)
    if args.case == "dangling-backup":
        backup.symlink_to("missing-snapshot")
    if args.case == "fifo-backup":
        os.mkfifo(backup, 0o600)
    if args.case == "directory-backup":
        backup.mkdir(mode=0o700)
    paths = {"resolver": resolv, "backup": backup, "holders": holders, "holder_lock": lock}
    before = {k: snapshot(v) for k, v in paths.items()}
    conf = work/"client.conf"
    conf.write_text("[qeli]\nserver = 127.0.0.1:9\nproto = tcp\nuser = legacy-audit\n"
                    "pass = legacy-audit-test-password\nmode = fake-tls\ndev = qlegacy0\ndns = off\n")
    env = dict(os.environ, QELI_KNOWN_HOSTS=str(work/"known-hosts"),
               QELI_DEVICE_ID_FILE=str(work/"device-id"))
    start = time.monotonic(); timed_out = False
    with (work/"client.log").open("wb") as out:
        process = subprocess.Popen([str(args.qeli), "client", "-c", str(conf)], env=env,
                                   stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL); rc = process.wait(timeout=3)
    duration = time.monotonic()-start
    after = {k: snapshot(v) for k, v in paths.items()}
    log = (work/"client.log").read_text(errors="replace")
    checks = {"resolver_preserved": before["resolver"] == after["resolver"],
              "legacy_evidence_preserved": all(before[k] == after[k] for k in ["backup", "holders", "holder_lock"])}
    if args.case == "none":
        checks["ordinary_start_reaches_connection"] = "127.0.0.1:9" in log and "legacy global DNS state" not in log
    else:
        checks["explicit_refusal"] = "legacy global DNS state" in log and "administrator recovery" in log and rc != 0
        checks["startup_refuses_promptly"] = not timed_out
    result = dict(case=args.case, checks=checks, before=before, after=after,
                  exit_code=rc, timed_out=timed_out, seconds=round(duration, 3))
    (work/"result.json").write_text(json.dumps(result, indent=2)+"\n")
    if held:
        held.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qeli", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--parent-mount")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("requires Linux root for private namespaces")
    args.qeli = args.qeli.resolve(strict=True); args.output = args.output.resolve()
    if args.case:
        return child(args)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    for case in CASES:
        directory = args.output/case; directory.mkdir(mode=0o700)
        command = ["unshare", "--net", "--mount", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
                   sys.executable, str(Path(__file__).resolve()), str(args.qeli), str(directory),
                   "--case", case, "--parent-mount", os.readlink("/proc/self/ns/mnt")]
        subprocess.run(command, check=True, timeout=15)
        result = json.loads((directory/"result.json").read_text()); results.append(result)
        print(case, "PASS" if all(result["checks"].values()) else "FAIL", result["checks"], flush=True)
    passed = sum(sum(row["checks"].values()) for row in results)
    total = sum(len(row["checks"]) for row in results)
    summary = dict(worker_sha256=hashlib.sha256(args.qeli.read_bytes()).hexdigest(), results=results,
                   total=total, passed=passed, failed=total-passed)
    (args.output/"results.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(f"{passed}/{total} checks PASS", flush=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
