#!/usr/bin/env python3
"""Isolated exact firewall recovery when chain enumeration is unavailable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time


def namespace(kind):
    stat = os.stat("/proc/thread-self/ns/" + kind)
    return f"{stat.st_dev}:{stat.st_ino}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qeli", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = Path(args.qeli).resolve(strict=True)
    root = Path(args.artifacts).resolve()
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError("requires root in a disposable Linux lab")
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_RECOVERY_PARENT_NET=namespace("net"),
                   QELI_RECOVERY_PARENT_MNT=namespace("mnt"))
        command = ["unshare", "--net", "--mount", "--pid", "--fork", "--kill-child=KILL",
                   "--mount-proc", sys.executable, str(Path(__file__).resolve()),
                   "--qeli", str(binary), "--artifacts", str(root), "--inside"]
        return subprocess.run(command, env=env, timeout=180).returncode
    if (not os.environ.get("QELI_RECOVERY_PARENT_NET") or
            namespace("net") == os.environ["QELI_RECOVERY_PARENT_NET"] or
            namespace("mnt") == os.environ["QELI_RECOVERY_PARENT_MNT"]):
        raise RuntimeError("fresh network/mount/PID fixture is mandatory")
    commands, processes, results = [], [], []
    artifact_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    def run(argv, check=True):
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=20)
        commands.append(dict(argv=argv, rc=p.returncode, output=p.stdout))
        (root / "commands.json").write_text(json.dumps(commands, indent=2))
        if check and p.returncode:
            raise RuntimeError(f"{argv}: {p.returncode}: {p.stdout}")
        return p

    def record(name, condition, message=""):
        results.append(dict(name=name, passed=bool(condition), detail=message))
        (root / "results.json").write_text(json.dumps(dict(
            artifact=str(binary), artifact_sha256=artifact_sha256,
            network=namespace("net"), results=results), indent=2))
        if not condition:
            raise AssertionError(name + ": " + message)
        print(name, "PASS", flush=True)

    def wait_for(predicate, seconds=25):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return True
            time.sleep(.05)
        return False

    def ready(name):
        return (root / name / "up").exists() and f"Profile '{name}' listening on" in (root / name / "worker.log").read_text()

    def firewall():
        return {tool: [line for line in run([tool]).stdout.splitlines()
                       if line.startswith(("-A ", "-P ", ":"))]
                for tool in ["iptables-save", "ip6tables-save"]}

    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    run(["mount", "--make-rprivate", "/"])
    for mountpoint in ["/run", "/var/lib", "/var/log"]:
        run(["mount", "-t", "tmpfs", "tmpfs", mountpoint])
    for path in ["/var/lib/qeli", "/var/log/qeli"]:
        Path(path).mkdir(mode=0o700)
    configdir = root / "etc-qeli"
    configdir.mkdir(mode=0o700)
    if not Path("/etc/qeli").is_dir():
        raise RuntimeError("existing /etc/qeli mount point required")
    run(["mount", "--bind", str(configdir), "/etc/qeli"])
    run(["ip", "link", "set", "lo", "up"])
    run(["ip", "link", "add", "wan0", "type", "dummy"])
    run(["ip", "link", "set", "wan0", "up"])
    run(["ip", "addr", "add", "192.0.2.1/24", "dev", "wan0"])
    Path("/proc/sys/net/ipv4/ip_forward").write_text("0")
    (configdir / "users.conf").write_text("")
    state = root / "state"
    state.mkdir(mode=0o700)
    for name in ["first", "second", "recovered", "error", "stopping"]:
        (root / name).mkdir(mode=0o700)
    foreign = ["-A", "FORWARD", "-m", "comment", "--comment", "operator-kept", "-j", "ACCEPT"]
    run(["iptables", *foreign])
    run(["ip6tables", *foreign])

    def config(name, number, users="/etc/qeli/users.conf"):
        path = configdir / (name + ".conf")
        post_down = f"printf down > {root / name / 'down'}; sleep 3" if name == "recovered" else ""
        path.write_text(f"""[auth]
users_file = {users}
[web]
enabled = false
[logging]
level = debug
[profile:{name}]
identity_key = /etc/qeli/{name}.key
bind.address = 127.0.0.1
bind.port = {24443 + number}
bind.transport = tcp
tun.name = qrec{number}
tun.address = 10.{74 + number}.0.1
tun.ip_mode = ipv4
tun.queues = 1
pool.cidr = 10.{74 + number}.0.0/24
routing.nat.enabled = {'true' if name == 'first' else 'false'}
routing.nat.interface = wan0
routing.forward_private = {'true' if name == 'first' else 'false'}
routing.ipv6.mode = off
routing.post_up = printf up >> {root / name / 'up'}
routing.post_down = {post_down}
dns.enabled = {'true' if name == 'first' else 'false'}
dns.listen = 10.{74 + number}.0.1
dns.port = 1053
obf.mode = fake-tls
""")
        path.chmod(0o600)
        return path

    def launch(name, path, nested=False):
        runtime = root / name / "run"
        owner_state = state
        if nested:
            owner_state = root / name / "state"
            owner_state.mkdir(mode=0o700)
        env = dict(os.environ, STATE_DIRECTORY=str(owner_state),
                   QELI_CONTROL_SOCKET=str(runtime / "control.sock"))
        cmd = [str(binary), "_worker", "-c", str(path)]
        if nested:
            # A different mount/PID namespace still shares this network namespace.
            cmd = ["unshare", "--mount", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", *cmd]
        with (root / name / "worker.log").open("w") as log:
            process = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        processes.append(process)
        return process

    # Copy the nft multi-call executable before overlaying it in this private mount namespace.
    multi = Path(shutil.which("iptables")).resolve(strict=True)
    if "xtables" not in multi.name:
        raise RuntimeError("iptables multi-call fixture required")
    real = root / "xtables-real"
    shutil.copy2(multi, real)
    wrapper = root / "iptables-wrapper"
    wrapper.write_text("#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n"
        + f"root=Path({str(root)!r})\n"
        + "args=sys.argv[1:]\n"
        + "with (root/'firewall-calls.log').open('a') as f:f.write(repr(sys.argv)+'\\n')\n"
        + "if '-S' in args and (root/'deny-list').exists():\n print('injected incompatible nft listing',file=sys.stderr);sys.exit(4)\n"
        + "if '--version' in args and (root/'wrong-backend').exists():\n print(os.path.basename(sys.argv[0])+' v1.8.11 (legacy)');sys.exit(0)\n"
        + "if '-D' in args and (root/'deny-delete').exists():\n print('injected delete denied',file=sys.stderr);sys.exit(4)\n"
        + f"os.execv({str(real)!r},[os.path.basename(sys.argv[0]),*args])\n")
    wrapper.chmod(0o700)
    run(["mount", "--bind", str(wrapper), str(multi)])
    try:
        first = launch("first", config("first", 0))
        record("first worker starts", wait_for(lambda: ready("first") or first.poll() is not None) and ready("first"), (root / "first/worker.log").read_text()[-4000:])
        active = firewall()
        first_rules = [line for line in active["iptables-save"] if "qeli-nat:first" in line]
        record("first owns nine NAT and DNS rules", len(first_rules) == 9)
        journal = state / "server-firewall.state"
        saved = journal.read_bytes() if journal.exists() else None
        first.kill()
        first.wait(timeout=5)
        record("SIGKILL leaves rules for recovery", firewall() == active)
        (configdir / "first.conf").unlink()
        (root / "deny-list").touch()
        recovered = launch("recovered", config("recovered", 2))
        record("new worker starts with listing unavailable", wait_for(lambda: ready("recovered") or recovered.poll() is not None) and ready("recovered"), (root / "recovered/worker.log").read_text()[-4000:])
        recovered_rules = firewall()
        (root / "firewall-recovery.json").write_text(json.dumps(dict(before=active, after=recovered_rules), indent=2))
        record("deleted profile exact rules are removed without listing", all("qeli-nat:first" not in line for lines in recovered_rules.values() for line in lines))
        record("recovery preserves foreign rules", all(any("operator-kept" in line for line in lines) for lines in recovered_rules.values()))
        stop(recovered)
        record("recovered worker stops cleanly", recovered.returncode == 0)
        record("clean stop restores forwarding", Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "0")
        record("nine exact specifications were durable before SIGKILL", saved is not None and
               sum(len(group["rules"]) for group in json.loads(saved)["namespaces"].values()) == 9)
        record("successful recovery retires exact evidence", not json.loads(journal.read_bytes())["namespaces"])
        record("journal permissions stay private", journal.stat().st_mode & 0o777 == 0o600)
        record("stable lock sidecar remains", (state / "server-firewall.state.lock").is_file())
        # Repeat the crash, then require explicit failure for unresolved deletion and backend drift.
        (root / "deny-list").unlink()
        again = launch("first", config("first", 0))
        record("second NAT generation starts", wait_for(lambda: ready("first") or again.poll() is not None) and ready("first"))
        before_failure = firewall()
        pending = journal.read_bytes()
        again.kill()
        again.wait(timeout=5)
        (configdir / "first.conf").unlink()
        (root / "deny-list").touch()
        for marker, diagnostic in [("deny-delete", "exact server firewall recovery"),
                                   ("wrong-backend", "iptables backend changed")]:
            (root / marker).touch()
            failed = launch("error", config("error", 3))
            record(marker + " aborts worker startup", wait_for(lambda: failed.poll() is not None, 15) and failed.returncode != 0 and
                   diagnostic in (root / "error/worker.log").read_text())
            record(marker + " preserves rules", firewall() == before_failure)
            record(marker + " retains exact journal", json.loads(journal.read_bytes()) == json.loads(pending))
            record(marker + " never reaches profile hook", not (root / "error/up").exists())
            (root / marker).unlink()
        journal.write_bytes(b"corrupt journal")
        failed = launch("error", config("error", 3))
        record("corrupt journal refuses recovery", wait_for(lambda: failed.poll() is not None, 15) and failed.returncode != 0)
        record("corrupt journal preserves firewall and evidence", firewall() == before_failure and journal.read_bytes() == b"corrupt journal")
        journal.write_bytes(pending)
        last = launch("recovered", config("recovered", 2))
        record("retry after failure recovers without listing", wait_for(lambda: ready("recovered") or last.poll() is not None) and ready("recovered"))
        record("retry removes all pending exact rules", all("qeli-nat:" not in line for lines in firewall().values() for line in lines))
        stop(last)
        record("final journal is empty", last.returncode == 0 and not json.loads(journal.read_bytes())["namespaces"])
        record("operator rules survive every failure", all(any("operator-kept" in line for line in lines) for lines in firewall().values()))
    finally:
        for process in reversed(processes):
            stop(process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
