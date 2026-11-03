#!/usr/bin/env python3
"""Isolated worker admission, SIGKILL, deleted-profile and startup-error regression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
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
routing.nat.enabled = true
routing.nat.interface = wan0
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = printf up >> {root / name / 'up'}
routing.post_down = {post_down}
dns.enabled = true
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

    try:
        first = launch("first", config("first", 0))
        record("first worker starts", wait_for(lambda: ready("first") or first.poll() is not None) and ready("first"), (root / "first/worker.log").read_text()[-4000:])
        active = firewall()
        first_rules = [line for line in active["iptables-save"] if "qeli-nat:first" in line]
        record("first owns NAT and both DNS INPUT/REDIRECT transports",
               len([line for line in first_rules if line.startswith("-A INPUT ")]) == 2 and
               len([line for line in first_rules if line.startswith("-A PREROUTING ")]) == 2 and
               any("MASQUERADE" in line for line in first_rules))
        usage = configdir / "usage.json"
        usage_before = usage.read_bytes() if usage.exists() else None
        second = launch("second", config("second", 1), nested=True)
        wait_for(lambda: second.poll() is not None or ready("second"), 15)
        after_second = firewall()
        (root / "firewall-admission.json").write_text(json.dumps(dict(before=active, after=after_second), indent=2))
        log = (root / "second/worker.log").read_text()
        record("different control/state paths and PID/mount namespaces cannot bypass admission",
               second.poll() not in (None, 0) and "server worker network namespace already owned" in log,
               log[-4000:])
        record("rejected worker preserves first firewall", after_second == active)
        record("rejected worker never reaches hook or control bind",
               not (root / "second/up").exists() and not (root / "second/run").exists())
        record("rejected worker preserves accounting", (usage.read_bytes() if usage.exists() else None) == usage_before)
        record("first worker remains responsive", run([str(binary), "list-clients", "--socket",
               str(root / "first/run/control.sock")], False).returncode == 0)
        first.kill()
        first.wait(timeout=5)
        record("SIGKILL releases original TUN", wait_for(lambda: run(["ip", "link", "show", "qrec0"], False).returncode != 0))
        crashed = firewall()
        record("SIGKILL leaves rules for recovery", any("qeli-nat:first" in line for line in crashed["iptables-save"]))
        record("SIGKILL leaves sysctl journal", (state / "sysctls.state").is_file())
        # The current config has no first profile. Recovery must not depend on that name being present.
        (configdir / "first.conf").unlink()
        recovered = launch("recovered", config("recovered", 2))
        record("new worker starts after SIGKILL", wait_for(lambda: ready("recovered") or recovered.poll() is not None) and ready("recovered"), (root / "recovered/worker.log").read_text()[-4000:])
        recovered_rules = firewall()
        record("deleted profile rules are removed", all("qeli-nat:first" not in line for lines in recovered_rules.values() for line in lines))
        record("recovery preserves foreign rules", all(any("operator-kept" in line for line in lines) for lines in recovered_rules.values()))
        recovered.send_signal(signal.SIGTERM)
        record("shutdown reaches post_down before releasing worker", wait_for(lambda: (root / "recovered/down").exists(), 10))
        stopping = launch("stopping", config("stopping", 4))
        exited = wait_for(lambda: stopping.poll() is not None, 2)
        record("post_down retains namespace reservation", exited and stopping.returncode != 0 and
               "server worker network namespace already owned" in (root / "stopping/worker.log").read_text())
        recovered.wait(timeout=15)
        record("recovered worker stops cleanly", recovered.returncode == 0)
        final = firewall()
        record("clean stop removes all owned rules", all("qeli-nat:" not in line for lines in final.values() for line in lines))
        record("clean stop restores forwarding and journal", Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "0" and not (state / "sysctls.state").exists())
        # This error occurs after namespace admission but before control/accounting/network setup.
        (configdir / "bad-users.conf").write_text("[user:broken]\npassword_hash = malformed\nmax_sessions = broken\n")
        bad = launch("error", config("error", 3, "/etc/qeli/bad-users.conf"))
        record("post-admission startup error exits", wait_for(lambda: bad.poll() is not None, 10) and bad.returncode != 0)
        retry = launch("error", config("error", 3))
        record("startup error releases namespace reservation", wait_for(lambda: ready("error") or retry.poll() is not None) and ready("error"), (root / "error/worker.log").read_text()[-4000:])
        stop(retry)
        record("retry worker stops cleanly", retry.returncode == 0)
        record("foreign rules survive all recovery stages", all(any("operator-kept" in line for line in lines) for lines in firewall().values()))
    finally:
        for process in reversed(processes):
            stop(process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
