'''Root-only, real Linux kernel tests. Run inside an independently isolated lab.

The caller must supply its parent mnt/net/pid namespace inode strings as
QELI_TEST_PARENT_MNT/NET/PID; this suite refuses to create sentinels until all
three identities differ. It is intentionally separate from unprivileged CI.
'''
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def cleanup_body(name):
    source = (ROOT / name).read_text()
    match = re.search(r"cleanup\(\) \{\n.*?\n\}\ntrap cleanup EXIT", source, re.S)
    if not match:
        raise AssertionError("cannot locate exact runner cleanup")
    return match[0].removesuffix("\ntrap cleanup EXIT")


class KernelIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("real kernel isolation tests require root in a private lab")
        for kind in ("mnt", "net", "pid"):
            parent = os.environ.get("QELI_TEST_PARENT_" + kind.upper())
            if not parent or os.readlink("/proc/self/ns/" + kind) == parent:
                raise RuntimeError("refusing kernel fixtures in caller's " + kind + " namespace")
        if "qeli-test-outer" not in Path("/proc/self/mountinfo").read_text():
            raise RuntimeError("independent outer /run mount is required")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="isolation-kernel-", dir=ROOT.parent)
        self.work = Path(self.temp.name)
        self.processes = []
        self.sentinels = []
        for name in ("qrm-cli", "qru-cli"):
            command("ip", "netns", "add", name)
            child = subprocess.Popen(["ip", "netns", "exec", name, "sleep", "120"])
            self.sentinels.append(child)
        command("ip", "link", "add", "qrm-a", "type", "veth", "peer", "name", "qrm-ar")
        self.etc = Path("/etc/netns/qru-cli")
        self.etc.mkdir(parents=True, exist_ok=True)
        (self.etc / "hosts").write_text("127.0.0.1 outer-sentinel\n")
        self.outer = self.snapshot()
        variables = r'''CLI_NS=qrm-cli
RTR_NS=qrm-rtr
SRV_NS=qrm-srv
SECONDARY_SRV_NS=qrm-srv-secondary
SERVER_JOB_PID=
SECONDARY_SERVER_JOB_PID=
CLIENT_JOB_PID=
TARGET_JOB_PID=
LOAD_JOB_PID=
FAULT_JOB_PID=
PING_PID=
DRAIN_UP_PID=
DRAIN_DOWN_PID=
NETNS_ETC=
'''
        self.fixture = self.work / "fixture with spaces.sh"
        self.fixture.write_text('''#!/bin/bash
set -u
source "''' + str(ROOT / "roaming_netns_isolation.sh") + '''" || exit 2
roaming_netns_isolate "${BASH_SOURCE[0]}" "$@" || exit 2
set -e
mode=$1
out=$2
python3 -B -c 'import socket,sys,time;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen();Path(sys.argv[2]).write_text(sys.argv[1]);time.sleep(120)' "$ROAMING_CONTROL_SOCKET" "$out/socket-ready" &
for i in $(seq 1 100); do
  if [ -f "$out/socket-ready" ]; then break; fi
  sleep 0.02
done
test -f "$out/socket-ready"
test "$(stat -c %a /run/qeli-roaming-control)" = 700
ip netns add qrm-cli
ip netns add qru-cli
ip link add qrm-a type veth peer name qrm-ar
ip link set qrm-a netns qrm-cli
ip link set qrm-ar netns qru-cli
mkdir -p /etc/netns/qru-cli
printf '127.0.0.1 private-%s\n' "$mode" > /etc/netns/qru-cli/hosts
ip netns exec qru-cli grep -q "private-$mode" /etc/hosts
ip netns exec qrm-cli sleep 120 &
sleeper=$!
python3 -B -c 'import json,os,sys;from pathlib import Path;Path(sys.argv[1]).write_text(json.dumps(dict(ids={k:os.readlink("/proc/self/ns/"+k) for k in ("mnt","net","pid")},args=sys.argv[2:],cwd=os.getcwd())))' "$out/ready" "$@"
''' + variables + cleanup_body("roaming_netns_e2e.sh") + '''
if [ "$mode" = tcp-cleanup ]; then cleanup || :; exit 37; fi
CLI_NS=qru-cli
RTR_NS=qru-rtr
SRV_NS=qru-srv
''' + cleanup_body("roaming_udp_netns_e2e.sh") + '''
if [ "$mode" = udp-cleanup ]; then cleanup || :; exit 0; fi
for i in $(seq 1 200); do
  if [ -f "$out/finish" ]; then exit 0; fi
  sleep 0.05
done
exit 38
''')

    def snapshot(self):
        return dict(names=command("ip", "netns", "list"), links=command("ip", "-j", "link"),
                    hosts=(self.etc / "hosts").read_text(),
                    live=[p.poll() for p in self.sentinels])

    def assert_outer_unchanged(self):
        self.assertEqual(self.snapshot(), self.outer)

    def start(self, mode, *extra, env=None):
        out = self.work / mode
        out.mkdir()
        p = subprocess.Popen(["bash", str(self.fixture), mode, str(out), *extra],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=dict(os.environ, **(env or {})))
        self.processes.append(p)
        until = time.monotonic() + 8
        while time.monotonic() < until:
            if (out / "ready").exists():
                try:
                    ready = json.loads((out / "ready").read_text())
                except json.JSONDecodeError:
                    continue
                print(json.dumps(dict(mode=mode, ready=ready)), flush=True)
                return p, out, ready
            if p.poll() is not None:
                self.fail(str(p.communicate()))
            time.sleep(0.02)
        self.fail("private fixture failed to become ready")

    def wait(self, p, expected):
        stdout, stderr = p.communicate(timeout=8)
        self.assertEqual(p.returncode, expected, stdout + stderr)

    def namespace_processes(self, inode):
        found = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if os.readlink(proc / "ns/pid") == inode:
                    found.append(int(proc.name))
            except OSError:
                pass
        return found

    def test_actual_cleanup_preserves_existing_names_processes_hosts_and_exit_status(self):
        for mode, expected in (("tcp-cleanup", 37), ("udp-cleanup", 0)):
            p, out, ready = self.start(mode)
            self.wait(p, expected)
            self.assertEqual(self.namespace_processes(ready["ids"]["pid"]), [])
            self.assert_outer_unchanged()

    def test_parallel_identical_names_have_distinct_namespaces(self):
        one, out1, first = self.start("one")
        two, out2, second = self.start("two")
        self.assertEqual((out1 / "socket-ready").read_text(), "/run/qeli-roaming-control/control.sock")
        self.assertEqual((out2 / "socket-ready").read_text(), (out1 / "socket-ready").read_text())
        for kind in ("mnt", "net", "pid"):
            self.assertNotEqual(first["ids"][kind], second["ids"][kind])
            self.assertNotEqual(first["ids"][kind], os.readlink("/proc/self/ns/" + kind))
        (out1 / "finish").touch()
        self.wait(one, 0)
        self.assertIsNone(two.poll())
        self.assertTrue(self.namespace_processes(second["ids"]["pid"]))
        self.assertEqual(self.namespace_processes(first["ids"]["pid"]), [])
        (out2 / "finish").touch()
        self.wait(two, 0)
        self.assert_outer_unchanged()

    def test_supervisor_sigterm_removes_descendants(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                p, out, ready = self.start("interrupt-" + str(signum))
                self.assertTrue(self.namespace_processes(ready["ids"]["pid"]))
                p.send_signal(signum)
                stdout, stderr = p.communicate(timeout=8)
                self.assertEqual(p.returncode, 128 + signum, stdout + stderr)
                self.assertEqual(self.namespace_processes(ready["ids"]["pid"]), [])
                self.assert_outer_unchanged()

    def test_supervisor_sigkill_removes_descendants(self):
        p, out, ready = self.start("hard-interrupt")
        self.assertTrue(self.namespace_processes(ready["ids"]["pid"]))
        p.kill()
        stdout, stderr = p.communicate(timeout=8)
        self.assertNotEqual(p.returncode, 0, stdout + stderr)
        deadline = time.monotonic() + 3
        while self.namespace_processes(ready["ids"]["pid"]) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.namespace_processes(ready["ids"]["pid"]), [])
        self.assert_outer_unchanged()

    def test_args_environment_and_working_directory_survive(self):
        p, out, ready = self.start("args", "binary with spaces", "literal;$(no-command)",
                                 env={"QELI_ROAMING_ISOLATED_NAMESPACES": "true"})
        self.assertEqual(ready["args"], ["args", str(out), "binary with spaces", "literal;$(no-command)"])
        self.assertEqual(ready["cwd"], os.getcwd())
        (out / "finish").touch()
        self.wait(p, 0)
        self.assert_outer_unchanged()

    def test_kernel_permission_failure_refuses_before_payload(self):
        out = self.work / "permission"
        out.mkdir()
        r = subprocess.run(["setpriv", "--bounding-set=-sys_admin", "bash", str(self.fixture),
                            "permission", str(out)], text=True, capture_output=True, timeout=8)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((out / "ready").exists())
        self.assert_outer_unchanged()

    def test_overlay_mount_failure_refuses_before_payload(self):
        commands = self.work / "commands"
        commands.mkdir()
        mount = commands / "mount"
        mount.write_text('#!/bin/bash\nif [ "${2:-}" = overlay ]; then exit 17; fi\nexec /usr/bin/mount "$@"\n')
        mount.chmod(0o755)
        out = self.work / "mount-failure"
        out.mkdir()
        r = subprocess.run(["bash", str(self.fixture), "mount-failure", str(out)],
                           env=dict(os.environ, PATH=str(commands) + ":" + os.environ["PATH"]),
                           text=True, capture_output=True, timeout=8)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse((out / "ready").exists())
        self.assert_outer_unchanged()

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None:
                p.kill()
            p.communicate(timeout=8)
        for p in self.sentinels:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=8)
        for name in ("qrm-cli", "qru-cli"):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)
        subprocess.run(["ip", "link", "del", "qrm-a"], capture_output=True)
        (self.etc / "hosts").unlink(missing_ok=True)
        self.etc.rmdir()
        self.temp.cleanup()
