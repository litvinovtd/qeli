#!/usr/bin/env python3
"""Contract tests for the fail-closed roaming resource release orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("roaming_resource_release_gate.sh")
CHILDREN = (
    "roaming_tcp_all_modes_netns_e2e.sh",
    "roaming_udp_all_modes_netns_e2e.sh",
    "roaming_netns_e2e.sh",
    "roaming_tcp_perf_netns_gate.sh",
)
STUB = """#!/bin/sh
set -eu
name=$(basename "$0")
printf '%s %s\\n' "$name" "$*" >>"$QELI_TEST_TRACE"
if [ "${QELI_TEST_MUTATE_ON:-}" = "$name" ]; then
  printf x >>"$QELI_TEST_BIN"
fi
if [ "${QELI_TEST_FAIL_ON:-}" = "$name" ]; then
  exit 19
fi
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("sha256sum"), "bash tools required")
class RoamingResourceReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tempdir.name)
        shutil.copy2(SCRIPT, self.work / SCRIPT.name)
        for name in CHILDREN:
            child = self.work / name
            child.write_text(STUB, encoding="utf-8", newline="\n")
            child.chmod(0o755)
        self.binary = self.work / "qeli"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        self.binary.chmod(0o755)
        self.trace = self.work / "trace.txt"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_gate(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "QELI_TEST_TRACE": str(self.trace),
                "QELI_TEST_BIN": str(self.binary),
                **extra_env,
            }
        )
        return subprocess.run(
            ["bash", str(self.work / SCRIPT.name), str(self.binary)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def trace_lines(self) -> list[str]:
        return self.trace.read_text(encoding="utf-8").splitlines() if self.trace.exists() else []

    def test_runs_every_phase_in_release_order(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [line.split()[0] for line in self.trace_lines()],
            [
                "roaming_tcp_all_modes_netns_e2e.sh",
                "roaming_udp_all_modes_netns_e2e.sh",
                "roaming_netns_e2e.sh",
                "roaming_udp_all_modes_netns_e2e.sh",
                "roaming_tcp_perf_netns_gate.sh",
                "roaming_netns_e2e.sh",
            ],
        )
        self.assertIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", result.stdout)

    def test_child_failure_prevents_every_later_phase(self) -> None:
        result = self.run_gate(QELI_TEST_FAIL_ON="roaming_tcp_perf_netns_gate.sh")
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 5)
        self.assertNotIn("ROAMING_RELEASE_TCP_PERF_PASS", result.stdout)
        self.assertNotIn("ROAMING_RELEASE_TCP_MULTINODE_PASS", result.stdout)

    def test_binary_mutation_is_detected_before_next_phase(self) -> None:
        result = self.run_gate(QELI_TEST_MUTATE_ON="roaming_tcp_all_modes_netns_e2e.sh")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 1)
        self.assertIn("qeli binary changed before tcp-wire-smoke completion", result.stderr)
        self.assertNotIn("ROAMING_RELEASE_TCP_WIRE_SMOKE_PASS", result.stdout)

    def test_operator_supplied_hash_is_enforced_before_first_phase(self) -> None:
        result = self.run_gate(QELI_ROAMING_RELEASE_SHA256="0" * 64)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.trace_lines(), [])
        self.assertIn("qeli binary hash mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
