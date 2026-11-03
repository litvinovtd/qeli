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
    "roaming_udp_resource_soak_netns_gate.sh",
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
if [ "${QELI_TEST_SILENT_SUCCESS:-}" = 1 ]; then
  exit 0
fi
case "$name" in
  roaming_tcp_all_modes_netns_e2e.sh)
    echo 'TCP roaming transport-mode matrix (success): 6 passed, 0 failed' ;;
  roaming_udp_all_modes_netns_e2e.sh)
    echo 'UDP roaming transport-mode matrix (success): 4 passed, 0 failed' ;;
  roaming_netns_e2e.sh)
    case "$2" in
      resume|grace-expiry|multinode)
        echo "=== RESULT (fake-tls/$2/tun/single): 1 passed, 0 failed ===" ;;
      soak)
        if [ "${QELI_TEST_MISSING_CHECKPOINT:-}" != 1 ]; then
          n=${QELI_ROAMING_SOAK_ITERATIONS:-10000}
          echo "  TCP soak progress $n/$n target=test"
        fi
        echo '=== RESULT (fake-tls/soak/tun/single): 1 passed, 0 failed ===' ;;
    esac ;;
  roaming_udp_resource_soak_netns_gate.sh)
    rep=${QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS:-10000}
    adapter=${QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS:-1000}
    echo "  soak progress $rep/$rep target=test"
    for mode in FAKE_TLS OBFS OBFS_AWG; do
      echo "  soak progress $adapter/$adapter target=test"
      echo "ROAMING_UDP_${mode}_ADAPTER_SOAK_PASS"
    done
    echo ROAMING_UDP_QUIC_REPRESENTATIVE_SOAK_PASS
    echo ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS ;;
  roaming_tcp_perf_netns_gate.sh)
    echo '=== RESULT: 1 passed, 0 failed ===' ;;
esac
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("sha256sum"), "bash tools required")
class RoamingResourceReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tempdir.name)
        shutil.copy2(SCRIPT, self.work / SCRIPT.name)
        shutil.copy2(SCRIPT.with_name("roaming_soak_parameters.sh"), self.work / "roaming_soak_parameters.sh")
        for name in CHILDREN:
            child = self.work / name
            child.write_text(STUB, encoding="utf-8", newline="\n")
            child.chmod(0o755)
        self.binary = self.work / "qeli"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        self.binary.chmod(0o755)
        self.trace = self.work / "trace.txt"
        self.clock_dir = self.work / "clock-bin"
        self.clock_dir.mkdir()
        clock = self.clock_dir / "python3"
        clock.write_text("#!/bin/sh\nset -eu\n"
                         "if [ ! -e \"$QELI_TEST_CLOCK_STATE\" ]; then\n"
                         "  : >\"$QELI_TEST_CLOCK_STATE\"\n"
                         "  echo 1000000000000\n"
                         "else\n"
                         "  echo \"$QELI_TEST_CLOCK_END_NS\"\n"
                         "fi\n", encoding="utf-8", newline="\n")
        clock.chmod(0o755)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_gate(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "QELI_TEST_TRACE": str(self.trace),
                "QELI_TEST_BIN": str(self.binary),
                "QELI_TEST_CLOCK_STATE": str(self.work / "clock-state"),
                "QELI_TEST_CLOCK_END_NS": "29800000000000",
                "PATH": str(self.clock_dir) + os.pathsep + os.environ.get("PATH", ""),
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
        trace = [line.split() for line in self.trace_lines()]
        self.assertEqual(
            [(parts[0], parts[2:]) for parts in trace],
            [
                ("roaming_tcp_all_modes_netns_e2e.sh", ["success"]),
                ("roaming_udp_all_modes_netns_e2e.sh", ["success"]),
                ("roaming_netns_e2e.sh", ["resume", "fake-tls"]),
                ("roaming_netns_e2e.sh", ["grace-expiry", "fake-tls"]),
                ("roaming_netns_e2e.sh", ["soak", "fake-tls"]),
                ("roaming_udp_resource_soak_netns_gate.sh", []),
                ("roaming_tcp_perf_netns_gate.sh", ["fake-tls"]),
                ("roaming_netns_e2e.sh", ["multinode", "fake-tls"]),
            ],
        )
        self.assertIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", result.stdout)
        self.assertIn("ROAMING_RESOURCE_RELEASE_ELAPSED_SECONDS=28800", result.stdout)

    def test_silent_successful_child_cannot_claim_a_release_pass(self) -> None:
        result = self.run_gate(QELI_TEST_SILENT_SUCCESS="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 1)
        self.assertIn("without its verified result", result.stderr)
        self.assertNotIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", result.stdout)

    def test_missing_final_flip_checkpoint_cannot_claim_a_release_pass(self) -> None:
        result = self.run_gate(QELI_TEST_MISSING_CHECKPOINT="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 5)
        self.assertIn("lacks its final 10000-flip checkpoint", result.stderr)
        self.assertNotIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", result.stdout)

    def test_under_eight_hours_cannot_claim_a_release_pass(self) -> None:
        result = self.run_gate(QELI_TEST_CLOCK_END_NS="29799999999999")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 8)
        self.assertIn("requires at least 28800 seconds", result.stderr)
        self.assertNotIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", result.stdout)

    def test_child_failure_prevents_every_later_phase(self) -> None:
        result = self.run_gate(QELI_TEST_FAIL_ON="roaming_tcp_perf_netns_gate.sh")
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)
        self.assertEqual(len(self.trace_lines()), 7)
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
