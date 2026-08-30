#!/usr/bin/env python3
"""Contract tests for the tiered UDP roaming resource soak matrix."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("roaming_udp_resource_soak_netns_gate.sh")
RUNNER = "roaming_udp_netns_e2e.sh"
STUB = """#!/bin/sh
set -eu
printf '%s %s %s %s\\n' \
  "$QELI_ROAMING_UDP_WIRE_MODE" \
  "$QELI_ROAMING_SOAK_ITERATIONS" \
  "$QELI_ROAMING_SOAK_SAMPLE_EVERY" \
  "$*" >>"$QELI_TEST_TRACE"
if [ "${QELI_TEST_FAIL_MODE:-}" = "$QELI_ROAMING_UDP_WIRE_MODE" ]; then
  exit 23
fi
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("sha256sum"), "bash tools required")
class RoamingUdpResourceSoakGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tempdir.name)
        shutil.copy2(SCRIPT, self.work / SCRIPT.name)
        runner = self.work / RUNNER
        runner.write_text(STUB, encoding="utf-8", newline="\n")
        runner.chmod(0o755)
        self.binary = self.work / "qeli"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        self.binary.chmod(0o755)
        self.trace = self.work / "trace.txt"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_gate(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({"QELI_TEST_TRACE": str(self.trace), **extra_env})
        return subprocess.run(
            ["bash", str(self.work / SCRIPT.name), str(self.binary)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def trace_lines(self) -> list[str]:
        return self.trace.read_text(encoding="utf-8").splitlines() if self.trace.exists() else []

    def test_defaults_use_one_representative_10k_and_three_adapter_1k_runs(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.trace_lines(),
            [
                f"quic 10000 100 {self.binary} soak",
                f"fake-tls 1000 100 {self.binary} soak",
                f"obfs 1000 100 {self.binary} soak",
                f"obfs-awg 1000 100 {self.binary} soak",
            ],
        )
        self.assertIn("ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS", result.stdout)

    def test_iteration_overrides_are_forwarded(self) -> None:
        result = self.run_gate(
            QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS="17",
            QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS="3",
            QELI_ROAMING_SOAK_SAMPLE_EVERY="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([line.split()[1:3] for line in self.trace_lines()], [["17", "1"], ["3", "1"], ["3", "1"], ["3", "1"]])

    def test_failure_stops_later_modes(self) -> None:
        result = self.run_gate(QELI_TEST_FAIL_MODE="obfs")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual([line.split()[0] for line in self.trace_lines()], ["quic", "fake-tls", "obfs"])
        self.assertNotIn("ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS", result.stdout)

    def test_rejects_invalid_iteration_count(self) -> None:
        result = self.run_gate(QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS="0")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(self.trace_lines(), [])


if __name__ == "__main__":
    unittest.main()
