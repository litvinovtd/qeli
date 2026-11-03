"""Actual Bash admission checks with controlled children; never creates namespaces."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
HELPER = ROOT / "roaming_soak_parameters.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux Bash required")
class SoakAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.trace = self.work / "trace"
        self.binary = self.work / "qeli with spaces"
        self.binary.write_text("#!/bin/sh\necho 'qeli controlled-fixture'\n")
        self.binary.chmod(0o755)
        self.environment = dict(os.environ, QELI_TEST_TRACE=str(self.trace))
        # The tests must not inherit operator overrides.
        for key in list(self.environment):
            if key.startswith("QELI_ROAMING_"):
                self.environment.pop(key)
        shutil.copy2(HELPER, self.work / HELPER.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_bash(self, args, env=None):
        return subprocess.run(["bash", *map(str, args)], capture_output=True, text=True,
                              env=dict(self.environment, **(env or {})), timeout=15)

    def call(self, *args):
        return self.run_bash(["-c", 'source "$1"; shift; roaming_soak_counts "$@"',
                              "counts-test", self.work / HELPER.name, *args])

    def fixture(self, wrapper):
        shutil.copy2(ROOT / wrapper, self.work / wrapper)
        children = ["roaming_netns_e2e.sh", "roaming_udp_netns_e2e.sh",
                    "roaming_tcp_all_modes_netns_e2e.sh", "roaming_udp_all_modes_netns_e2e.sh",
                    "roaming_udp_resource_soak_netns_gate.sh", "roaming_tcp_perf_netns_gate.sh"]
        stub = ('#!/bin/sh\nset -eu\n'
                'printf "%s %s %s %s\\n" "$(basename "$0")" '
                '"${QELI_ROAMING_SOAK_ITERATIONS:-unset}" '
                '"${QELI_ROAMING_SOAK_SAMPLE_EVERY:-unset}" "$*" >> "$QELI_TEST_TRACE"\n'
                'if [ "${QELI_TEST_CHILD_FAIL:-}" = "$(basename "$0")" ]; then exit 23; fi\n')
        for name in children:
            if name == wrapper:
                continue
            f = self.work / name; f.write_text(stub); f.chmod(0o755)
        return self.work / wrapper

    def test_canonical_boundaries(self):
        for value, sample in (("1", "1"), ("8", "8"), ("100", "10"),
                              ("2147483647", "2147483647")):
            with self.subTest(value=value):
                r = self.call(value, sample)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_noncanonical_and_overflow_refuse(self):
        for value in ("", "0", "00", "000", "08", "0100", "-1", "+1", "1.0",
                      "x", "1:2", " 10", "10\n", "2147483648", "9" * 100):
            with self.subTest(value=value):
                self.assertEqual(self.call(value, "1").returncode, 2)

    def test_bad_sample_and_missing_intermediate_sampling_refuse(self):
        for value in ("0", "00", "08", "-1", "x", "2147483648", "101"):
            with self.subTest(value=value):
                self.assertEqual(self.call("100", value).returncode, 2)

    def test_requested_release_minimum(self):
        self.assertEqual(self.call("99", "1", "100").returncode, 2)
        self.assertEqual(self.call("100", "10", "100").returncode, 0)

    def test_direct_cases_refuse_before_resource_probes(self):
        for transport in ("tcp", "udp"):
            for value in ("00", "08", "2147483648"):
                with self.subTest(transport=transport, value=value):
                    r = self.run_bash(["-c", 'SCRIPT_DIR="$1"; source "$2"; run_' + transport + '_soak_case',
                        "case-test", self.work, ROOT / ("roaming_" + transport + "_netns_soak_case.sh")],
                        {"QELI_ROAMING_SOAK_ITERATIONS": value})
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertNotIn("could not identify", r.stdout + r.stderr)

    def test_parent_runners_refuse_before_mktemp_or_ip(self):
        for name in ("roaming_netns_e2e.sh", "roaming_udp_netns_e2e.sh"):
            shutil.copy2(ROOT / name, self.work / name)
            r = self.run_bash([self.work / name, self.binary, "soak"],
                {"QELI_ROAMING_SOAK_ITERATIONS": "00", "TMPDIR": str(self.work / "not-created")})
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertNotIn("mktemp:", r.stderr)
            self.assertFalse((self.work / "not-created").exists())

    def test_bounded_release_preserves_100_flips(self):
        wrapper = self.fixture("linux_roaming_release_soak.sh")
        r = self.run_bash([wrapper, self.binary, "100"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = self.trace.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(" 100 10 " in line for line in lines))
        self.assertIn("passed 100 flips each", r.stdout)

    def test_bounded_release_rejects_bad_counts_before_children(self):
        wrapper = self.fixture("linux_roaming_release_soak.sh")
        for value in ("99", "00", "0100", "2147483648"):
            with self.subTest(value=value):
                r = self.run_bash([wrapper, self.binary, value])
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertFalse(self.trace.exists())

    def test_bounded_child_failure_cannot_report_pass(self):
        wrapper = self.fixture("linux_roaming_release_soak.sh")
        r = self.run_bash([wrapper, self.binary, "100"],
                         {"QELI_TEST_CHILD_FAIL": "roaming_netns_e2e.sh"})
        self.assertEqual(r.returncode, 23, r.stdout + r.stderr)
        self.assertEqual(len(self.trace.read_text().splitlines()), 1)
        self.assertNotIn("=== RESULT", r.stdout)

    def test_udp_reduced_counts_report_only_smoke(self):
        wrapper = self.fixture("roaming_udp_resource_soak_netns_gate.sh")
        r = self.run_bash([wrapper, self.binary], {
            "QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS": "17",
            "QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS": "3",
            "QELI_ROAMING_SOAK_SAMPLE_EVERY": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SOAK_MATRIX_SMOKE", r.stdout)
        self.assertNotIn("SOAK_PASS", r.stdout)
        self.assertEqual(len(self.trace.read_text().splitlines()), 4)

    def test_udp_defaults_report_full_matrix(self):
        wrapper = self.fixture("roaming_udp_resource_soak_netns_gate.sh")
        r = self.run_bash([wrapper, self.binary])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SOAK_MATRIX_PASS", r.stdout)
        self.assertNotIn("_SMOKE", r.stdout)

    def test_udp_invalid_counts_do_not_start_any_child(self):
        wrapper = self.fixture("roaming_udp_resource_soak_netns_gate.sh")
        for env in ({"QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS": "00"},
                    {"QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS": "08"},
                    {"QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS": "3"},
                    {"QELI_ROAMING_SOAK_SAMPLE_EVERY": "00"}):
            with self.subTest(env=env):
                r = self.run_bash([wrapper, self.binary], env)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertFalse(self.trace.exists())

    def test_endurance_wrapper_rejects_downgrades_before_first_phase(self):
        wrapper = self.fixture("roaming_resource_release_gate.sh")
        for key, value in (("QELI_ROAMING_SOAK_ITERATIONS", "100"),
                           ("QELI_ROAMING_UDP_REPRESENTATIVE_SOAK_ITERATIONS", "100"),
                           ("QELI_ROAMING_UDP_ADAPTER_SOAK_ITERATIONS", "999"),
                           ("QELI_ROAMING_SOAK_SAMPLE_EVERY", "1001")):
            with self.subTest(key=key):
                r = self.run_bash([wrapper, self.binary], {key: value})
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertFalse(self.trace.exists())
                self.assertNotIn("ROAMING_RESOURCE_RELEASE_GATE_PASS", r.stdout)

    def test_missing_shared_helper_refuses(self):
        wrapper = self.fixture("linux_roaming_release_soak.sh")
        (self.work / HELPER.name).unlink()
        r = self.run_bash([wrapper, self.binary, "100"])
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main()
