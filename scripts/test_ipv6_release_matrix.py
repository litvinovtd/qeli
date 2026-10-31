import unittest
from pathlib import Path
import subprocess
import sys

import audit_outer_udp_capture as carrier
import release_certification
import run_ipv6_release_matrix as matrix


class Ipv6ReleaseMatrixContractTest(unittest.TestCase):
    def test_case_ids_are_unique_and_required(self):
        ids = matrix.case_ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(set(ids).issubset(release_certification.REQUIRED_CASES))

    def test_full_matrix_covers_every_outer_inner_transport_cell(self):
        parameters = {args for _, args in matrix.MATRIX_CASES}
        for outer in ("4", "6"):
            for inner in ("4", "6"):
                for transport, wire in (
                    ("tcp", "fake-tls"),
                    ("udp", "fake-tls"),
                    ("udp", "quic"),
                ):
                    self.assertIn((outer, inner, transport, wire, "full"), parameters)

    def test_dual_split_has_tcp_and_udp(self):
        parameters = {args for _, args in matrix.MATRIX_CASES}
        self.assertIn(("4", "dual", "tcp", "fake-tls", "split"), parameters)
        self.assertIn(("4", "dual", "udp", "fake-tls", "split"), parameters)

    def test_special_cases_are_required_but_do_not_weaken_base_matrix(self):
        special_ids = [case_id for case_id, _ in matrix.SPECIAL_CASES]
        self.assertEqual(special_ids, ["linux.tap.ndp-ra"])
        self.assertTrue(set(special_ids).issubset(release_certification.REQUIRED_CASES))
        self.assertNotIn("linux.tap.ndp-ra", matrix.case_ids())
        self.assertEqual(
            matrix.SPECIAL_CASES[0][1], ("4", "6", "tcp", "fake-tls", "full", "tap")
        )

    def test_legacy_pair_is_a_required_distinct_gate(self):
        self.assertEqual(matrix.LEGACY_CASE_ID, "linux.legacy-peer")
        self.assertIn(matrix.LEGACY_CASE_ID, release_certification.REQUIRED_CASES)
        self.assertNotIn(matrix.LEGACY_CASE_ID, matrix.case_ids())
        self.assertEqual(matrix.LEGACY_SCRIPT.name, "ipv6_legacy_pair.sh")

    def test_dns_pair_is_a_required_distinct_gate(self):
        self.assertEqual(matrix.DNS_CASE_ID, "linux.dns.ipv4-ipv6")
        self.assertIn(matrix.DNS_CASE_ID, release_certification.REQUIRED_CASES)
        self.assertNotIn(matrix.DNS_CASE_ID, matrix.case_ids())
        self.assertEqual(matrix.DNS_SCRIPT.name, "ipv6_dns_pair.sh")

    def test_mtu_pmtu_ptb_pair_is_a_required_distinct_gate(self):
        self.assertEqual(matrix.MTU_CASE_ID, "linux.mtu.1280-pmtu-ptb")
        self.assertIn(matrix.MTU_CASE_ID, release_certification.REQUIRED_CASES)
        self.assertNotIn(matrix.MTU_CASE_ID, matrix.case_ids())
        self.assertEqual(matrix.MTU_SCRIPT.name, "ipv6_mtu_pair.sh")

    def test_exact_ipv4_mtu_payload_boundary_is_inclusive_but_never_oversize(self):
        self.assertEqual(1252 + 20 + 8, 1280)
        for budget, expected in ((548, False), (549, True), (1251, True),
                                 (1252, True), (1253, False), (65535, False)):
            with self.subTest(budget=budget):
                self.assertEqual(carrier.budget_fits_ipv4_path(budget), expected)
        self.assertFalse(carrier.budget_fits_ipv4_path(1252, 1279))
        self.assertTrue(carrier.budget_fits_ipv4_path(1251, 1279))
        for invalid in (None, "1252", 1252.0, True, -1, 0):
            with self.subTest(invalid=invalid):
                self.assertFalse(carrier.budget_fits_ipv4_path(invalid))

    def test_budget_cli_uses_the_guard_without_opening_a_capture_socket(self):
        for budget, expected in ((548, 1), (1252, 0), (1253, 1)):
            with self.subTest(budget=budget):
                result = subprocess.run([sys.executable, str(Path(carrier.__file__)),
                                         "--validate-budget", str(budget)],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_mtu_pair_mandates_real_wire_capture_for_both_modes(self):
        source = matrix.MTU_SCRIPT.read_text(encoding="utf8")
        for mode in ("pmtu", "mtu"):
            self.assertIn('QELI_PACKET_AUDIT=1 bash "$CASE_SCRIPT" "$BIN" 4 6 udp quic full ' + mode, source)
        case = matrix.CASE_SCRIPT.read_text(encoding="utf8")
        for direction in ("UPLINK", "DOWNLINK"):
            self.assertIn("audit_outer_udp_capture.py' --validate-budget '$" + direction + "_BUDGET'", case)
        self.assertNotIn("-lt 1252", case)

    def test_bounded_soak_is_a_required_distinct_gate(self):
        self.assertEqual(matrix.SOAK_CASE_ID, "linux.roaming-flap-soak")
        self.assertIn(matrix.SOAK_CASE_ID, release_certification.REQUIRED_CASES)
        self.assertNotIn(matrix.SOAK_CASE_ID, matrix.case_ids())
        self.assertEqual(matrix.SOAK_SCRIPT.name, "linux_roaming_release_soak.sh")

if __name__ == "__main__":
    unittest.main()
