import unittest

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

if __name__ == "__main__":
    unittest.main()
