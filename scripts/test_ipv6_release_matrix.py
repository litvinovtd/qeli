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


if __name__ == "__main__":
    unittest.main()
