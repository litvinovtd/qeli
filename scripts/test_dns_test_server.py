import unittest

import dns_test_server as dns


class DnsTestServerTest(unittest.TestCase):
    def test_a_round_trip(self):
        query = dns.build_query("a.release.test.", 1, 0x1234)
        response, name, qtype = dns.build_response(query)
        self.assertEqual(name, "a.release.test.")
        self.assertEqual(qtype, 1)
        self.assertEqual(dns.parse_answer(response, 0x1234, 1), "192.0.2.80")

    def test_aaaa_round_trip(self):
        query = dns.build_query("aaaa.release.test.", 28, 0xABCD)
        response, _name, _qtype = dns.build_response(query)
        self.assertEqual(dns.parse_answer(response, 0xABCD, 28), "2001:db8::80")

    def test_rejects_wrong_transaction(self):
        query = dns.build_query("a.release.test.", 1, 1)
        response, _name, _qtype = dns.build_response(query)
        with self.assertRaisesRegex(ValueError, "invalid DNS response header"):
            dns.parse_answer(response, 2, 1)


if __name__ == "__main__":
    unittest.main()
