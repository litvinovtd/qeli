#!/usr/bin/env python3
"""Parser regressions for roaming_android_sleep_wake_gate.py."""

import unittest

import roaming_android_sleep_wake_gate as gate


class AndroidSleepWakeGateTests(unittest.TestCase):
    def test_parse_idle_flags(self) -> None:
        self.assertEqual(
            gate.parse_idle_flags("  mLightEnabled=true  mDeepEnabled=false\n"),
            (False, True),
        )

    def test_parse_idle_flags_rejects_incomplete_dump(self) -> None:
        with self.assertRaises(gate.GateFailure):
            gate.parse_idle_flags("mDeepEnabled=true\n")

    def test_find_tun_identity_is_exact(self) -> None:
        dump = (
            "00000000000000000000000000000001 01 80 10 80 lo\n"
            "fe800000000000001122334455667788 12 40 20 80 tun0\n"
        )
        self.assertEqual(
            gate.find_tun_identity(dump, "tun0"),
            "fe800000000000001122334455667788 12 40 20 80 tun0",
        )
        with self.assertRaises(gate.GateFailure):
            gate.find_tun_identity(dump, "tun")

    def test_parse_ping_counts(self) -> None:
        self.assertEqual(
            gate.parse_ping_counts("160 packets transmitted, 160 received, 0% packet loss"),
            (160, 160),
        )

    def test_parse_dns_address_accepts_resolution_without_icmp_reply(self) -> None:
        output = (
            "PING example.com (172.66.147.243) 56(84) bytes of data.\n\n"
            "1 packets transmitted, 0 received, 100% packet loss\n"
        )
        self.assertEqual(
            gate.parse_dns_address(output, "example.com"),
            "172.66.147.243",
        )

    def test_parse_dns_address_rejects_unresolved_name(self) -> None:
        with self.assertRaises(gate.GateFailure):
            gate.parse_dns_address("ping: bad address 'example.com'", "example.com")


if __name__ == "__main__":
    unittest.main()
