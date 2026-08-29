#!/usr/bin/env python3
"""Regressions for roaming_android_udp_grace_expiry_gate.py."""

import os
import tempfile
import unittest

import roaming_android_udp_grace_expiry_gate as gate


VALID_LOG = """
08-29 D/VpnSvc: UDP same-network NAT recovery — preparing a soft roaming path
08-29 D/VpnSvc: Native transport error -10: transport disconnected
08-29 D/VpnSvc: Auth OK: IP 10.93.3.2
08-29 D/VpnSvc: Native NetworkPlan 2 APPLIED: mode=full
"""


class AndroidUdpGraceExpiryGateTests(unittest.TestCase):
    def test_duration_must_exceed_grace(self) -> None:
        gate.validate_durations(40, 15)
        with self.assertRaises(gate.GateFailure):
            gate.validate_durations(15, 15)
        with self.assertRaises(gate.GateFailure):
            gate.validate_durations(14.9, 15)

    def test_grace_must_be_positive(self) -> None:
        with self.assertRaises(gate.GateFailure):
            gate.validate_durations(40, 0)

    def test_finds_replacement_tun_by_exact_address(self) -> None:
        dump = (
            "lo               UNKNOWN        127.0.0.1/8 ::1/128\n"
            "tun1             UNKNOWN        10.93.3.2/32 fe80::1234/64\n"
        )
        self.assertEqual(
            gate.find_interface_by_address(dump, "10.93.3.2/32"),
            (
                "tun1",
                "tun1             UNKNOWN        10.93.3.2/32 fe80::1234/64",
            ),
        )

    def test_address_match_is_not_prefix_based(self) -> None:
        dump = "tun0 UNKNOWN 10.93.3.20/32 fe80::1234/64\n"
        with self.assertRaises(gate.GateFailure):
            gate.find_interface_by_address(dump, "10.93.3.2/32")

    def test_rejects_ambiguous_recovered_address(self) -> None:
        dump = (
            "tun0 UNKNOWN 10.93.3.2/32 fe80::1/64\n"
            "tun1 UNKNOWN 10.93.3.2/32 fe80::2/64\n"
        )
        with self.assertRaises(gate.GateFailure):
            gate.find_interface_by_address(dump, "10.93.3.2/32")

    def test_counts_one_full_reconnect(self) -> None:
        self.assertEqual(gate.reconnect_counts(VALID_LOG), (1, 1))

    def test_validates_ordered_fallback(self) -> None:
        gate.validate_udp_fallback_sequence(VALID_LOG)

    def test_rejects_missing_roaming_attempt(self) -> None:
        with self.assertRaises(gate.GateFailure):
            gate.validate_udp_fallback_sequence(
                VALID_LOG.replace(
                    "UDP same-network NAT recovery — preparing a soft roaming path\n", ""
                )
            )

    def test_rejects_reordered_full_auth(self) -> None:
        reordered = """
08-29 D/VpnSvc: Auth OK: IP 10.93.3.2
08-29 D/VpnSvc: UDP same-network NAT recovery — preparing a soft roaming path
08-29 D/VpnSvc: Native transport error -10: transport disconnected
08-29 D/VpnSvc: Native NetworkPlan 2 APPLIED: mode=full
"""
        with self.assertRaises(gate.GateFailure):
            gate.validate_udp_fallback_sequence(reordered)

    def test_rejects_multiple_successful_auths(self) -> None:
        with self.assertRaises(gate.GateFailure):
            gate.validate_udp_fallback_sequence(VALID_LOG + "Auth OK: IP 10.93.3.2\n")

    def test_fault_hook_argv_is_shell_free(self) -> None:
        handle, path = tempfile.mkstemp(prefix="qeli-grace-hook-")
        os.close(handle)
        try:
            os.chmod(path, 0o700)
            argv = gate.fault_hook_argv(path, "apply")
            self.assertEqual(argv, [os.path.realpath(path), "apply"])
            self.assertNotIn("sh", argv)
        finally:
            os.unlink(path)

    @unittest.skipIf(os.name == "nt", "Windows does not expose POSIX execute bits")
    def test_rejects_non_executable_fault_hook(self) -> None:
        handle, path = tempfile.mkstemp(prefix="qeli-grace-hook-")
        os.close(handle)
        try:
            os.chmod(path, 0o600)
            with self.assertRaises(gate.GateFailure):
                gate.fault_hook_argv(path, "apply")
        finally:
            os.unlink(path)

    def test_rejects_unknown_hook_action(self) -> None:
        handle, path = tempfile.mkstemp(prefix="qeli-grace-hook-")
        os.close(handle)
        try:
            with self.assertRaises(gate.GateFailure):
                gate.fault_hook_argv(path, "destroy")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
