#!/usr/bin/env python3
"""Repeated carrier visits must never accept a historical roaming commit."""
import unittest
from audit_android_network_handover import carrier_committed_since

class CarrierEpochTests(unittest.TestCase):
    def test_historical_commit_is_not_completion(self):
        old = "Roaming path committed: android:12\n"
        self.assertFalse(carrier_committed_since(old, old, "12"))
    def test_fresh_commit_for_revisited_handle(self):
        old = "Roaming path committed: android:12\n"
        self.assertTrue(carrier_committed_since(old, old + old, "12"))
    def test_similar_handle_is_not_completion(self):
        self.assertFalse(carrier_committed_since("", "Roaming path committed: android:123\n", "12"))
    def test_other_carrier_is_not_completion(self):
        self.assertFalse(carrier_committed_since("", "Roaming path committed: android:13\n", "12"))
    def test_truncated_evidence_cannot_prove_freshness(self):
        old = "Roaming path committed: android:12\n" * 2
        self.assertFalse(carrier_committed_since(old, old[:len(old)//2], "12"))

if __name__ == "__main__":
    unittest.main()
