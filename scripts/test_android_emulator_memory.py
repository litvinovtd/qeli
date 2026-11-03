import unittest
from audit_android_data_plane_lab import admitted_guest_memory


class AndroidEmulatorMemoryTest(unittest.TestCase):
    def test_guest_kernel_reservations_are_allowed(self):
        result = admitted_guest_memory("MemTotal:        1492000 kB\nMemFree: 42000 kB\n")
        self.assertEqual(result["actual_guest_total_kib"], 1492000)
        self.assertEqual(result["requested_mb"], 1536)

    def test_silent_minimum_ram_increase_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "guest RAM differs"):
            admitted_guest_memory("MemTotal: 2550000 kB\n")

    def test_unexpected_low_memory_guest_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "guest RAM differs"):
            admitted_guest_memory("MemTotal: 500000 kB\n")

    def test_missing_duplicate_or_invalid_total_cannot_admit_fixture(self):
        for value in ("MemFree: 42 kB\n", "MemTotal: 1492000 kB\nMemTotal: 1492000 kB\n", "MemTotal: -1 kB\n", "MemTotal: 1492000 MB\n"):
            with self.subTest(value=value), self.assertRaisesRegex(AssertionError, "missing or ambiguous"):
                admitted_guest_memory(value)


if __name__ == "__main__":
    unittest.main()
