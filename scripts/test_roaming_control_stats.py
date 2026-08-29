#!/usr/bin/env python3
"""Contract tests for the private roaming control-counter reader."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("roaming_control_stats.py")
SPEC = importlib.util.spec_from_file_location("roaming_control_stats", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
STATS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATS)


def response(profile: dict) -> str:
    return json.dumps(
        {
            "ok": True,
            "message": json.dumps({"profiles": [profile]}),
        }
    )


class RoamingControlStatsTests(unittest.TestCase):
    def test_extracts_requested_fields_in_order(self) -> None:
        payload = response(
            {
                "name": "roam",
                "udp": {
                    "attempts_total": 10_000,
                    "active_candidates": 0,
                    "cid_aliases": 3,
                },
            }
        )
        self.assertEqual(
            STATS.extract_fields(
                payload,
                "roam",
                "udp",
                ["attempts_total", "active_candidates", "cid_aliases"],
            ),
            [10_000, 0, 3],
        )

    def test_rejects_missing_duplicate_or_non_integer_counters(self) -> None:
        valid = {
            "name": "roam",
            "tcp": {"attempts_total": 1},
        }
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            STATS.extract_fields(response(valid), "roam", "tcp", ["commits_total"])

        invalid = {
            "name": "roam",
            "tcp": {"attempts_total": True},
        }
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            STATS.extract_fields(response(invalid), "roam", "tcp", ["attempts_total"])

        duplicate = json.dumps(
            {
                "ok": True,
                "message": json.dumps({"profiles": [valid, valid]}),
            }
        )
        with self.assertRaisesRegex(ValueError, "expected one roaming profile"):
            STATS.extract_fields(duplicate, "roam", "tcp", ["attempts_total"])


if __name__ == "__main__":
    unittest.main()
