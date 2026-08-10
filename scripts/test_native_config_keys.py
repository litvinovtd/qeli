#!/usr/bin/env python3
"""Cross-language guard for the shared client INI key surface.

Transport semantics live in Rust, while platform editors still model OS-specific fields and
must carry every valid foreign field through an open/save round trip. This test makes the
recognized key union explicit: adding/removing a Rust or GUI key cannot silently leave one
client rejecting or deleting it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.find(start)
    last = text.find(end, first + len(start)) if first >= 0 else -1
    if first < 0 or last < 0:
        raise AssertionError(f"cannot locate source contract {start!r}..{end!r}")
    return text[first:last]


def without_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def quoted_keys(text: str) -> set[str]:
    return set(re.findall(r'"([a-z][a-z0-9_]*)"', without_comments(text)))


def rust_contract() -> set[str]:
    client = without_comments(
        between(source("qeli/src/config/client.rs"), "pub fn from_ini", "pub fn to_link")
    )
    runtime = set(
        re.findall(
            r'q\s*\.(?:get|get_or|parse_or|bool_or)\(\s*"([a-z0-9_]+)"',
            client,
        )
    )
    config = source("qeli/src/config/mod.rs")
    gui_only = quoted_keys(
        between(config, "pub const GUI_ONLY_CLIENT_KEYS", "pub const RETIRED_KEYS")
    )
    contract = runtime | gui_only
    if len(contract) < 60:
        raise AssertionError("Rust client-key extractor drifted or returned an incomplete set")
    return contract


def android_contract() -> tuple[set[str], set[str]]:
    text = source("qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt")
    carried = quoted_keys(
        between(text, "private val CARRIED_INI_KEYS", "private val KNOWN_INI_KEYS")
    )
    modeled = quoted_keys(
        between(text, "private val KNOWN_INI_KEYS", "private fun longAt")
    )
    unsupported = quoted_keys(
        between(text, "private val UNSUPPORTED_INI_KEYS", "private val CARRIED_INI_KEYS")
    )
    return modeled | carried | unsupported, unsupported


def csharp_contract() -> set[str]:
    text = source("qeli-shared/QeliShared/Model/VpnConfig.cs")
    carried = quoted_keys(
        between(
            text,
            "public static readonly HashSet<string> CarriedIniKeys",
            "private static readonly HashSet<string> KnownIniKeys",
        )
    )
    modeled = quoted_keys(
        between(
            text,
            "private static readonly HashSet<string> KnownIniKeys",
            "public IReadOnlyList<string> UnknownKeys",
        )
    )
    return modeled | carried


def swift_contract() -> set[str]:
    text = source("qeli-ios/QeliCore/Model/VPNConfig.swift")
    carried = quoted_keys(between(text, "static let carriedINIKeys", "static let mtuMin"))
    modeled = quoted_keys(between(text, "static let knownINIKeys", "static let carriedINIKeys"))
    return modeled | carried


class ClientConfigKeyContractTests(unittest.TestCase):
    def test_every_platform_recognizes_the_exact_rust_and_gui_key_union(self):
        expected = rust_contract()
        android, _unsupported = android_contract()
        self.assertEqual(android, expected)
        self.assertEqual(csharp_contract(), expected)
        self.assertEqual(swift_contract(), expected)
        self.assertEqual(len(expected), 73)

    def test_android_has_no_silently_unsupported_shared_security_keys(self):
        _recognized, unsupported = android_contract()
        self.assertEqual(unsupported, set())


if __name__ == "__main__":
    unittest.main()
