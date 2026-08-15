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


def rust_runtime_contract() -> set[str]:
    client = without_comments(
        between(source("qeli/src/config/client.rs"), "pub fn from_ini", "pub fn to_link")
    )
    return set(
        re.findall(
            r'q\s*\.(?:get|get_or|parse_or|bool_or)\(\s*"([a-z0-9_]+)"',
            client,
        )
    )


def rust_contract() -> set[str]:
    runtime = rust_runtime_contract()
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


def documented_client_matrix(relative: str) -> dict[str, tuple[str, ...]]:
    """Extract the five before/after states from the dedicated Markdown matrix."""
    lines = source(relative).splitlines()
    header = next(
        (
            i
            for i, line in enumerate(lines)
            if line.startswith("| Keys | CLI |") or line.startswith("| Ключи | CLI |")
        ),
        -1,
    )
    if header < 0:
        raise AssertionError(f"cannot locate client matrix in {relative}")

    matrix: dict[str, tuple[str, ...]] = {}
    for line in lines[header + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 7:
            raise AssertionError(f"malformed client-matrix row in {relative}: {line}")
        keys = re.findall(r"`([a-z][a-z0-9_]*)`", cells[0])
        if not keys:
            raise AssertionError(f"client-matrix row has no keys in {relative}: {line}")
        states = tuple(cells[1:6])
        if any(not re.fullmatch(r"[ACRD]→[ACRD]", state) for state in states):
            raise AssertionError(
                f"invalid before/after state in {relative}: {states!r}"
            )
        for key in keys:
            if key in matrix:
                raise AssertionError(f"duplicate documented key {key!r} in {relative}")
            matrix[key] = states
    return matrix


class ClientConfigKeyContractTests(unittest.TestCase):
    def test_rust_roundtrip_fixture_and_assertions_cover_every_runtime_key(self):
        text = source("qeli/src/config/client.rs")
        body = text[text.index("fn exhaustive_round_trip_every_client_key()") :]
        fixture = between(body, 'let fixture = r####"', '"####;')
        qeli_section = between(fixture, "[qeli]", "[logging]")
        fixture_keys = set(
            re.findall(r"^\s*([a-z][a-z0-9_]*)\s*=", qeli_section, re.MULTILINE)
        )
        token_block = between(body, "let qeli_tokens = [", "];\n\n        for t")
        asserted_keys = set(
            re.findall(r'"([a-z][a-z0-9_]*)\s*=', token_block)
        )
        expected = rust_runtime_contract()
        self.assertEqual(fixture_keys, expected)
        self.assertEqual(asserted_keys, expected)

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

    def test_ru_and_english_before_after_matrices_cover_the_live_contract(self):
        expected = rust_contract()
        ru = documented_client_matrix("docs/ru/CLIENT-CONFIG-MATRIX.md")
        eng = documented_client_matrix("docs/eng/CLIENT-CONFIG-MATRIX.md")
        self.assertEqual(set(ru), expected)
        self.assertEqual(set(eng), expected)
        self.assertEqual(ru, eng)


if __name__ == "__main__":
    unittest.main()
