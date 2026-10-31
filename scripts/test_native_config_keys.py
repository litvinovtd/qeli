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
    return set(re.findall(r'"([a-z][a-z0-9_.]*)"', without_comments(text)))


def rust_runtime_contract() -> set[str]:
    client = without_comments(
        between(source("qeli/src/config/client.rs"), "pub fn from_ini", "pub fn to_link")
    )
    return set(
        re.findall(
            r'q\s*\.(?:get|get_or|parse_or|bool_or)\(\s*"([a-z0-9_.]+)"',
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


def editor_contract() -> set[str]:
    import json
    fields = [json.loads("[" + row + "]") for row in re.findall(r'field!\(([^\n]+)\)', source("qeli/src/config/editor/schema.rs")) if row.startswith('"')]
    return {row[0] for row in fields if not row[0].startswith("logging.")}


def documented_defaults(text: str) -> dict[str, str]:
    """Read only the dedicated client tables, including qualified logging fields.

    A grouped row must state each default in key order; a single common default
    is allowed only when all fields have the same value. Opaque 'profile defaults'
    cannot hide drift. Descriptions and unrelated server tables are not scanned.
    """
    headers = ("| Key | Default | CLI |", "| Ключ | Умолч. | CLI |")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(headers)), -1)
    if start < 0:
        raise AssertionError("missing dedicated client default table")
    result: dict[str, str] = {}
    for line in lines[start:]:
        if line.startswith("### "):
            break
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 8:
            raise AssertionError(f"malformed client table: {line}")
        keys = re.findall(r"`([a-z][a-z0-9_.]*)`", cells[0])
        if not keys:
            continue
        tokens = re.findall(r"`[^`]+`|\b(?:on|off)\b|—", cells[1])
        values = [{"on": "true", "off": "false", "—": ""}.get(token, token.strip('`'))
                  for token in tokens]
        if len(values) == 1:
            values *= len(keys)
        if len(values) != len(keys):
            raise AssertionError(f"incomplete defaults for {keys}: {cells[1]}")
        for key, value in zip(keys, values):
            if key in result:
                raise AssertionError(f"duplicate client default {key}")
            result[key] = value
    return result


def generated_contract(relative: str) -> set[str]:
    # The generator check below proves every schema-to-model projection is up to date.
    return quoted_keys(source(relative)) & editor_contract() | {"server"}


def android_contract() -> tuple[set[str], set[str]]:
    return generated_contract("qeli-android/app/src/main/kotlin/com/qeli/model/ConfigProjection.kt"), set()


def csharp_contract() -> set[str]:
    return generated_contract("qeli-shared/QeliShared/Model/VpnConfig.Native.g.cs")


def swift_contract() -> set[str]:
    return generated_contract("qeli-ios/QeliCore/Model/VPNConfigProjection.swift")


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
        keys = re.findall(r"`([a-z][a-z0-9_.]*)`", cells[0])
        if not keys:
            raise AssertionError(f"client-matrix row has no keys in {relative}: {line}")
        states = tuple(cells[1:6])
        if any(not re.fullmatch(r"[ACRDN]→[ACRDN]", state) for state in states):
            raise AssertionError(
                f"invalid before/after state in {relative}: {states!r}"
            )
        for key in keys:
            if key in matrix:
                raise AssertionError(f"duplicate documented key {key!r} in {relative}")
            matrix[key] = states
    return matrix


class ClientConfigKeyContractTests(unittest.TestCase):
    def test_documented_defaults_cover_the_complete_authoritative_schema(self):
        import json
        fields = [json.loads("[" + row + "]") for row in re.findall(
            r'field!\(([^\n]+)\)', source("qeli/src/config/editor/schema.rs"))
            if row.startswith('"')]
        expected = {row[0]: row[2] for row in fields}
        self.assertEqual(len(expected), 88)
        for lang in ("ru", "eng"):
            self.assertEqual(documented_defaults(source(f"docs/{lang}/manuals/CONFIG.md")),
                             expected, lang)

    def test_client_ini_examples_do_not_advertise_unsupported_inline_comments(self):
        for lang in ("ru", "eng"):
            text = source(f"docs/{lang}/manuals/CONFIG.md")
            examples = [m[1] for m in re.finditer(r"^```[^\n]*\n(.*?)^```\s*$", text,
                                                re.MULTILINE | re.DOTALL)
                        if re.search(r"^\[qeli\]", m[1], re.MULTILINE)]
            # Includes net_gateway migration, compact policy and macOS fixed-utun examples.
            self.assertEqual(len(examples), 13, lang)
            for example in examples:
                for line in example.splitlines():
                    if line.lstrip().startswith(("#", ";")):
                        continue
                    # This is a documentation-style guard; native parsing remains
                    # authoritative. Do not rewrite secret/command values containing '#'.
                    self.assertIsNone(re.match(r"[^=]+?=\s*(?:false|true|required|auto|off)\s+[#;]",
                                               line), f"{lang}: {line}")

    def test_native_schema_and_generated_adapters_are_current(self):
        import gen_config_bindings
        self.assertEqual(editor_contract(), rust_contract())
        for relative, expected in gen_config_bindings.generate().items():
            self.assertEqual(source(relative), expected, relative)


    def test_rust_roundtrip_fixture_and_assertions_cover_every_runtime_key(self):
        text = source("qeli/src/config/client.rs")
        body = text[text.index("fn exhaustive_round_trip_every_client_key()") :]
        fixture = between(body, 'let fixture = r####"', '"####;')
        qeli_section = between(fixture, "[qeli]", "[logging]")
        fixture_keys = set(
            re.findall(r"^\s*([a-z][a-z0-9_.]*)\s*=", qeli_section, re.MULTILINE)
        )
        token_block = between(body, "let qeli_tokens = [", "];\n\n        for t")
        asserted_keys = set(
            re.findall(r'"([a-z][a-z0-9_.]*)\s*=', token_block)
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
        # Deliberate contract-size tripwire: an accidental removal from the shared source
        # plus all generated/maintained mirrors must not make the equality checks vacuous.
        # Full IPv6 adds ipv6/leak controls/lan_subnet_ipv6 and the shared REALITY core adds
        # its three transport-owned settings; roaming adds one shared session-policy key.
        self.assertEqual(len(expected), 85)

    def test_literal_dotted_queue_key_is_carried_without_logging_aliases(self):
        self.assertIn("tun.tx_queue_len", rust_runtime_contract())
        self.assertIn("tun.tx_queue_len", editor_contract())
        self.assertNotIn("logging.level", editor_contract())
        self.assertEqual(quoted_keys('"tun.tx_queue_len" "logging.level"'),
                         {"tun.tx_queue_len", "logging.level"})
        for keys in (android_contract()[0], csharp_contract(), swift_contract()):
            self.assertIn("tun.tx_queue_len", keys)

    def test_model_coverage_fixtures_keep_literal_queue_key_in_qeli(self):
        fixtures = {
            "qeli-shared/QeliShared/Protocol/WireConformance.cs": 'key.StartsWith("logging.", StringComparison.Ordinal)',
            "qeli-android/app/src/test/kotlin/com/qeli/ConfigHardeningTest.kt": 'key.startsWith("logging.")',
            "qeli-ios/QeliIOSTests/ConfigHardeningTests.swift": 'key.hasPrefix("logging.")',
        }
        for relative, section_test in fixtures.items():
            text = source(relative)
            self.assertIn(section_test, text, relative)
            self.assertIn('"tun.tx_queue_len"', text, relative)

    def test_android_has_no_silently_unsupported_shared_security_keys(self):
        _recognized, unsupported = android_contract()
        self.assertEqual(unsupported, set())

    def test_reality_policy_has_one_handler_for_cli_and_every_native_runtime(self):
        # Source wiring guard complements byte-capture and real TLS interop Rust tests.
        # App runtime is target-gated, so a Linux test run alone cannot catch this drift.
        for relative, start, end in [
            ("qeli/src/client/mod.rs", "async fn connect_reality", "async fn connect_"),
            ("qeli/src/transport_core/runtime.rs", "async fn wrap_reality", "async fn "),
        ]:
            text = source(relative)
            first = text.index(start)
            last = text.find(end, first + len(start))
            body = text[first:last if last >= 0 else len(text)]
            self.assertIn("session::establish_reality_tls", body, relative)
            self.assertNotIn("::client_handshake(", body, relative)
            self.assertNotIn("::client_handshake_compact(", body, relative)
        policy = between(source("qeli/src/transport_core/session.rs"),
                         "pub(crate) async fn establish_reality_tls", "#[derive(Debug)]")
        for field in ("reality_compact", "reality_split", "reality_split_delay_ms"):
            self.assertIn(field, policy)
        for keys in (android_contract()[0], csharp_contract(), swift_contract()):
            self.assertTrue({"reality_compact", "reality_split", "reality_split_delay"} <= keys)

    def test_cli_applied_matrix_keys_match_actual_runtime_reads(self):
        # A GUI-only exemption must not be mistaken for a working CLI setting.
        # Conversely a newly wired reader requires updating the current-state matrix.
        expected = rust_runtime_contract()
        for lang in ("ru", "eng"):
            matrix = documented_client_matrix(f"docs/{lang}/reference/CLIENT-CONFIG-MATRIX.md")
            applied = {key for key, states in matrix.items() if states[0].endswith("→A")}
            self.assertEqual(applied, expected, lang)

    def test_ru_and_english_before_after_matrices_cover_the_live_contract(self):
        expected = rust_contract()
        ru = documented_client_matrix("docs/ru/reference/CLIENT-CONFIG-MATRIX.md")
        eng = documented_client_matrix("docs/eng/reference/CLIENT-CONFIG-MATRIX.md")
        self.assertEqual(set(ru), expected)
        self.assertEqual(set(eng), expected)
        self.assertEqual(ru, eng)


if __name__ == "__main__":
    unittest.main()
