"""Guard runnable CONFIG.md server fragments; runtime admission is checked separately."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def ini_examples(text: str) -> list[str]:
    return re.findall(r"^```ini[^\n]*\n(.*?)^```[ \t]*$", text, re.MULTILINE | re.DOTALL)


def check_examples(text: str) -> None:
    examples = ini_examples(text)
    if not examples:
        raise AssertionError("missing INI examples")
    for example in examples:
        keys = set(re.findall(r"^\s*([a-z][a-z0-9_.]*)\s*=", example, re.MULTILINE))
        if "bind_static" in keys and "bind_static_to_session" in keys:
            raise AssertionError("server auth and client binding settings need separate INI blocks")
        for line in example.splitlines():
            if line.lstrip().startswith(("#", ";")) or "=" not in line:
                continue
            key, value = line.split("=", 1)
            # Shell commands may contain an intentional '#', and passwords may
            # contain any printable punctuation. Never sanitize those values.
            if key.strip() in {"routing.post_up", "routing.post_down", "post_up", "post_down",
                               "password_command", "pass", "password_hash", "obf.obfs_key", "key"}:
                continue
            if re.search(r"(?:^|[ \t])[#;][ \t]", value):
                raise AssertionError(f"unsupported INI inline comment: {line}")


class ServerConfigExampleTests(unittest.TestCase):
    def test_all_user_manual_ini_examples_use_whole_line_comments(self):
        for lang in ("ru", "eng"):
            for path in (ROOT / "docs" / lang / "manuals").glob("*.md"):
                text = path.read_text(encoding="utf-8")
                if ini_examples(text):
                    with self.subTest(path=path.relative_to(ROOT).as_posix()):
                        check_examples(text)

    def test_inline_allowlist_comment_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "inline comment"):
            check_examples('```ini\n[web]\nallowed_ips = 203.0.113.4 # my IP\n```\n')

    def test_ru_and_english_examples_are_unambiguous_ini(self):
        for lang in ("ru", "eng"):
            text = (ROOT / f"docs/{lang}/manuals/CONFIG.md").read_text(encoding="utf-8")
            # Includes migration, compact policy and the explicit NDP source/refresh example.
            self.assertEqual(len(ini_examples(text)), 41, lang)  # Includes the macOS dev_node example.
            check_examples(text)

    def test_valid_secret_and_shell_punctuation_are_preserved(self):
        check_examples('```ini\n[qeli]\npass = x # secret\n'
                       'password_command = printf "x # secret"\n'
                       'post_up = echo "x # literal"\n```\n')


if __name__ == "__main__":
    unittest.main()
