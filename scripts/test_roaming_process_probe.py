#!/usr/bin/env python3
"""Contract tests for exact qeli data-plane worker selection in soak gates."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).with_name("roaming_process_probe.sh")


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash"),
    "POSIX symlinks and bash required",
)
class RoamingProcessProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.binary = self.root / "qeli"
        self.binary.write_bytes(b"qeli-test")
        self.other_binary = self.root / "other-qeli"
        self.other_binary.write_bytes(b"other-test")
        self.config = str(self.root / "server.conf")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def add_process(self, pid: int, binary: Path, argv: list[str]) -> None:
        process = self.proc / str(pid)
        process.mkdir()
        os.symlink(binary, process / "exe")
        (process / "cmdline").write_bytes(
            b"\0".join(argument.encode() for argument in argv) + b"\0"
        )

    def run_probe(self, *pids: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; shift; roaming_find_server_worker_pid "$@"',
                "probe-test",
                str(HELPER),
                str(self.binary),
                self.config,
                str(self.proc),
                *(str(pid) for pid in pids),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_selects_only_exact_worker_binary_and_config(self) -> None:
        self.add_process(100, self.binary, [str(self.binary), "server", "-c", self.config])
        self.add_process(101, self.binary, [str(self.binary), "_worker", "-c", self.config])
        self.add_process(
            102,
            self.other_binary,
            [str(self.other_binary), "_worker", "-c", self.config],
        )
        self.add_process(
            103,
            self.binary,
            [str(self.binary), "_worker", "-c", f"{self.config}.other"],
        )

        result = self.run_probe(100, 101, 102, 103)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "101\n")

    def test_accepts_long_config_flag(self) -> None:
        self.add_process(
            201,
            self.binary,
            [str(self.binary), "_worker", "--config", self.config],
        )

        result = self.run_probe(201)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "201\n")

    def test_missing_worker_fails_closed(self) -> None:
        self.add_process(301, self.binary, [str(self.binary), "server", "-c", self.config])

        result = self.run_probe(301)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no exact qeli _worker", result.stderr)

    def test_multiple_exact_workers_fail_closed(self) -> None:
        for pid in (401, 402):
            self.add_process(
                pid,
                self.binary,
                [str(self.binary), "_worker", "-c", self.config],
            )

        result = self.run_probe(401, 402)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multiple exact qeli _worker", result.stderr)


if __name__ == "__main__":
    unittest.main()
