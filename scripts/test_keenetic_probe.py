"""Diagnostic ownership and installed-pin guards; no live SSH or tool installs."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from test_native_ssh_command import load

probe = load(Path(__file__).with_name('keenetic_toolchain_probe.py'))


class ProbeTests(unittest.TestCase):
    def test_success_closes_diagnostic_connection(self):
        client = Mock()
        with patch.object(probe, 'connect', return_value=client), patch.object(probe, 'run', return_value='fixture'), contextlib.redirect_stdout(io.StringIO()):
            probe.main()
        client.close.assert_called_once()

    def test_read_error_closes_diagnostic_connection(self):
        client = Mock()
        with patch.object(probe, 'connect', return_value=client), patch.object(probe, 'run', side_effect=TimeoutError('probe timeout')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(TimeoutError, 'probe timeout'):
                probe.main()
        client.close.assert_called_once()

    @unittest.skipUnless(os.name == 'posix', 'requires shell; qualify on Linux')
    def test_missing_named_pin_never_queries_components_or_proxies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rustup = root / 'rustup'
            rustup.write_text('#!/bin/sh\nif [ "$1 $2" = "toolchain list" ]; then echo stable-x86_64-unknown-linux-gnu; else echo forbidden >&2; exit 77; fi\n')
            rustup.chmod(0o755)
            for label, command in probe.CMDS:
                if label.startswith('pinned'):
                    result = subprocess.run(command, shell=True, env=dict(os.environ, PATH=str(root)+':'+os.environ['PATH']), capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0)
                    self.assertIn('not installed', result.stdout)
                    self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
