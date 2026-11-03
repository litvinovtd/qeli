"""Command-channel ownership and adapter compatibility; no network in these tests."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch
import native_lab
from ssh_command import run_ssh_command


class CommandFixture:
    def __init__(self, payload=b" stdout\nstderr ", status=17):
        self.stdin = Mock()
        self.channel = Mock()
        self.stdout = Mock(channel=self.channel)
        self.stderr = Mock()
        def read():
            self.channel.set_combine_stderr.assert_called_once_with(True)
            self.stdin.close.assert_called_once()
            return payload
        self.stdout.read.side_effect = read
        def exit_status():
            self.stdout.read.assert_called_once()
            return status
        self.channel.recv_exit_status.side_effect = exit_status
        self.client = Mock()
        self.client.exec_command.return_value = self.stdin, self.stdout, self.stderr


def load(path):
    spec = importlib.util.spec_from_file_location('ssh_audit_' + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    try:
        import paramiko
        context = contextlib.nullcontext()
    except ModuleNotFoundError:
        context = patch.dict(sys.modules, {'paramiko': types.ModuleType('paramiko')})
    with context:
        spec.loader.exec_module(module)
    return module


class CommandTests(unittest.TestCase):
    def test_combined_output_status_and_channel_close(self):
        f = CommandFixture()
        self.assertEqual(run_ssh_command(f.client, 'fixture', 7), (' stdout\nstderr ', 17))
        f.client.exec_command.assert_called_once_with('fixture', timeout=7)
        f.stderr.read.assert_not_called()
        f.channel.close.assert_called_once()
        f.client.close.assert_not_called()

    def test_invalid_utf8_is_replaced_without_losing_output(self):
        f = CommandFixture(b'A\xffB')
        self.assertEqual(run_ssh_command(f.client, 'fixture')[0], 'A\ufffdB')
        f.channel.close.assert_called_once()

    def test_read_timeout_closes_command_without_closing_connection(self):
        f = CommandFixture()
        f.stdout.read.side_effect = TimeoutError('read timeout')
        with self.assertRaisesRegex(TimeoutError, 'read timeout'):
            run_ssh_command(f.client, 'fixture')
        f.channel.close.assert_called_once()
        f.channel.recv_exit_status.assert_not_called()
        f.client.close.assert_not_called()

    def test_setup_stdin_and_exit_status_errors_close_channel(self):
        for failing in ('combine', 'stdin', 'status'):
            f = CommandFixture()
            operation = {'combine': f.channel.set_combine_stderr,
                         'stdin': f.stdin.close, 'status': f.channel.recv_exit_status}[failing]
            operation.side_effect = OSError(failing + ' fault')
            with self.subTest(failing=failing), self.assertRaisesRegex(OSError, failing + ' fault'):
                run_ssh_command(f.client, 'fixture')
            f.channel.close.assert_called_once()

    def test_command_open_error_does_not_close_shared_connection(self):
        f = CommandFixture()
        f.client.exec_command.side_effect = OSError('open fault')
        with self.assertRaisesRegex(OSError, 'open fault'):
            run_ssh_command(f.client, 'fixture')
        f.client.close.assert_not_called()

    def test_four_callers_preserve_return_and_whitespace_contracts(self):
        root = Path(__file__).resolve().parents[1]
        lab = load(root / 'scripts/lab_common.py')
        keen = load(root / 'scripts/build_keenetic.py')
        openwrt = load(root / 'qeli-openwrt/build/build_openwrt.py')
        for label in ('native', 'lab', 'keenetic', 'openwrt'):
            f = CommandFixture()
            with self.subTest(caller=label):
                if label == 'native':
                    self.assertEqual(native_lab.LabConnection(f.client).run('fixture', 7), ('stdout\nstderr', 17))
                elif label == 'lab':
                    self.assertEqual(lab.run(f.client, 'fixture', 7), ' stdout\nstderr')
                else:
                    caller = keen if label == 'keenetic' else openwrt
                    self.assertEqual(caller.run(f.client, 'fixture', 7), (17, 'stdout\nstderr'))
                f.channel.set_combine_stderr.assert_called_once_with(True)
                f.channel.close.assert_called_once()

    def test_failed_native_connect_closes_client_and_keeps_original_error(self):
        for close_error in (None, OSError('close fault')):
            client = Mock()
            client.connect.side_effect = OSError('auth fault')
            client.close.side_effect = close_error
            paramiko = types.ModuleType('paramiko')
            paramiko.SSHClient = Mock(return_value=client)
            policy = types.ModuleType('ssh_hostkey')
            policy.harden = Mock()
            with self.subTest(close_error=close_error), patch.dict(sys.modules, {'paramiko': paramiko, 'ssh_hostkey': policy}):
                with self.assertRaisesRegex(RuntimeError, 'auth fault'):
                    native_lab.connect_lab('fixture', 'fixture', 'fixture-only')
                client.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
