"""Real init functions in isolated files, mocked UCI/firewall; never mutate /etc.
Linux: QELI_OPENWRT_TEST_SHELL='/usr/bin/busybox ash' python -m unittest
  discover -s scripts -p test_openwrt_init.py -v
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get('QELI_OPENWRT_TEST_SHELL', '/bin/sh'))
PRELUDE = r'''
. "$QELI_TEST_INIT"
RUNDIR="$QELI_TEST_ROOT/run"
CONF="$RUNDIR/client.conf"
PASS_FILE="$RUNDIR/password"
OBFS_KEY_FILE="$RUNDIR/obfs-key"
STATEDIR="$QELI_TEST_ROOT/state"
FIREWALL_INIT="$QELI_TEST_ROOT/firewall"
logger() { :; }
config_get() {
    local value
    value="$(printenv "QELI_TEST_$3")" || value="${4:-}"
    export "$1=$value"
}
config_get_bool() { config_get "$@"; }
config_list_foreach() {
    local item
    for item in ${QELI_TEST_dns_servers:-}; do "$3" "$item"; done
}
config_load() { :; }
config_foreach() { "$1" zone0; }
uci() {
    [ "$1" != -q ] || shift
    local verb="$1" key="$2"
    if [ "$verb" = get ]; then
        case "$key" in
            qeli.main.dev) printf '%s' "${QELI_TEST_dev:-qeli0}" ;;
            firewall.zone0.name|firewall.zone1.name) printf qeli ;;
            firewall.zone0.device) cat "$QELI_TEST_ROOT/device" ;;
            firewall.zone0.masq6) cat "$QELI_TEST_ROOT/masq6" ;;
            *) return 1 ;;
        esac
        return
    fi
    printf '%s\n' "$verb" >> "$QELI_TEST_ROOT/calls"
    [ "${QELI_TEST_FAIL:-}" != "$verb" ] || return 17
    case "$verb" in
        delete) : > "$QELI_TEST_ROOT/device" ;;
        add_list) printf '%s' "${key#*=}" > "$QELI_TEST_ROOT/device" ;;
        set) printf 1 > "$QELI_TEST_ROOT/masq6" ;;
    esac
}
'''

MIGRATION_MODEL = r'''
uci() {
    [ "$1" != -q ] || shift
    local verb="$1" key="$2" name
    name="${key#qeli.main.}"
    if [ "$verb" = get ]; then
        [ -f "$QELI_TEST_ROOT/stage-$name" ] || return 1
        cat "$QELI_TEST_ROOT/stage-$name"
        return
    fi
    printf '%s\n' "$verb" >> "$QELI_TEST_ROOT/calls"
    [ "${QELI_TEST_FAIL:-}" != "$verb" ] || return 17
    case "$verb" in
        delete) command rm -f "$QELI_TEST_ROOT/stage-$name" ;;
        commit)
            for name in pass obfs_key; do
                if [ -f "$QELI_TEST_ROOT/stage-$name" ]; then
                    command cp "$QELI_TEST_ROOT/stage-$name" "$QELI_TEST_ROOT/disk-$name" || return 1
                else
                    command rm -f "$QELI_TEST_ROOT/disk-$name" || return 1
                fi
            done ;;
        *) return 1 ;;
    esac
}
'''

@unittest.skipUnless(shutil.which(SHELL[0]), 'requires POSIX shell (run in Linux lab)')
class OpenWrtInitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='qeli-openwrt-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'run').mkdir(mode=0o700)
        (self.root / 'run/password').write_text('fixture-password')
        (self.root / 'run/client.conf').write_text('previous-config\n')
        (self.root / 'device').write_text('qeli0')
        (self.root / 'masq6').write_text('1')
        firewall = self.root / 'firewall'
        firewall.write_text('#!/bin/sh\nprintf "reload\\n" >> "$QELI_TEST_ROOT/calls"\n[ "${QELI_TEST_FAIL:-}" != reload ]\n')
        firewall.chmod(0o700)
        self.env = dict(os.environ, QELI_TEST_ROOT=str(self.root),
            QELI_TEST_INIT=str(ROOT / 'qeli-openwrt/files/qeli.init'),
            QELI_TEST_server='vpn.example:443', QELI_TEST_user='router1')

    def run_shell(self, body, **values):
        env = dict(self.env)
        env.update({'QELI_TEST_' + k: v for k, v in values.items()})
        return subprocess.run(SHELL + ['-c', PRELUDE + '\n' + body], env=env,
            text=True, capture_output=True, timeout=15)

    def config(self):
        return (self.root / 'run/client.conf').read_text()

    def calls(self):
        p = self.root / 'calls'
        return p.read_text().splitlines() if p.exists() else []

    def test_journal_root_resolves_only_firmware_var_without_chmod_or_mkdir(self):
        real = self.root / 'firmware-var'
        real.mkdir()
        # Even a planted child must not be canonicalized or modified by shell.
        target = self.root / 'protected'
        target.mkdir(mode=0o755)
        (real / 'lib').symlink_to(target)
        result = self.run_shell(r'''
readlink() { [ "$*" = '-f /var' ] || return 19; printf '%s' "$QELI_TEST_ROOT/firmware-var"; }
chmod() { return 21; }
mkdir() { return 22; }
qeli_state_directory
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(real / 'lib/qeli'))
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(target.iterdir()), [])

    def test_journal_root_resolution_failure_does_not_fall_back_to_symlink(self):
        for body in ["return 17", "printf relative", "printf /missing-qeli-fixture-dir"]:
            with self.subTest(body=body):
                result = self.run_shell('readlink() { ' + body + '; }; qeli_state_directory')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def seed_legacy(self, name='pass', value='legacy-fixture'):
        for prefix in ('stage-', 'disk-'):
            (self.root / (prefix + name)).write_text(value)

    def migration(self, body='migrate_legacy_secrets', **values):
        return self.run_shell(MIGRATION_MODEL + '\n' + body, **values)

    def test_start_result_hook_preserves_failure_and_disabled_success(self):
        result = self.run_shell('qeli_start_service() { return 17; }; start_service; service_started')
        self.assertEqual(result.returncode, 17)
        self.assertEqual(self.run_shell('start_service; service_started', enabled='0').returncode, 0)

    def test_stop_result_hook_and_restart_gate_preserve_cleanup_failure(self):
        result = self.run_shell('''
rm() { return 17; }
stop_service
service_stopped
''')
        self.assertEqual(result.returncode, 17)
        result = self.run_shell('''
QELI_STOP_RESULT=17
qeli_start_service() { printf start >> "$QELI_TEST_ROOT/calls"; }
start_service
service_started
''')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])

    def test_clear_secrets_propagates_unlink_failure(self):
        (self.root / 'run/obfs-key').write_text('fixture-obfs')
        for name in ('pass', 'obfs_key', 'all'):
            result = self.run_shell('rm() { return 17; }; clear_secrets "$QELI_TEST_NAME"', NAME=name)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((self.root / 'run/password').exists())
            self.assertTrue((self.root / 'run/obfs-key').exists())

    def test_clear_named_all_absent_and_invalid_names(self):
        (self.root / 'run/obfs-key').write_text('fixture-obfs')
        self.assertEqual(self.run_shell('clear_secrets pass').returncode, 0)
        self.assertTrue((self.root / 'run/obfs-key').exists())
        self.assertEqual(self.run_shell('clear_secrets pass').returncode, 0)
        self.assertEqual(self.run_shell('clear_secrets invalid').returncode, 2)
        self.assertTrue((self.root / 'run/obfs-key').exists())
        self.assertEqual(self.run_shell('clear_secrets').returncode, 0)
        self.assertFalse((self.root / 'run/obfs-key').exists())

    def test_migration_failed_commit_retries_when_staged_keys_are_already_gone(self):
        self.seed_legacy(); self.seed_legacy('obfs_key', 'legacy-obfs')
        (self.root / 'run/password').unlink()
        result = self.migration(FAIL='commit'); self.assertNotEqual(result.returncode, 0)
        pending = self.root / 'run/secret-migration-pending'
        self.assertTrue(pending.exists()); self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / 'stage-pass').exists())
        self.assertTrue((self.root / 'disk-pass').exists())
        self.assertEqual((self.root / 'run/password').read_text(), 'legacy-fixture')
        self.assertEqual((self.root / 'run/obfs-key').read_text(), 'legacy-obfs')
        self.assertEqual(self.migration().returncode, 0)
        self.assertFalse(pending.exists()); self.assertFalse((self.root / 'disk-pass').exists())
        self.assertFalse((self.root / 'disk-obfs_key').exists())
        self.assertEqual(self.calls(), ['delete', 'delete', 'commit', 'commit'])

    def test_migration_copy_marker_delete_failure_preserves_persisted_secret(self):
        self.seed_legacy()
        (self.root / 'run/password').unlink()
        result = self.migration('write_runtime_secret_value() { return 17; }; migrate_legacy_secrets')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])
        self.assertTrue((self.root / 'stage-pass').exists())
        (self.root / 'run/password').write_text('new-secret')
        result = self.migration('ensure_runtime_dir() { return 17; }; migrate_legacy_secrets')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])
        self.assertTrue((self.root / 'stage-pass').exists())
        self.assertNotEqual(self.migration(FAIL='delete').returncode, 0)
        self.assertTrue((self.root / 'stage-pass').exists()); self.assertTrue((self.root / 'disk-pass').exists())
        self.assertTrue((self.root / 'run/secret-migration-pending').exists())
        self.assertEqual(self.migration().returncode, 0)
        self.assertFalse((self.root / 'disk-pass').exists())

    def test_migration_existing_runtime_secret_wins_and_empty_legacy_is_scrubbed(self):
        self.seed_legacy(); self.seed_legacy('obfs_key', '')
        self.assertEqual(self.migration().returncode, 0)
        self.assertEqual((self.root / 'run/password').read_text(), 'fixture-password')
        self.assertFalse((self.root / 'disk-pass').exists())
        self.assertFalse((self.root / 'disk-obfs_key').exists())
        self.assertFalse((self.root / 'run/obfs-key').exists())

    def test_migration_marker_removal_failure_keeps_retry_intent(self):
        self.seed_legacy()
        result = self.migration('''
rm() { case "$*" in *secret-migration-pending*) return 17 ;; esac; command rm "$@"; }
migrate_legacy_secrets
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'run/secret-migration-pending').exists())
        self.assertEqual(self.migration().returncode, 0)
        self.assertEqual(self.calls(), ['delete', 'commit', 'commit'])

    def test_start_rejects_both_config_load_failures_before_procd_admission(self):
        for fail_at in ('1', '2'):
            result = self.run_shell('''
load_count=0
config_load() { load_count=$((load_count + 1)); [ "$load_count" != "$QELI_TEST_FAIL_AT" ]; }
migrate_legacy_secrets() { :; }
procd_open_instance() { printf procd >> "$QELI_TEST_ROOT/calls"; }
start_service
''', FAIL_AT=fail_at, enabled='0')
            self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])
        self.assertEqual(self.run_shell('start_service', enabled='0').returncode, 0)

    def test_firewall_load_and_context_restore_errors_stop_before_mutation(self):
        for package in ('firewall', 'qeli'):
            result = self.run_shell('config_load() { [ "$1" != "$QELI_TEST_PACKAGE" ]; }; sync_firewall_device', PACKAGE=package)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])

    def test_duplicate_qeli_firewall_zones_are_rejected_before_mutation(self):
        result = self.run_shell('''
config_foreach() { "$1" zone0; "$1" zone1; }
sync_firewall_device
''')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.calls(), [])

    def test_incomplete_defaults_block_start_before_live_sync_mutation(self):
        (self.root / 'run/firewall-install-pending').touch(mode=0o600)
        result = self.run_shell('sync_firewall_device')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_render_password_reference_permissions_and_router_dns(self):
        result = self.run_shell('render_conf', gateway='1', kill_switch='1', dns='tunnel',
            dns_servers='1.1.1.1 2606:4700:4700::1111', mtu='1280')
        self.assertEqual(result.returncode, 0, result.stderr)
        content = self.config()
        self.assertIn('forward = true\n', content)
        self.assertIn('dns_servers = "1.1.1.1, 2606:4700:4700::1111"\n', content)
        self.assertIn('mtu = 1280\n', content)
        self.assertNotIn('fixture-password', content)
        self.assertIn('password_file = ', content)
        self.assertEqual((self.root / 'run/client.conf').stat().st_mode & 0o777, 0o600)
        self.assertFalse(list((self.root / 'run').glob('.config.*')))

    def test_literal_backslashes_and_controls_cannot_inject_ini_keys(self):
        value = r'vpn.example:443\npost_up = touch /tmp/no-execution'
        result = self.run_shell('render_conf', server=value, proto='tcp\npost_down = bad',
            user='user\x7f\r\npassword_command = bad')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('server = "' + value + '"\n', self.config())
        lines = self.config().splitlines()
        self.assertFalse(any(line.startswith(('post_up =', 'post_down =', 'password_command =')) for line in lines))
        self.assertNotIn('\x7f', self.config())

    def test_failed_render_preserves_previous_config(self):
        for mtu in ('abc', '575', '16603', '999999999999999999999999999999999'):
            with self.subTest(mtu=mtu):
                result = self.run_shell('render_conf', mtu=mtu)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.config(), 'previous-config\n')
                self.assertFalse(list((self.root / 'run').glob('.config.*')))

    def test_earlier_write_error_is_not_hidden_by_later_logging_write(self):
        result = self.run_shell('ini_kv() { return 17; }; render_conf')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config(), 'previous-config\n')

    def test_publish_failure_preserves_previous_config_and_removes_temp(self):
        result = self.run_shell('mv() { return 17; }; render_conf')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config(), 'previous-config\n')
        self.assertFalse(list((self.root / 'run').glob('.config.*')))

    def test_secret_literal_roundtrip_and_boundaries(self):
        prefix = "quote'\"$()`\\;"
        value = prefix + 'x' * (4096 - len(prefix))
        result = self.run_shell('write_runtime_secret_value pass "$QELI_TEST_VALUE"', VALUE=value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'run/password').read_text(), value)
        self.assertEqual((self.root / 'run/password').stat().st_mode & 0o777, 0o600)
        for value in ('', 'x' * 4097, 'bad\x7fvalue', 'bad\nvalue'):
            with self.subTest(length=len(value)):
                old = (self.root / 'run/password').read_text()
                result = self.run_shell('write_runtime_secret_value pass "$QELI_TEST_VALUE"', VALUE=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / 'run/password').read_text(), old)

    def test_legacy_secret_migration_noop_does_not_commit(self):
        result = self.run_shell('migrate_legacy_secrets')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_status_reads_current_committed_flag_and_distinguishes_load_error(self):
        self.assertEqual(self.run_shell('status_enabled', enabled='1').returncode, 0)
        self.assertEqual(self.run_shell('status_enabled', enabled='0').returncode, 1)
        self.assertEqual(self.run_shell('status_enabled').returncode, 1)
        self.assertEqual(self.run_shell('config_load() { return 17; }; status_enabled').returncode, 2)

    def test_firewall_noop_does_not_commit_or_reload(self):
        result = self.run_shell('sync_firewall_device')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_firewall_failures_return_error_and_retry_committed_staged_values(self):
        for failure in ('delete', 'add_list', 'set', 'commit', 'reload'):
            with self.subTest(failure=failure):
                (self.root / 'device').write_text('qeli-old')
                (self.root / 'masq6').write_text('0')
                (self.root / 'calls').write_text('')
                result = self.run_shell('sync_firewall_device', FAIL=failure)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.root / 'run/firewall-pending').exists())
                result = self.run_shell('sync_firewall_device')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / 'run/firewall-pending').exists())
                self.assertEqual((self.root / 'device').read_text(), 'qeli0')
                self.assertEqual((self.root / 'masq6').read_text(), '1')
                self.assertEqual(self.calls()[-2:], ['commit', 'reload'])

    def test_firewall_reserved_namespace_rejects_before_mutation(self):
        for dev in ('br-lan', 'wan', 'qeli;bad', 'qeli' + 'x' * 12):
            with self.subTest(dev=dev):
                self.assertNotEqual(self.run_shell('sync_firewall_device', dev=dev).returncode, 0)
                self.assertEqual(self.calls(), [])

if __name__ == '__main__':
    unittest.main()
