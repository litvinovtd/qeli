"""Router launcher state-root contract. Shell never creates/chmods recovery state."""
import shlex
from test_keenetic_templates import KeeneticFixture


class KeeneticStateRootTests(KeeneticFixture):
    def state_root(self, readlink):
        script = self.root / 'state-root.sh'
        script.write_text('. ' + shlex.quote(str(self.bundle / 'lifecycle.sh')) + '\n' +
                          'readlink() { ' + readlink + '; }\n' +
                          'chmod() { exit 21; }; mkdir() { exit 22; }\n' +
                          'qeli_export_state_directory || exit $?\n' +
                          'printf "%s" "$STATE_DIRECTORY"\n')
        return self.run_script(script)

    def test_both_templates_export_core_state_before_start(self):
        from test_keenetic_templates import ROOT
        for name in ['S99qeli', 'opkgtun/S99qeli']:
            source = (ROOT / 'release/keenetic' / name).read_text()
            self.assertLess(source.index('  qeli_export_state_directory ||'),
                            source.index('  "$BIN" --config "$QELI_LAUNCH_CONF" >>'))

    def test_resolves_var_only_and_keeps_original_physical_state(self):
        real = self.root / 'firmware-var'
        real.mkdir()
        protected = self.root / 'protected'
        protected.mkdir(mode=0o755)
        (real / 'lib').symlink_to(protected)
        result = self.state_root('[ "$*" = "-f /var" ] || return 19; '
                                 'printf "%s" "$QELI_FIXTURE_ROOT/firmware-var"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(real / 'lib/qeli'))
        self.assertEqual(protected.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(protected.iterdir()), [])

    def test_failure_and_relative_root_are_not_admitted(self):
        for body in ['return 17', 'printf relative', 'printf /missing-qeli-fixture-dir']:
            with self.subTest(body=body):
                result = self.state_root(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
