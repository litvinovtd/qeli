"""Historical host-mutating benchmarks must refuse an ordinary invocation."""

import os
import runpy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent
RETIRED_SCENARIOS = (
    'perf_allmodes_prod.py', 'perf_ab_p3b1.py', 'perf_netns_cpu.py',
    'perf_modes_test.py', 'perf_prod_live_monitor.py', 'perf_facts.py',
)


class LegacyBenchmarkGuards(unittest.TestCase):
    def test_host_mutating_runners_refuse_before_credentials_or_network(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('QELI_')}
        for name in ('benchmark.py', 'bench_bonding.py'):
            with self.subTest(script=name):
                result = subprocess.run([sys.executable, '-B', str(SCRIPTS / name)],
                                        cwd=SCRIPTS.parent, env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('--allow-host-wide-benchmark', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_retired_production_scenarios_refuse_even_with_credentials_and_opt_in(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('QELI_')}
        for configured in (False, True):
            selected = dict(environment)
            if configured:
                selected.update(QELI_PROD_PASS='fixture-only', QELI_LAB_PASS='fixture-only',
                                QELI_BENCH_BEFORE_BIN='fixture-not-used',
                                QELI_CLIENT_LINK_DIR=str(SCRIPTS), QELI_LAB_IP='192.0.2.11',
                                QELI_TEST_USER='fixture', QELI_TEST_PW='fixture-only')
            for name in RETIRED_SCENARIOS:
                with self.subTest(script=name, configured=configured):
                    arguments = ['--allow-host-wide-benchmark'] if configured else []
                    result = subprocess.run([sys.executable, '-B', str(SCRIPTS / name), *arguments],
                                            cwd=SCRIPTS.parent, env=selected,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, '')
                    self.assertTrue(result.stderr.startswith('RETIRED:'), result.stderr)
                    self.assertIn('scripts/benchmark_isolated_lab.py', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_retired_imports_refuse_without_network(self):
        for name in RETIRED_SCENARIOS:
            with self.subTest(script=name), patch('socket.socket', side_effect=AssertionError('network during import')):
                with self.assertRaisesRegex(SystemExit, '^RETIRED:'):
                    runpy.run_path(str(SCRIPTS / name), run_name='audit_discovery')


if __name__ == '__main__':
    unittest.main()
