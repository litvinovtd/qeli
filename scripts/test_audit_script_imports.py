"""Offline discovery must never execute a manual lab/network mutation scenario."""
import ast
import contextlib
import io
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

MANUAL_SCENARIOS = ('test_0712_features.py', 'test_blocked_ips.py', 'test_blocked_settings.py', 'test_config_rejection.py', 'test_disconnect2.py', 'test_disconnect_during_connect.py', 'test_download_bonding.py', 'test_gateway_nat.py', 'test_kick.py', 'test_l3_user_limits.py', 'test_live_tunnel.py', 'test_maxsessions.py', 'test_multidevice.py', 'test_multipath_allmodes.py', 'test_multipath_bonding.py', 'test_multipath_resilience.py', 'test_panel_ipv6_e2e.py', 'test_panel_route_dns.py', 'test_push_matrix.py', 'test_route_push.py', 'test_tun_reclaim.py', 'test_udp_reap.py', 'test_user_reload.py', 'test_web_reload.py')


class AuditScriptImportTests(unittest.TestCase):
    def test_manual_scenarios_import_without_network_or_output(self):
        for name in MANUAL_SCENARIOS:
            with self.subTest(script=name):
                output = io.StringIO()
                with patch("socket.socket", side_effect=AssertionError("network during import")):
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                        runpy.run_path(str(Path(__file__).with_name(name)), run_name="audit_discovery")
                self.assertEqual(output.getvalue(), "")

    def test_manual_scenarios_execute_only_under_the_main_guard(self):
        for name in MANUAL_SCENARIOS:
            tree = ast.parse(Path(__file__).with_name(name).read_text(encoding="utf-8"))
            executable = []
            for index, node in enumerate(tree.body):
                if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    continue
                executable.append(node)
            with self.subTest(script=name):
                self.assertEqual(len(executable), 1)
                self.assertIsInstance(executable[0], ast.If)
                self.assertEqual(ast.unparse(executable[0].test), "__name__ == '__main__'")


if __name__ == "__main__":
    unittest.main()
