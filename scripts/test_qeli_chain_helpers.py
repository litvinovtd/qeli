"""Portable, non-root contract checks; kernel integration is a separate lab gate."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("chain_guard", ROOT / "scripts/qeli_chain_guard.py")
guard = importlib.util.module_from_spec(spec)
# Import-only shim on Windows; these tests never call flock or install rules.
with patch.dict(sys.modules, {"fcntl": SimpleNamespace()} if sys.platform == "win32" else {}):
    spec.loader.exec_module(guard)


class GuardContract(unittest.TestCase):
    def test_iproute_table_string_and_number(self):
        for table in (208, "208"):
            self.assertTrue(guard.rule_owned({"table": table, "iif": "qeli-in"}, 208, "qeli-in"))
        self.assertFalse(guard.rule_owned({"table": 208, "iif": "foreign"}, 208, "qeli-in"))
        self.assertFalse(guard.rule_owned({"table": 209, "iif": "qeli-in"}, 208, "qeli-in"))

    def test_foreign_chain_refused_without_mutation(self):
        with patch.object(guard, "chain_exists", return_value=True), patch.object(guard, "ipt") as ipt:
            with self.assertRaisesRegex(RuntimeError, "foreign chain"):
                guard.publish("iptables", "qeli-in", "qeli-out", False, False)
            ipt.assert_not_called()

    def test_populate_before_jump_both_families(self):
        for ipv6, binary in ((False, "iptables"), (True, "ip6tables")):
            calls, rows = [], []

            def ipt(tool, *args, **kwargs):
                self.assertEqual(tool, binary)
                calls.append(args)
                if args[0] == "-A":
                    rows.append("-A " + " ".join(args[1:]))
                if args[:2] == ("-C", "FORWARD"):
                    return SimpleNamespace(returncode=1)
                return SimpleNamespace(returncode=0, stdout="\n".join(rows))

            with patch.object(guard, "chain_exists", return_value=False), patch.object(guard, "ipt", side_effect=ipt):
                guard.publish(binary, "qeli-in", "qeli-out", ipv6, False)
            self.assertEqual(calls[-1], ("-I", "FORWARD", "1", "-i", "qeli-in", "-j", guard.CHAIN))
            self.assertIn("-A QELI_CHAIN_IN -j DROP", rows)
            self.assertEqual(len(rows), 1 if ipv6 else 2)
            if not ipv6:
                self.assertEqual(rows[0], "-A QELI_CHAIN_IN -o qeli-out -j RETURN")

    def test_unexpected_owned_rule_is_not_accepted(self):
        fake = SimpleNamespace(returncode=0, stdout="-A QELI_CHAIN_IN -j DROP\n-A QELI_CHAIN_IN -j ACCEPT")
        with patch.object(guard, "chain_exists", return_value=True), patch.object(guard, "ipt", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "unexpected rule"):
                guard.publish("ip6tables", "qeli-in", "qeli-out", True, True)

    def test_service_order_and_protection_lifetime(self):
        units = ROOT / "release/examples/linux-chain"
        watcher = (units / "qeli-chain-guard.service").read_text()
        ingress = (units / "qeli-chain-in.service").read_text()
        self.assertIn("ExecStartPre=/usr/bin/python3", watcher)
        self.assertIn(" --once", watcher)
        self.assertFalse(any(x.startswith("ExecStop=") for x in watcher.splitlines()))
        self.assertIn("After=network-online.target qeli-chain-guard.service", ingress)
        self.assertIn("ExecStartPre=/usr/local/libexec/qeli-chain-ready", ingress)
        self.assertNotIn("Requires=qeli-chain-guard.service", ingress)
        self.assertIn("Restart=always", ingress)


if __name__ == "__main__":
    unittest.main()
