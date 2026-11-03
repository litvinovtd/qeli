"""Fail-closed benchmark stability with controlled SSH; no lab mutations."""
import contextlib
import io
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import stability_gate as gate

QUIET = {"processes": "sshd sshd\niperf3 iperf3 -s\n",
         "links": [{"ifname": "ens18", "linkinfo": {"info_kind": "ether"}}],
         "qdiscs": [{"kind": "fq_codel"}], "connections": ""}


class Connection:
    def __init__(self, rates=None, busy=False, close_fail=False, inspect_fail=False, after_busy=False):
        self.rates = iter(rates or [100] * 10)
        self.commands = []
        self.closed = 0
        self.busy = busy
        self.close_fail = close_fail
        self.inspect_fail = inspect_fail
        self.after_busy = after_busy
        self.inspections = 0

    def checked(self, command, label, timeout):
        self.commands.append(command)
        if "python3 -c " in command:
            self.inspections += 1
            if self.inspect_fail:
                raise RuntimeError("probe failed")
            data = dict(QUIET)
            if self.busy or (self.after_busy and self.inspections > 1):
                data["processes"] += "qeli /usr/bin/qeli daemon\n"
            return json.dumps(data)
        rate = next(self.rates)
        if isinstance(rate, Exception):
            raise rate
        return json.dumps({"end": {"sum_received": {"bits_per_second": rate * 1e6}}})

    def close(self):
        self.closed += 1
        if self.close_fail:
            raise RuntimeError("controlled close failure")


class StabilityTests(unittest.TestCase):
    def exercise(self, server=None, client=None, env=None, connect_error=None):
        server, client = server or Connection(), client or Connection()
        calls = []
        def connect(*args):
            calls.append(args)
            if connect_error and len(calls) == 2:
                raise RuntimeError("second connection refused")
            return server if len(calls) == 1 else client
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "result.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(env or {}, connect, lambda _: None, target)
            data = json.loads(target.read_text()) if target.exists() else None
        return rc, data, server, client, calls

    def test_success_all_samples_and_both_directions(self):
        rc, data, s, c, calls = self.exercise()
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        for row in data["directions"].values():
            self.assertEqual(row["stats"]["n"], 5)
            self.assertEqual(len(row["samples"]), 5)
        measured = [cmd for cmd in c.commands if cmd.startswith("timeout 40")]
        self.assertEqual(len(measured), 10)
        self.assertEqual(sum("-R " in cmd for cmd in measured), 5)
        self.assertEqual((s.closed, c.closed), (1, 1))

    def test_failed_requested_samples_refuse(self):
        rc, data, *_ = self.exercise(client=Connection([100, 100] + [RuntimeError("failed")] * 3 + [100] * 5))
        self.assertEqual(rc, 1)
        self.assertIsNone(data["directions"]["up"]["stats"])
        self.assertEqual(len(data["directions"]["up"]["samples"]), 5)

    def test_unrounded_threshold(self):
        rc, data, *_ = self.exercise(client=Connection([100, 91.96] + [100] * 8))
        self.assertEqual(rc, 1)
        self.assertGreater(data["directions"]["up"]["stats"]["spread_pct"], 8)

    def test_one_noisy_direction_refuses(self):
        self.assertEqual(self.exercise(client=Connection([100] * 5 + [100, 80, 100, 100, 100]))[0], 1)

    def test_stats_invalid_and_partial_values(self):
        for values in ([100, None], [100, 0], [100, -1], [100, True],
                       [100, "100"], [100, math.nan], [100, math.inf], [], [100]):
            with self.subTest(values=values):
                self.assertIsNone(gate.stats(values))
        self.assertGreater(gate.stats([100, 91.96])["spread_pct"], 8)

    def test_zero_spread_limit(self):
        self.assertEqual(self.exercise(env={"QELI_GATE_MAX_SPREAD": "0"})[0], 0)
        self.assertEqual(self.exercise(env={"QELI_GATE_MAX_SPREAD": "0"}, client=Connection([100, 99] + [100] * 8))[0], 1)

    def test_invalid_settings_refuse_before_ssh(self):
        for key, values in {"QELI_GATE_RUNS": ["1", "0", "-1", "21", "bad"],
                            "QELI_GATE_MAX_SPREAD": ["nan", "inf", "-1", "100", "bad"],
                            "QELI_GATE_PORT": ["0", "65536", "x"],
                            "QELI_LAB_SERVER": ["host; touch /tmp/unwanted", "10.66.116.11"]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    rc, data, _, _, calls = self.exercise(env={key: value})
                    self.assertEqual(rc, 1)
                    self.assertEqual(calls, [])
                    self.assertIsNone(data)

    def test_optional_ssh_dependency_not_needed_on_import_or_invalid_settings(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-c",
            "import runpy; runpy.run_path(" + repr(str(Path(gate.__file__).resolve())) + ")"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_busy_refuses_before_measurement_without_mutation(self):
        rc, data, s, c, _ = self.exercise(server=Connection(busy=True))
        self.assertEqual(rc, 1)
        self.assertEqual(data["directions"], {})
        self.assertEqual(c.commands, [])
        self.assertEqual((s.closed, c.closed), (1, 1))
        self.assertTrue(all(cmd.startswith("python3 -c ") for cmd in s.commands))

    def test_post_probe_busy_refuses_previous_good_rates(self):
        rc, data, *_ = self.exercise(server=Connection(after_busy=True))
        self.assertEqual(rc, 1)
        self.assertEqual(data["directions"]["up"]["stats"]["n"], 5)
        self.assertFalse(data["verdict_quiet"])

    def test_probe_failure_closes_both(self):
        rc, _, s, c, _ = self.exercise(server=Connection(inspect_fail=True))
        self.assertEqual(rc, 1)
        self.assertEqual((s.closed, c.closed), (1, 1))

    def test_second_connection_failure_closes_first(self):
        rc, data, s, c, _ = self.exercise(connect_error=True)
        self.assertEqual(rc, 1)
        self.assertEqual((s.closed, c.closed), (1, 0))
        self.assertTrue(data["errors"])

    def test_close_failure_does_not_skip_other_close_or_accept(self):
        rc, data, s, c, _ = self.exercise(client=Connection(close_fail=True))
        self.assertEqual(rc, 1)
        self.assertEqual((s.closed, c.closed), (1, 1))
        self.assertTrue(data["errors"])

    def test_result_failure_refuses(self):
        with patch.object(gate, "save_result", side_effect=OSError("disk full")):
            self.assertEqual(self.exercise()[0], 1)

    def test_atomic_result_failure_preserves_old_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "result.json"
            target.write_text("old")
            with patch.object(gate.os, "replace", side_effect=OSError("denied")):
                with self.assertRaises(OSError):
                    gate.save_result(target, {"verdict_quiet": False})
            self.assertEqual(target.read_text(), "old")
            self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_nonfinite_result_never_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "result.json"
            with self.assertRaises(ValueError):
                gate.save_result(target, {"rate": math.nan})
            self.assertFalse(target.exists())

    def test_nonpositive_measurements_record_failure(self):
        for rate in (0, -1, math.inf, math.nan):
            with self.subTest(rate=rate):
                result = gate.measure(Connection([rate]), "10.66.116.10", 5201, False)
                self.assertIsNone(result["mbps"])
                self.assertIn("error", result)

    def test_inspect_detects_tunnels_shapers_and_iperf_clients(self):
        for field, value in (
            ("processes", "qemu-system-x86 qemu-system-x86_64\n"),
            ("processes", "iperf3 iperf3 -c 10.66.116.10\n"),
            ("processes", "top top -b\n"),
            ("links", [{"ifname": "vpn0", "linkinfo": {"info_kind": "tun"}}]),
            ("qdiscs", [{"kind": "netem"}]),
            ("connections", "ESTAB ..."),
        ):
            class Probe:
                def checked(self, *args, **kwargs):
                    data = dict(QUIET); data[field] = value
                    return json.dumps(data)
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(RuntimeError, "lab is busy"):
                    gate.inspect(Probe(), 5201)

    def test_invalid_probe_shape_refuses(self):
        class Probe:
            def checked(self, *args, **kwargs):
                return '{"processes": 0}'
        with self.assertRaises(RuntimeError):
            gate.inspect(Probe(), 5201)


if __name__ == "__main__":
    unittest.main()
