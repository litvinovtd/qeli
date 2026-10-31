#!/usr/bin/env python3
"""Run the previously disconnected, self-contained audit regressions.

Only reviewed modules are admitted. Linux shell fixtures are separate from portable
models. Lab/network mutation scenarios and tests requiring SDK/native/rootfs inputs
are intentionally outside this runner. A skip or zero tests cannot qualify a suite.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest

SUITES = {
    "portable": (
        "test_android_dns_fixture", "test_android_handover_epochs",
        "test_android_resolver_diagnostics", "test_android_startup_state",
        "test_android_trusted_lockdown", "test_audit_script_imports",
        "test_dns_test_server", "test_keenetic_verify",
        "test_roaming_android_sleep_wake_gate", "test_roaming_control_stats",
        "test_router_artifact", "test_router_build", "test_router_toolchain", "test_linux_release", "test_linux_release_fetch", "test_linux_release_cpu",
        "test_tap_ipv6_control_probe", "test_verify_ios_ipa",
    ),
    "linux": (
        "test_roaming_android_udp_grace_expiry_gate", "test_roaming_process_probe",
        "test_router_checkout", "test_router_source", "test_keenetic_templates",
        "test_keenetic_state", "test_keenetic_install_rollback",
        "test_openwrt_init", "test_openwrt_defaults",
    ),
}


def qualified(result: unittest.TestResult, planned: int) -> bool:
    return (planned > 0 and result.testsRun == planned and result.wasSuccessful()
            and not result.skipped and not result.expectedFailures)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, choices=tuple(SUITES))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES[args.group])
    planned = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = qualified(result, planned)
    report = {"group": args.group, "modules": list(SUITES[args.group]),
              "planned": planned, "run": result.testsRun, "skipped": result.skipped,
              "failures": result.failures, "errors": result.errors,
              "expected_failures": result.expectedFailures,
              "status": "PASS" if passed else "FAIL"}
    # Serialize IDs, not TestCase objects; preserve traceback and skip reason.
    for field in ("skipped", "failures", "errors", "expected_failures"):
        report[field] = [(str(test), reason) for test, reason in report[field]]
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"AUDIT_CONTRACT_SUITE {args.group} {report['status']} "
          f"run={result.testsRun}/{planned} skipped={len(result.skipped)}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
