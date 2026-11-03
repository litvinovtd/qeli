#!/usr/bin/env python3
"""Diagnostic Android framework restart control, never a product acceptance gate."""
import json
import re
import time
from android_lab_ui import AndroidVpnSettings, wait_until

PACKAGE = "com.qeli.audit.restartcontrol"


def restart_control(arun, evidence, result):
    settings = AndroidVpnSettings(arun, evidence, result, "Q29 restart control", "control-")
    cells = []
    result["restart_control"] = {"cells": cells, "observation_window_seconds": 45}

    def pid():
        return arun("shell", "pidof", PACKAGE, check=False).stdout.strip()

    def log():
        return arun("shell", "logcat", "-d", "-s", "Q29Control:I").stdout

    def links():
        return arun("shell", "su", "0", "ip", "-o", "link", "show").stdout

    def tun_present():
        return bool(re.search(r"^\d+: tun\d", links(), re.M))

    def capture(mode, phase):
        for label, command in (
            ("services", ["dumpsys", "activity", "services", PACKAGE]),
            ("exit-info", ["dumpsys", "activity", "exit-info", PACKAGE]),
            ("vpn", ["dumpsys", "vpn_management"]),
            ("logcat", ["logcat", "-d"]),
            ("links", ["su", "0", "ip", "-o", "link", "show"]),
        ):
            value = arun("shell", *command, check=False).stdout
            (evidence / f"control-{mode}-{phase}-{label}.txt").write_text(value)

    arun("shell", "appops", "set", PACKAGE, "ACTIVATE_VPN", "allow")
    for mode, with_tun, lockdown in (("plain", False, False), ("vpn_open", True, False), ("vpn", True, True)):
        log_mode = "vpn" if with_tun else "plain"
        broadcast = arun("shell", "am", "broadcast", "--include-stopped-packages", "--receiver-foreground",
                         "-a", "com.qeli.audit.CONTROL_MODE", "-n", PACKAGE + "/.ModeReceiver",
                         "--ez", "with_tun", str(with_tun).lower())
        (evidence / f"control-{mode}-mode-broadcast.txt").write_text(broadcast.stdout + broadcast.stderr)
        wait_until(lambda: f"MODE with_tun={str(with_tun).lower()} committed=true" in log(),
                   "control receiver failed to persist mode")
        settings.open()
        settings.switch("Always-on VPN", True)
        settings.switch("Block connections without VPN", lockdown)
        wait_until(lambda: bool(pid()) and f"READY mode={log_mode} pid={pid()} " in log(),
                   f"OS did not start {mode} control service")
        old_pid = pid()
        assert re.fullmatch(r"[0-9]+", old_pid), old_pid
        state = arun("shell", "dumpsys", "activity", "services", PACKAGE).stdout
        assert "isForeground=true" in state and "startRequested=true" in state and "startCommandResult=3" in state, state
        assert tun_present() == with_tun, (mode, links())
        policy = {key: arun("shell", "settings", "get", "secure", key).stdout.strip()
                  for key in ("always_on_vpn_app", "always_on_vpn_lockdown")}
        assert policy == {"always_on_vpn_app": PACKAGE, "always_on_vpn_lockdown": "1" if lockdown else "0"}, policy
        capture(mode, "before")
        started = time.monotonic()
        arun("shell", "su", "0", "kill", "-9", old_pid)
        error = None
        try:
            wait_until(lambda: bool(pid()) and pid() != old_pid and f"READY mode={log_mode} pid={pid()} " in log(),
                       f"OS did not redeliver {mode} control within 45s", 45)
        except AssertionError as failure:
            error = str(failure)
        elapsed = round(time.monotonic() - started, 2)
        capture(mode, "after")
        new_pid = pid()
        ready = [line for line in log().splitlines() if new_pid and f"READY mode={log_mode} pid={new_pid} " in line]
        cell = dict(mode=mode, old_pid=old_pid, new_pid=new_pid, elapsed_seconds=elapsed,
                    status="NO_RESTART_OBSERVED" if error else "RESTART_OBSERVED", policy=policy,
                    ready_lines=ready, tun_after=tun_present())
        if error: cell["error"] = error
        else:
            assert len(ready) == 1 and "flags=1 " in ready[0] and "result=3" in ready[0], ready
            assert tun_present() == with_tun
        cells.append(cell)
        (evidence / "control-results.json").write_text(json.dumps(result["restart_control"], indent=2) + "\n")
        print("CONTROL_" + mode.upper() + "_" + cell["status"], flush=True)
        settings.open()
        settings.switch("Block connections without VPN", False)
        settings.switch("Always-on VPN", False)
        arun("shell", "am", "force-stop", PACKAGE)
        wait_until(lambda: not tun_present(), "control cleanup retained TUN")
    settings.forget()
    wait_until(lambda: any(value in arun("shell", "appops", "get", PACKAGE, "ACTIVATE_VPN").stdout
                          for value in ("ignore", "deny")), "control Forget did not revoke consent", 15)
    arun("shell", "am", "force-stop", PACKAGE)
    assert not tun_present()
    state = arun("shell", "dumpsys", "activity", "services", PACKAGE).stdout
    assert "ControlService" not in state, state
    assert arun("shell", "settings", "get", "secure", "always_on_vpn_app").stdout.strip() == "null"
    capture("cleanup", "final")
    result["restart_control"]["cleanup"] = "PASS"
    (evidence / "control-results.json").write_text(json.dumps(result["restart_control"], indent=2) + "\n")
