#!/usr/bin/env python3
"""Real Android power states and isolated TCP reset/recovery; no shell-UID traffic gate."""
import json
import re
import subprocess
import time
from android_lab_ui import wait_until
from roaming_android_sleep_wake_gate import parse_idle_flags, parse_screen_awake


def power_lifecycle(arun, evidence, probe, result, *, endurance=False, tcp_fault=True, dns_probe=None):
    checks = result["power_lifecycle"] = {"cycles": [], "endurance": endurance}
    def save(name, value):
        (evidence / name).write_text(value)
        return value
    def logs():
        return arun("shell", "logcat", "-d", "-s", "VpnSvc:D").stdout
    def counts():
        value = logs()
        return dict(auth=value.count("Auth OK:"), plans=len(re.findall(r"Native NetworkPlan [0-9]+ APPLIED:", value)))
    def snapshot(label):
        pid = arun("shell", "pidof", "com.qeli").stdout.strip()
        assert re.fullmatch(r"[0-9]+", pid), pid
        links = save(label + "-links.txt", arun("shell", "su", "0", "ip", "-o", "link", "show").stdout)
        tun = re.findall(r"(?m)^([0-9]+): (tun[0-9]+):", links)
        assert len(tun) == 1, links
        index, name = tun[0]
        addresses = arun("shell", "su", "0", "ip", "-o", "addr", "show", "dev", name).stdout
        save(label + "-addresses.txt", addresses)
        state = save(label + "-services.txt", arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout)
        assert "isForeground=true" in state and "startRequested=true" in state, state
        power = save(label + "-power.txt", arun("shell", "dumpsys", "power").stdout)
        save(label + "-vpn.txt", arun("shell", "dumpsys", "vpn_management").stdout)
        return dict(pid=pid, tun=name, ifindex=index, addresses=addresses), power
    original_idle = save("power-original-deviceidle.txt", arun("shell", "dumpsys", "deviceidle").stdout)
    deep, light = parse_idle_flags(original_idle)
    original_battery = save("power-original-battery.txt", arun("shell", "dumpsys", "battery").stdout)
    awake = parse_screen_awake(arun("shell", "dumpsys", "power").stdout)
    whitelist = save("power-whitelist.txt", arun("shell", "dumpsys", "deviceidle", "whitelist").stdout)
    assert not re.search(r"(?m)^.*?,com\.qeli,", whitelist), "Qeli has a battery exemption"
    checks["battery_exemption"] = False
    try:
        phases = (("screen-off", False, 30), ("deep-idle-01", True, 120), ("deep-idle-02", True, 120)) if endurance else (("screen-off", False, 5), ("deep-idle", True, 20))
        for label, forced, duration in phases:
            before, _ = snapshot("power-" + label + "-before")
            before_counts = counts()
            before_wake = logs().count("same network, keeping the tunnel")
            arun("shell", "dumpsys", "battery", "unplug")
            arun("shell", "input", "keyevent", "223")
            if forced:
                arun("shell", "dumpsys", "deviceidle", "enable", "deep")
                entered = arun("shell", "dumpsys", "deviceidle", "force-idle", "deep").stdout
                save("power-" + label + "-enter.txt", entered)
                assert arun("shell", "dumpsys", "deviceidle", "get", "deep").stdout.strip() == "IDLE", entered
            wait_until(lambda: not parse_screen_awake(arun("shell", "dumpsys", "power").stdout), "screen did not turn off", 10)
            started = time.monotonic()
            observations = []
            while time.monotonic() - started < duration:
                time.sleep(min(15, max(0, duration - (time.monotonic() - started))))
                idle_sample = arun("shell", "dumpsys", "deviceidle", "get", "deep").stdout.strip()
                awake_sample = parse_screen_awake(arun("shell", "dumpsys", "power").stdout)
                assert not awake_sample and (not forced or idle_sample == "IDLE"), (label, idle_sample, awake_sample)
                observations.append(dict(elapsed_seconds=round(time.monotonic()-started,2), idle=idle_sample, awake=awake_sample))
                (evidence / ("power-" + label + "-observations.json")).write_text(json.dumps(observations, indent=2)+"\n")
            asleep, state = snapshot("power-" + label + "-asleep")
            assert asleep == before, (before, asleep)
            assert not parse_screen_awake(state)
            idle = arun("shell", "dumpsys", "deviceidle", "get", "deep").stdout.strip()
            if forced: assert idle == "IDLE", idle
            save("power-" + label + "-idle-state.txt", idle)
            arun("shell", "dumpsys", "deviceidle", "unforce")
            arun("shell", "dumpsys", "deviceidle", "enable" if deep else "disable", "deep")
            arun("shell", "dumpsys", "battery", "reset")
            arun("shell", "input", "keyevent", "224")
            arun("shell", "wm", "dismiss-keyguard")
            wait_until(lambda: logs().count("same network, keeping the tunnel") > before_wake, "same-network wake marker absent", 20)
            if endurance:
                replies = [probe("Q29PROTECTED", True, label="power-"+label+"-wake-"+f+"-"+p, family=f, protocol=p, payload_bytes=16384 if p=="tcp" else 257) for f in ("ipv4","ipv6") for p in ("tcp","udp")]
            else:replies = [probe("Q29PROTECTED", True, label="power-" + label + "-wake")]
            if dns_probe is not None:dns_probe("power-"+label, True, modes=("system",))
            after, _ = snapshot("power-" + label + "-after")
            assert after == before and counts() == before_counts, (before, after, before_counts, counts())
            cell = dict(name=label, requested_sleep_seconds=duration, elapsed_seconds=round(time.monotonic()-started,2),
                        idle_state=idle, observations=observations, before=before, asleep=asleep, after=after, counts=before_counts, wake_probe=replies[0], wake_probes=replies, status="PASS")
            checks["cycles"].append(cell)
            print("POWER_" + label.upper() + "_PASS", flush=True)
        if tcp_fault:
            before, _ = snapshot("power-tcp-reset-before")
            before_counts = counts()
            errors = len(re.findall(r"Native transport error", logs()))
            rule = ["-p", "tcp", "--dport", "24966", "-m", "comment", "--comment", "q29-private-power-reset", "-j", "REJECT", "--reject-with", "tcp-reset"]
            subprocess.run(["iptables", "-I", "INPUT", "1", *rule], check=True, capture_output=True, text=True)
            try:
                wait_until(lambda: len(re.findall(r"Native transport error", logs())) > errors, "TCP reset did not reach client transport", 15)
                denied = probe("Q29BLOCKED", False, label="power-tcp-reset-blocked")
                retained, _ = snapshot("power-tcp-reset-active")
                assert retained == before, (before, retained)
                save("power-tcp-reset-rule.txt", subprocess.check_output(["iptables", "-S", "INPUT"], text=True))
            finally:
                subprocess.run(["iptables", "-D", "INPUT", *rule], check=True, capture_output=True, text=True)
            wait_until(lambda: counts()["plans"] > before_counts["plans"], "TCP reset recovery did not apply a fresh plan", 40)
            recovered = probe("Q29PROTECTED", True, label="power-tcp-reset-recovered")
            after, _ = snapshot("power-tcp-reset-after")
            assert after == before and counts()["auth"] > before_counts["auth"], (before, after, counts())
            assert "Android TUN reused for NetworkPlan" in logs()
            checks["tcp_reset"] = dict(status="PASS", before=before, fault=retained, after=after,
                                       before_counts=before_counts, after_counts=counts(), blocked_probe=denied, recovered_probe=recovered)
            print("POWER_TCP_RESET_RECOVERY_PASS", flush=True)
    finally:
        arun("shell", "dumpsys", "deviceidle", "unforce", check=False)
        arun("shell", "dumpsys", "deviceidle", "enable" if deep else "disable", "deep", check=False)
        arun("shell", "dumpsys", "deviceidle", "enable" if light else "disable", "light", check=False)
        arun("shell", "dumpsys", "battery", "reset", check=False)
        arun("shell", "input", "keyevent", "224" if awake else "223", check=False)
        save("power-lifecycle-logcat.log", logs())
        (evidence / "power-results.json").write_text(json.dumps(checks, indent=2) + "\n")
    idle_after = save("power-restored-deviceidle.txt", arun("shell", "dumpsys", "deviceidle").stdout)
    assert parse_idle_flags(idle_after) == (deep, light)
    assert parse_screen_awake(arun("shell", "dumpsys", "power").stdout) == awake
    battery_after = save("power-restored-battery.txt", arun("shell", "dumpsys", "battery").stdout)
    for key in ("AC powered", "USB powered", "Wireless powered"):
        assert re.search(key + r": (true|false)", original_battery).group(1) == re.search(key + r": (true|false)", battery_after).group(1)
    checks["power_settings_restored"] = "PASS"
    (evidence / "power-results.json").write_text(json.dumps(checks, indent=2) + "\n")
