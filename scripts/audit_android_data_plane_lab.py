#!/usr/bin/env python3
"""Offline Android payload gate: disposable readonly AVD and Qeli in fresh NET/MNT/PID.

No working service, host firewall, physical carrier or production profile is used.
The Linux binary and uploaded APK bytes must be supplied by a qualified caller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from audit_udp_handshake_contracts import hashed, stop
from android_lab_ui import AndroidVpnSettings, wait_until

EMULATOR_MEMORY_MB = 1536


def admitted_guest_memory(meminfo, requested_mb=EMULATOR_MEMORY_MB):
    """Reject silent emulator RAM clamping before measuring application behavior."""
    totals = re.findall(r"^MemTotal:\s+([0-9]+)\s+kB\s*$", meminfo, re.M)
    assert len(totals) == 1, "guest MemTotal missing or ambiguous"
    total_kib = int(totals[0])
    # The guest kernel reserves part of configured RAM; MemTotal cannot exceed it.
    assert requested_mb * 1024 * 3 // 4 <= total_kib <= requested_mb * 1024, (
        "guest RAM differs from bounded fixture", requested_mb, total_kib)
    return dict(requested_mb=requested_mb, actual_guest_total_kib=total_kib,
                explicit_lowram_override=True)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def userdata():
    result = {}
    for path in sorted(Path("/root/.android/avd/test.avd").glob("userdata*")):
        if path.is_file() and path.suffix in (".img", ".qcow2"):
            info = path.stat()
            result[path.name] = dict(size=info.st_size, mtime_ns=info.st_mtime_ns, sha256=sha(path))
    assert result, "no persistent AVD userdata found"
    return result


class Echo:
    """Independent framed TCP/reversed payload and UDP tagged reply sinks."""
    def __init__(self, output, hosts=None):
        self.output = output
        self.sockets = []
        self.threads = []
        self.closing = threading.Event()
        self.lock = threading.Lock()
        self.rows = []
        for family, host in (hosts or ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::"))):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 26000))
                sock.settimeout(.5)
                if kind == socket.SOCK_STREAM:
                    sock.listen(4)
                self.sockets.append(sock)
                thread = threading.Thread(target=self.serve, args=(sock, kind), daemon=True)
                thread.start()
                self.threads.append(thread)

    def record(self, protocol, peer, payload):
        with self.lock:
            self.rows.append(dict(protocol=protocol, peer=peer[0], bytes=len(payload),
                                  payload_sha256=hashlib.sha256(payload).hexdigest(), unix_time=time.time()))
            self.output.write_text(json.dumps(self.rows, indent=2) + "\n")

    def serve(self, sock, kind):
        try:
            while not self.closing.is_set():
                try:
                    if kind == socket.SOCK_DGRAM:
                        payload, peer = sock.recvfrom(65535)
                        sock.sendto(b"Q29:" + payload, peer)
                        self.record("udp", peer, payload)
                    else:
                        client, peer = sock.accept()
                        try:
                            with client:
                                client.settimeout(10)
                                def exact(length):
                                    data = b""
                                    while len(data) < length:
                                        chunk = client.recv(length - len(data))
                                        if not chunk:
                                            raise EOFError("TCP echo client closed early")
                                        data += chunk
                                    return data
                                length = struct.unpack("!I", exact(4))[0]
                                assert 0 < length <= 65536
                                payload = exact(length)
                                client.sendall(struct.pack("!I", length) + payload[::-1])
                                self.record("tcp", peer, payload)
                        except (EOFError, OSError):
                            # A cancelled/failed client must not kill the shared listener.
                            continue
                except socket.timeout:
                    continue
        except (OSError, EOFError):
            if not self.closing.is_set():
                with self.lock:
                    self.rows.append(dict(error=traceback.format_exc()))
                    self.output.write_text(json.dumps(self.rows, indent=2) + "\n")

    def close(self):
        self.closing.set()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(12)
            assert not thread.is_alive(), "echo worker remained"


class DnsFixture:
    """Tiny offline A/AAAA authority; only unique q29-*.test questions get answers."""
    def __init__(self, output):
        self.output = output
        self.rows = []
        self.closing = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("198.19.0.53", 53))
        self.sock.settimeout(.5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.closing.is_set():
                try:
                    data, peer = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
                from audit_android_dns_fixture import response
                reply, row = response(data)
                self.sock.sendto(reply, peer)
                self.rows.append(dict(row, peer=peer[0]))
                self.output.write_text(json.dumps(self.rows, indent=2) + "\n")
        except BaseException:
            if not self.closing.is_set():
                self.rows.append(dict(error=traceback.format_exc()))
                self.output.write_text(json.dumps(self.rows, indent=2) + "\n")

    def close(self):
        self.closing.set()
        self.sock.close()
        self.thread.join(2)
        assert not self.thread.is_alive(), "DNS worker remained"


def system_lifecycle(arun, evidence, echo, result, *, dot=None):
    """Use real Settings and externally kill the product process, outside instrumentation."""
    settings = AndroidVpnSettings(arun, evidence, result, "Qeli")
    open_settings, switch = settings.open, settings.switch
    def logs():
        return arun("shell", "logcat", "-d", "-s", "VpnSvc:D", "VpnRecovery:I", "Q29System:I").stdout
    def probe(tag, expect_reply, label=None, family="ipv4", protocol="udp", payload_bytes=None):
        label = label or tag
        assert family in ("ipv4", "ipv6") and protocol in ("tcp", "udp")
        payload_bytes = payload_bytes or len(tag)
        payload = bytes((i * 31 + 17) % 251 for i in range(payload_bytes))
        payload = tag.encode() + payload[len(tag):]
        expected = payload[::-1] if protocol == "tcp" else b"Q29:" + payload
        needle = f"COMPLETE tag={tag} uid={probe_uid} family={family} protocol={protocol} bytes={payload_bytes} "
        initial = sum(needle in line for line in arun("shell", "logcat", "-d", "-s", "Q29Probe:I").stdout.splitlines())
        before = len(echo.rows)
        broadcast = arun("shell", "am", "broadcast", "--include-stopped-packages", "--receiver-foreground",
                         "-n", "com.qeli.test/com.qeli.SystemNetworkProbeReceiver", "--es", "tag", tag, "--es", "family", family, "--es", "protocol", protocol, "--ei", "payload_bytes", str(payload_bytes))
        (evidence / (label + "-broadcast.txt")).write_text(broadcast.stdout + broadcast.stderr)
        wait_until(lambda: sum(needle in line for line in arun("shell", "logcat", "-d", "-s", "Q29Probe:I").stdout.splitlines()) > initial, "independent probe did not finish", 8)
        output = arun("shell", "logcat", "-d", "-s", "Q29Probe:I").stdout
        line = [line for line in output.splitlines() if needle in line][-1]
        (evidence / (label + "-probe.txt")).write_text(line + "\n")
        time.sleep(.2)
        digest = hashlib.sha256(payload).hexdigest()
        seen = [row for row in echo.rows[before:] if row.get("payload_sha256") == digest and row.get("protocol") == protocol and (":" in row["peer"]) == (family == "ipv6")]
        if expect_reply:
            assert "reply=Q29:" + tag in line and len(seen) == 1, (line, seen)
            udp_profile = result["suite"] in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") and result["recovery_transport"] != "tcp"
            assert f"sha256={digest}" in line and f"reply_sha256={hashlib.sha256(expected).hexdigest()}" in line and seen[0]["bytes"] == payload_bytes, (line, seen)
            if tag != "Q29BASELINE":
                prefix = ("fd86:29:2:" if udp_profile else "fd86:29:1:") if family == "ipv6" else ("10.87.0." if udp_profile else "10.86.0.")
                assert seen[0]["peer"].startswith(prefix), seen
        else:
            assert "reply=Q29:" + tag not in line and "error=" in line and not seen, (line, seen)
        return dict(uid=int(probe_uid), echoed=len(seen), expected_reply=expect_reply, family=family, protocol=protocol, payload_bytes=payload_bytes, payload_sha256=digest, reply_sha256=hashlib.sha256(expected).hexdigest())
    uid_text = arun("shell", "cmd", "package", "list", "packages", "-U", "com.qeli").stdout
    uid_rows = dict(re.findall(r"package:(com\.qeli(?:\.test)?) uid:([0-9]+)", uid_text))
    assert set(uid_rows) == {"com.qeli", "com.qeli.test"}, uid_text
    probe_uid = uid_rows["com.qeli.test"]
    assert int(probe_uid) >= 10000 and probe_uid != uid_rows["com.qeli"]
    result["probe_uids"] = uid_rows
    bursts = None
    if result["leak_bursts_enabled"]:
        from audit_android_leak_bursts import LeakBursts
        bursts = LeakBursts(arun, evidence, echo, result)
        bursts.run("physical-baseline", tag="Q29BASELINE")
    result["app_probe_baseline"] = probe("Q29BASELINE", True, family="ipv6" if result["carrier_fixture"] == "nat64" else "ipv4")
    policy_applied = logs().count("Native NetworkPlan 1 APPLIED:")
    # Start the saved profile through the OS after Debug instrumentation or Release UI import.
    arun("shell", "am", "start", "-n", "com.qeli/.MainActivity")
    open_settings(); switch("Always-on VPN", True)
    dns_probe = None
    if result["suite"] == "startup":
        from audit_android_startup_dns import StartupDns
        startup = StartupDns(arun, evidence, result)
        dns_probe = startup.probe
        dns_probe("physical-baseline", True, modes=("raw",))
        startup.enable_lockdown(settings, bursts)
    else:
        if result["suite"] in ("endurance","private-dns"):
            from audit_android_startup_dns import StartupDns
            startup = StartupDns(arun, evidence, result);dns_probe = startup.probe
        switch("Block connections without VPN", True)
    wait_until(lambda: "kill_switch=true" in logs() and logs().count("Native NetworkPlan 1 APPLIED:") > policy_applied,
               "system-owned saved kill-switch profile did not start", 30)
    policy = {key: arun("shell", "settings", "get", "secure", key).stdout.strip()
              for key in ("always_on_vpn_app", "always_on_vpn_lockdown")}
    assert policy == {"always_on_vpn_app": "com.qeli", "always_on_vpn_lockdown": "1"}, policy
    result["system_policy"] = policy
    if result.get("ui_connect_restart_enabled"):
        ui=AndroidVpnSettings(arun,evidence,result,"Qeli",prefix="connect-")
        arun("shell","am","start","-n","com.qeli/.MainActivity")
        tree=ui.ui("connected")
        tab=ui.text_node(tree,"Connection");assert tab is not None
        ui.tap(tab);tree=ui.ui("connection-tab")
        def ring(tree):
            node=next((v for v in tree.iter("node") if v.get("resource-id")=="com.qeli:id/ringConnect"),None)
            assert node is not None,"connect ring absent"
            return node
        old_count=logs().count("Android VPN CONNECTED:")
        ui.tap(ring(tree))
        wait_until(lambda:not re.search(r"^\d+: tun\d",arun("shell","su","0","ip","-o","link","show").stdout,re.M),"UI disconnect left TUN",20)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            tree=ui.ui("disconnected")
            if any(v.get("resource-id")=="com.qeli:id/tvStatus" and v.get("text")=="Disconnected" for v in tree.iter("node")):break
        else:raise AssertionError("UI did not finish disconnect")
        blocked=probe("Q29PROTECTED",False,label="ui-disconnected-lockdown")
        ui.tap(ring(tree))
        wait_until(lambda:logs().count("Android VPN CONNECTED:")>old_count,"Release UI connect did not publish a new VPN",30)
        result["ui_connect_restart"]={"status":"PASS","instrumentation":"NOT_RUN","blocked":blocked,
            "payloads":[probe("Q29PROTECTED",True,label="ui-reconnect-"+f+"-"+p,family=f,protocol=p,payload_bytes=16384 if p=="tcp" else 257) for f in ("ipv4","ipv6") for p in ("tcp","udp")]}
    if dns_probe is not None:
        dns_probe("connected", True)
        if result["resolver_diagnostics_enabled"]:startup.diagnose()
    result["app_probe_lockdown_connected"] = probe("Q29PROTECTED", True)
    if result["android_build_type"] == "release" and result["suite"] != "handover":
        # Release UI import has no instrumented bootstrap. Exercise both families and
        # socket protocols with the independent ordinary-UID receiver before faults.
        result["release_start_payloads"] = [
            probe("Q29PROTECTED", True, label="release-start-" + family + "-" + protocol,
                  family=family, protocol=protocol,
                  payload_bytes=16384 if protocol == "tcp" else 257)
            for family in ("ipv4", "ipv6") for protocol in ("tcp", "udp")
        ]
    if bursts is not None:bursts.run("connected-steady")
    if result["suite"] == "startup":
        result["startup_dns_matrix"] = "PASS"
    elif result["suite"] == "nat64":
        # The emulator modem publishes a fixed IPv4-only Cellular network even
        # with -net-tap. Qualify this IPv6-only carrier independently; an invalid
        # Cellular transition must not be counted as a NAT64 handover PASS.
        (evidence / "nat64-connected-connectivity.txt").write_text(arun("shell", "dumpsys", "connectivity").stdout)
        (evidence / "nat64-connected-links.txt").write_text(arun("shell", "su", "0", "ip", "-o", "addr", "show").stdout)
        result["nat64_payload_matrix"] = "PASS"
    elif result["suite"] == "handover":
        from audit_android_network_handover import network_handover
        if result.get("trusted_lockdown_handover_enabled"):
            from audit_android_trusted_lockdown import enable_trusted_wifi
            enable_trusted_wifi(arun,evidence,result)
        network_handover(arun, evidence, probe, result, bursts=bursts)
        if result.get("trusted_lockdown_handover_enabled"):result["trusted_wifi_lockdown"]["status"]="PASS"
        open_settings()
    elif result["suite"] == "recovery":
        from audit_android_udp_recovery import udp_recovery
        udp_recovery(arun, evidence, probe, result)
        open_settings()
    elif result["suite"] == "endurance":
        from audit_android_power_lifecycle import power_lifecycle
        from audit_android_network_handover import network_handover
        power_lifecycle(arun,evidence,probe,result,endurance=True,tcp_fault=False,dns_probe=dns_probe)
        network_handover(arun,evidence,probe,result,bursts=bursts,cycles=3,dns_probe=dns_probe)
        open_settings()
    elif result["suite"] == "private-dns":
        from audit_android_private_dns import private_dns_matrix
        assert dot is not None
        private_dns_matrix(arun,evidence,result,startup,dot,probe)
        open_settings()
    elif result["suite"] == "power":
        from audit_android_power_lifecycle import power_lifecycle
        power_lifecycle(arun, evidence, probe, result)
        open_settings()
    else:
        old_pid = arun("shell", "pidof", "com.qeli").stdout.strip(); assert re.fullmatch(r"[0-9]+", old_pid)
        before_applied = logs().count("Native NetworkPlan 1 APPLIED:")
        (evidence / "before-sigkill-services.txt").write_text(arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout)
        (evidence / "before-sigkill-vpn.txt").write_text(arun("shell", "dumpsys", "vpn_management").stdout)
        arun("shell", "su", "0", "kill", "-9", old_pid)
        recovery_started = time.monotonic()
        recovery_error = None
        try:
            wait_until(lambda: logs().count("Native NetworkPlan 1 APPLIED:") > before_applied, "OS did not restore authenticated VPN after SIGKILL", 45)
        except AssertionError as error:
            recovery_error = str(error)
        finally:
            for name, command in (("after-sigkill-services.txt", ["dumpsys", "activity", "services", "com.qeli"]),
                                  ("after-sigkill-exit-info.txt", ["dumpsys", "activity", "exit-info", "com.qeli"]),
                                  ("after-sigkill-vpn.txt", ["dumpsys", "vpn_management"]),
                                  ("after-sigkill-system-logcat.log", ["logcat", "-d"])):
                (evidence / name).write_text(arun("shell", *command, check=False).stdout)
        new_pid = arun("shell", "pidof", "com.qeli", check=False).stdout.strip()
        if recovery_error is None:
            assert new_pid and new_pid != old_pid
            recovery_log = logs()
            new_process_lines = "\n".join(line for line in recovery_log.splitlines()
                if re.search(r"\s" + re.escape(new_pid) + r"\s+\d+\s+[VDIWEF]\s", line))
            redelivery = "Android redelivered" in new_process_lines
            sticky_recovery = (
                "Android restarted the recovery record; requesting desired VPN recovery" in new_process_lines
                and "Android recovery record requested the desired VPN after process death" in new_process_lines
            )
            assert redelivery or sticky_recovery, "missing recovery trigger in the new process"
            assert new_process_lines.count("Native NetworkPlan 1 APPLIED:") == 1, "duplicate VPN generation after recovery"
            result["sigkill_recovery"] = dict(status="PASS", old_pid=old_pid, new_pid=new_pid,
                redelivery=redelivery, sticky_recovery=sticky_recovery,
                seconds=time.monotonic()-recovery_started, one_network_plan=True)
            state = arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout
            assert "isForeground=true" in state, state
            (evidence / "sigkill-services.txt").write_text(state)
            result["app_probe_lockdown_recovered"] = probe("Q29RECOVERED", True)
        else:
            result["sigkill_recovery"] = dict(status="FAIL", old_pid=old_pid, new_pid=new_pid, error=recovery_error)
            # Complete independent safety/revoke checks even when OS recovery fails.
            result["app_probe_lockdown_process_dead"] = probe("Q29DEAD", False)
        (evidence / "sigkill-logcat.log").write_text(logs())
        arun("shell", "am", "force-stop", "com.qeli")
        wait_until(lambda: not re.search(r"^\d+: tun\d", arun("shell", "su", "0", "ip", "-o", "link", "show").stdout, re.M), "force-stop retained TUN")
        result["app_probe_lockdown_without_VPN"] = probe("Q29BLOCKED", False)
        time.sleep(30)
        assert not arun("shell", "pidof", "com.qeli", check=False).stdout.strip(), "force-stopped VPN resurrected"
        assert "VpnRecoveryService" not in arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout
        result["force_stop_no_resurrection_seconds"] = 30
        # Force-stop is a user stop; clear the package's stopped state by an explicit launch.
        arun("shell", "am", "start", "-n", "com.qeli/.MainActivity")
        recovery_applied = logs().count("Native NetworkPlan 1 APPLIED:")
        open_settings(); switch("Block connections without VPN", False); switch("Always-on VPN", False)
        switch("Always-on VPN", True); switch("Block connections without VPN", True)
        wait_until(lambda: logs().count("Native NetworkPlan 1 APPLIED:") > recovery_applied,
                   "manual re-enable did not restore authenticated VPN")
        state = arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout
        assert "isForeground=true" in state, state
        (evidence / "manual-recovery-services.txt").write_text(state)
        result["manual_recovery_after_force_stop"] = "PASS"
        result["app_probe_manual_recovery"] = probe("Q29MANUAL", True)
    if bursts is not None:bursts.force_stop(open_settings, switch, logs, probe, dns_probe=dns_probe)
    before_revoke = logs().count("Android revoked the VPN service")
    switch("Block connections without VPN", False); switch("Always-on VPN", False)
    settings.forget()
    wait_until(lambda: logs().count("Android revoked the VPN service") > before_revoke, "system Settings did not invoke onRevoke")
    wait_until(lambda: "VpnServiceImpl" not in arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout,
               "revoked service remained")
    links = arun("shell", "su", "0", "ip", "-o", "link", "show").stdout
    assert not re.search(r"^\d+: tun\d", links, re.M), links
    prefs = (arun("shell", "su", "0", "cat", "/data/data/com.qeli/shared_prefs/app_state.xml")
             if result["android_build_type"] == "release" else
             arun("shell", "run-as", "com.qeli", "cat", "shared_prefs/app_state.xml")).stdout
    (evidence / "revoked-prefs.xml").write_text(prefs)
    tree = ET.fromstring(prefs)
    assert any(n.get("name") == "connection_desired" and n.get("value") == "false" for n in tree), prefs
    wait_until(lambda: any(mode in arun("shell", "appops", "get", "com.qeli", "ACTIVATE_VPN").stdout
                          for mode in ("ignore", "deny")), "Forget did not revoke VPN consent", 15)
    consent = arun("shell", "appops", "get", "com.qeli", "ACTIVATE_VPN").stdout
    (evidence / "revoked-consent.txt").write_text(consent)
    assert "ignore" in consent or "deny" in consent, consent
    result["system_revoke"] = "PASS"
    time.sleep(30)
    stopped = arun("shell", "dumpsys", "activity", "services", "com.qeli").stdout
    assert "VpnServiceImpl" not in stopped and "VpnRecoveryService" not in stopped, "revoked VPN resurrected"
    assert not re.search(r"^\d+: tun\d", arun("shell", "su", "0", "ip", "-o", "link", "show").stdout, re.M)
    result["revoke_no_resurrection_seconds"] = 30
    (evidence / "system-lifecycle-logcat.log").write_text(logs())
    result["system_echo_receipts"] = len(echo.rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--qeli", type=Path, required=True)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--inside", action="store_true")
    ap.add_argument("--restart-control", action="store_true", help="run the standalone platform-only restart control before system suite")
    ap.add_argument("--suite", choices=("explicit", "ordinary", "routed", "system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns", "trusted-wifi", "profile-ui", "settings-ui"), default="explicit")
    ap.add_argument("--transport", choices=("tcp", "udp", "quic"), default="udp", help="transport for recovery/handover suite; recovery requires udp/quic; trusted-wifi requires tcp")
    ap.add_argument("--carrier", choices=("default", "nat64"), default="default", help="private IPv6-only TAP/SLAAC/DNS64/NAT64 backend; Release nat64 suite only")
    ap.add_argument("--startup-state", action="store_true", help="24-sample cold-start burst with ordinary-UID network snapshots; startup only")
    ap.add_argument("--apps-mode", choices=("all", "include", "exclude"), default="all", help="Release startup/handover per-app fixture; include captures only test UID and excludes VPN owner")
    ap.add_argument("--require-published-start", action="store_true", help="require first fresh sockets after product CONNECTED log to succeed; Release startup only")
    ap.add_argument("--resolver-diagnostics", action="store_true", help="observe Android async DNS variants; startup suite only")
    ap.add_argument("--leak-bursts", action="store_true", help="ordinary-UID probe bursts crossing handover/force-stop; Release only")
    ap.add_argument("--variant", choices=("debug", "release"), default="debug", help="require matching APK build type in fixture manifest")
    ap.add_argument("--trusted-lockdown-handover", action="store_true", help="enable actual trusted SSID UI under OS lockdown before Release handover")
    ap.add_argument("--ui-connect-restart", action="store_true", help="verify real Release Activity disconnect/connect after OS lockdown bootstrap; private-dns only")
    args = ap.parse_args()
    if args.suite == "trusted-wifi" and args.variant != "debug":ap.error("trusted Wi-Fi fixture requires debug instrumentation")
    if args.suite in ("profile-ui", "settings-ui") and (args.variant != "debug" or args.transport != "tcp"):ap.error("profile UI fixture requires debug TCP")
    if args.trusted_lockdown_handover and (args.variant != "release" or args.suite != "handover" or args.apps_mode != "all"):ap.error("trusted lockdown handover requires Release handover apps_mode=all")
    if args.ui_connect_restart and (args.variant != "release" or args.suite != "private-dns"):ap.error("UI connect restart requires Release private-dns suite")
    if args.apps_mode != "all" and (args.variant != "release" or args.suite not in ("startup", "handover", "app-policy")):ap.error("per-app fixture requires Release startup/handover/app-policy")
    if args.require_published_start and (args.variant != "release" or args.suite != "startup" or not args.startup_state):ap.error("published start requires Release startup state")
    if args.startup_state and args.suite != "startup":ap.error("startup state requires startup suite")
    if args.resolver_diagnostics and args.suite != "startup":ap.error("resolver diagnostics require startup suite")
    if args.suite == "recovery" and args.transport == "tcp":ap.error("recovery requires udp/quic")
    if args.carrier == "nat64" and (args.variant != "release" or args.suite != "nat64"):ap.error("nat64 requires Release nat64 suite")
    if args.suite == "nat64" and args.carrier != "nat64":ap.error("nat64 suite requires nat64 carrier")
    if args.leak_bursts and (args.variant != "release" or args.suite not in ("handover", "nat64", "startup", "endurance", "private-dns")):ap.error("leak bursts require Release handover/nat64/startup/endurance/private-dns suite")
    if args.suite == "startup" and (args.variant != "release" or not args.leak_bursts):ap.error("startup requires Release and leak bursts")
    if args.suite == "endurance" and (args.variant != "release" or not args.leak_bursts):ap.error("endurance requires Release and leak bursts")
    if args.suite == "private-dns" and (args.variant != "release" or not args.leak_bursts):ap.error("private-dns requires Release and leak bursts")
    if args.suite == "app-policy" and (args.variant != "release" or args.apps_mode not in ("include", "exclude")):ap.error("app-policy requires Release include/exclude")
    if args.suite == "trusted-wifi" and args.transport != "tcp":ap.error("trusted Wi-Fi fixture requires TCP")
    assert not args.restart_control or args.suite == "system"
    assert os.geteuid() == 0
    root = args.root.resolve(strict=True)
    assert re.fullmatch(r"/var/tmp/qeli-q29-data-[a-z0-9-]+", str(root)), root
    assert sha(args.qeli) == args.sha256
    if not args.inside:
        env = dict(os.environ)
        for kind in ("net", "mnt", "pid"):
            env["Q29_PARENT_" + kind.upper()] = os.readlink("/proc/self/ns/" + kind)
        return subprocess.run(["unshare", "--net", "--mount", "--pid", "--fork", "--kill-child=KILL",
                               "--mount-proc", sys.executable, __file__, "--inside", "--root", str(root),
                               "--qeli", str(args.qeli), "--sha256", args.sha256, "--suite", args.suite, "--transport", args.transport, "--variant", args.variant, "--carrier", args.carrier, "--apps-mode", args.apps_mode,
                               *(["--require-published-start"] if args.require_published_start else []),
                               *(["--startup-state"] if args.startup_state else []), *(["--resolver-diagnostics"] if args.resolver_diagnostics else []), *(["--restart-control"] if args.restart_control else []), *(["--leak-bursts"] if args.leak_bursts else []), *(["--ui-connect-restart"] if args.ui_connect_restart else []), *(["--trusted-lockdown-handover"] if args.trusted_lockdown_handover else [])], env=env, timeout=1200 if args.suite == "endurance" else 650).returncode
    assert all(os.readlink("/proc/self/ns/" + kind) != os.environ["Q29_PARENT_" + kind.upper()]
               for kind in ("net", "mnt", "pid"))
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    result = dict(trusted_lockdown_handover_enabled=args.trusted_lockdown_handover, ui_connect_restart_enabled=args.ui_connect_restart, require_published_start=args.require_published_start, apps_mode=args.apps_mode, startup_state_enabled=args.startup_state, resolver_diagnostics_enabled=args.resolver_diagnostics, leak_bursts_enabled=args.leak_bursts, status="RUNNING", android_build_type=args.variant, carrier_fixture=args.carrier, namespace_isolation=True, qeli_sha256=args.sha256, suite=args.suite, recovery_transport=args.transport if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") else None)
    def dump(name, value):
        (evidence / name).write_text(json.dumps(value, indent=2) + "\n")
    def cmd(*argv, timeout=30):
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        assert proc.returncode == 0, (argv, proc.stdout, proc.stderr)
        return proc.stdout
    cmd("mount", "--make-rprivate", "/")
    cmd("ip", "link", "set", "lo", "up")
    for path in ("/run", "/var/lib", "/var/log"):
        cmd("mount", "-t", "tmpfs", "tmpfs", path)
    Path("/var/lib/qeli").mkdir()
    Path("/var/log/qeli").mkdir()
    private = root / "etc"
    private.mkdir(mode=0o700)
    cmd("mount", "--bind", str(private), "/etc/qeli")
    namespace_before = cmd("ip", "-br", "addr")
    (evidence / "namespace-network-before.txt").write_text(namespace_before)
    before = userdata()
    dump("avd-userdata-before.json", before)
    dump("namespace-identities.json", {kind: os.readlink("/proc/self/ns/" + kind) for kind in ("net", "mnt", "pid")})
    config = "[auth]\nusers_file = " + str(root / "users.ini") + "\nrequire_client_key_proof = true\nbind_static_to_session = true\n[web]\nenabled = false\n[logging]\nlevel = debug\n"
    for profile, port, subnet, v6 in (("tcp", 24966, "10.86.0", "fd86:29:1"), ("udp", 24967, "10.87.0", "fd86:29:2")):
        config += f"""[profile:{profile}]
identity_key = {root}/{profile}.key
bind.address = {"192.0.2.10" if args.carrier == "nat64" else "127.0.0.1"}
bind.port = {port}
bind.transport = {profile}
tun.name = q29{profile}
tun.address = {subnet}.1
tun.queues = 1
tun.ip_mode = dual
tun.ipv6_address = {v6}::1
pool.cidr = {subnet}.0/24
pool.ipv6.cidr = {v6}::/120
routing.nat.enabled = false
routing.ipv6.mode = manual
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 5000
obf.heartbeat.jitter_ms = 100
obf.traffic_shaping.enabled = false
perf.connection.idle_timeout_secs = 0
perf.connection.max_clients = 8
perf.connection.handshake_timeout_secs = 12
"""
        if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") and profile == "udp":
            config += f"roaming.enabled = true\nroaming.grace_secs = 15\nobf.quic.enabled = {str(args.transport == 'quic').lower()}\n"
    (root / "server.ini").write_text(config)
    (root / "server.ini").chmod(0o600)
    (root / "users.ini").write_text("[user:fixture]\npassword_hash = " + hashed() + "\nenabled = true\n")
    (root / "users.ini").chmod(0o600)
    temporary = root / "tmp"
    temporary.mkdir(mode=0o700)
    os.environ["TMPDIR"] = str(temporary)
    state = root / "state"
    state.mkdir(mode=0o700)
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_CONTROL_SOCKET=str(root / "control.sock"))
    adb = "/root/android-sdk/platform-tools/adb"
    serial = "emulator-5560"
    def arun(*argv, timeout=30, check=True):
        proc = subprocess.run([adb, "-s", serial, *argv], capture_output=True, text=True, timeout=timeout)
        if check:
            assert proc.returncode == 0, (argv, proc.stdout, proc.stderr)
        return proc
    server = emulator = echo = capture = dns = nat64 = leak_capture = dot = None
    fixture_addresses = [("198.19.0.1/32", False), ("198.19.0.53/32", False), ("2001:db8:29::1/128", True)] if args.suite in ("routed", "system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns", "trusted-wifi") else []
    started = time.monotonic()
    fixture_installed = []
    try:
        if args.carrier == "nat64":
            from audit_android_nat64 import Nat64Fixture
            nat64 = Nat64Fixture(root, evidence, cmd)
            nat64.start()
        for address, ipv6 in fixture_addresses:
            cmd("ip", *(["-6"] if ipv6 else []), "addr", "add", address, "dev", "lo")
            fixture_installed.append((address, ipv6))
        if args.suite in ("routed", "startup", "app-policy", "endurance", "private-dns"):
            dns = DnsFixture(evidence / "dns-receipts.json")
        cmd(str(args.qeli), "check-config", "-c", str(root / "server.ini"))
        public = cmd(str(args.qeli), "show-identity", "-c", str(root / "server.ini"))
        (evidence / "server-public-keys.txt").write_text(public)
        keys = dict(re.findall(r"(?m)^(tcp|udp)\s+\S+\s+([0-9a-f]{64})$", public))
        assert len(keys) == 2, public
        server_log = (evidence / "server.log").open("wb")
        server = subprocess.Popen([str(args.qeli), "server", "-c", str(root / "server.ini")], env=env,
                                  stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
        until = time.monotonic() + 20
        while time.monotonic() < until:
            assert server.poll() is None, "server exited"
            if "q29tcp" in cmd("ip", "-br", "link") and "q29udp" in cmd("ip", "-br", "link"):
                break
            time.sleep(.1)
        else:
            raise AssertionError("server TUN setup timeout")
        capture = subprocess.Popen(["tcpdump", "-i", "q29udp" if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") and args.transport != "tcp" else "q29tcp", "-U", "-s", "0", "-w", str(evidence / "tcp-tun.pcap")],
                                   stdout=(evidence / "tcpdump.log").open("wb"), stderr=subprocess.STDOUT, start_new_session=True)
        echo_hosts = [(socket.AF_INET, "198.19.0.1"), (socket.AF_INET6, "2001:db8:29::1")] if args.suite in ("routed", "system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") else None
        if args.suite == "private-dns":
            from audit_android_private_dns import DnsTlsFixture
            dot = DnsTlsFixture(root,evidence)
        if args.suite == "trusted-wifi":echo_hosts=[(socket.AF_INET,"198.19.0.1"),(socket.AF_INET6,"2001:db8:29::1")]
        echo = Echo(evidence / "echo-receipts.json", echo_hosts)
        if args.leak_bursts or args.suite == "app-policy":
            leak_capture = subprocess.Popen(["tcpdump", "-i", "any", "-U", "-s", "0", "-w", str(evidence / "leak-any.pcap"), "port", "26000", "or", "port", "53", "or", "port", "853"], stdout=(evidence / "leak-capture.log").open("wb"), stderr=subprocess.STDOUT, start_new_session=True)
        command = ["/root/android-sdk/emulator/emulator", "-avd", "test", "-port", "5560", "-read-only",
                   "-no-snapshot-load", "-no-snapshot-save", "-no-window", "-no-audio", "-no-boot-anim",
                   "-gpu", "swiftshader", "-memory", str(EMULATOR_MEMORY_MB), "-lowram", "-cores", "1"]
        if args.suite in ("app-policy","private-dns"):command.extend(["-dns-server", "198.19.0.53"])
        if nat64 is not None:
            command.extend(nat64.emulator_options())
        dump("emulator-command.json", command)
        cmd(adb, "start-server")
        emulator = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=(evidence / "emulator.log").open("wb"),
                                    stderr=subprocess.STDOUT, start_new_session=True)
        print("PRIVATE_SERVER_AND_READONLY_AVD_STARTED", flush=True)
        until = time.monotonic() + 240
        while time.monotonic() < until:
            assert emulator.poll() is None, "emulator exited"
            proc = arun("shell", "getprop", "sys.boot_completed", timeout=15, check=False)
            if proc.returncode == 0 and proc.stdout.strip() == "1":
                break
            time.sleep(2)
        else:
            raise AssertionError("AVD boot timeout")
        guest_meminfo = arun("shell", "cat", "/proc/meminfo").stdout
        (evidence / "android-meminfo-before.txt").write_text(guest_meminfo)
        result["emulator_memory"] = admitted_guest_memory(guest_meminfo)
        if args.variant == 'release' and args.suite in ('system', 'power', 'recovery', 'handover', 'nat64', 'startup', 'app-policy', 'endurance', 'private-dns'):
            from audit_android_release_ui import await_download_storage
            await_download_storage(arun, evidence, result, label='before-install')
        assert not arun("shell", "pm", "list", "packages", "com.qeli").stdout.strip(), "fixture already has Qeli"
        stale = arun("shell", "pm", "list", "packages", "-u", "com.qeli").stdout
        for package in ("com.qeli.test", "com.qeli"):
            if re.search(r"^package:" + re.escape(package) + r"$", stale, re.M):
                arun("uninstall", package, timeout=60)
        result["environment"] = {name: arun("shell", "getprop", name).stdout.strip()
                                 for name in ("ro.build.version.sdk", "ro.build.version.release", "ro.product.cpu.abi",
                                       "ro.build.fingerprint", "ro.build.id", "ro.build.version.incremental")}
        if args.restart_control:
            from audit_android_restart_control import restart_control
            control_manifest = json.loads((root / "control/manifest.json").read_text())
            control_apk = root / "control/restart-control.apk"
            assert sha(control_apk) == control_manifest["apks"]["restart-control.apk"]
            (evidence / "control-install.log").write_text(arun("install", "-t", str(control_apk), timeout=90).stdout)
            result["restart_control_apk"] = control_manifest
            restart_control(arun, evidence, result)
            print("PLATFORM_CONTROL_COMPLETE", flush=True)
        if nat64 is not None:
            result["nat64_initial_carrier"] = nat64.verify_carrier(arun, "nat64-initial")
        methods = ["tcpDualStackPayloadAndCompletedRestart", "udpDualStackPayload", "quicDualStackPayload"]
        phases = [("baseline", "com.qeli.VpnDataPlaneInstrumentedTest#" + methods[0]),
                  ("fixed", ",".join("com.qeli.VpnDataPlaneInstrumentedTest#" + method for method in methods))]
        expected_tests = 3
        if args.suite == "ordinary":
            methods = [transport + "Ordinary" + mode + "Payload" for transport in ("tcp", "udp", "quic")
                       for mode in ("Split", "Full")]
            phases = [("fixed", ",".join("com.qeli.VpnDataPlaneInstrumentedTest#" + method for method in methods))]
            expected_tests = 6
        if args.suite == "routed":
            methods = [transport + "Routed" + mode + "PayloadDns" for transport in ("tcp", "udp", "quic")
                       for mode in ("Split", "Full")] + ["fullKillSwitchRefusesWithoutSystemLockdown"]
            phases = [("fixed", ",".join("com.qeli.VpnDataPlaneInstrumentedTest#" + method for method in methods))]
            expected_tests = 7
            for label, argv in [("connectivity-command-help", ["shell", "cmd", "connectivity", "help"]),
                                ("system-vpn-policy", ["shell", "settings", "list", "secure"])]:
                value = arun(*argv, check=False).stdout
                if label == "system-vpn-policy":
                    value = "\n".join(line for line in value.splitlines() if "vpn" in line or "private_dns" in line)
                (evidence / (label + ".txt")).write_text(value)
        if args.suite in ("system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns"):
            phases = [("fixed", "com.qeli.VpnSystemLifecycleInstrumentedTest#bootstrapSavedProfileAndLeaveConnected")]
            expected_tests = 1
        if args.suite == "trusted-wifi":
            protection_methods = ["stoppedServiceRejectsLateProtectBeforeCarrierMutation",
                                  "replacedCoreCannotProtectOnBehalfOfCurrentConnection",
                                  "protectionWaitsAtOwnerCheckWhileLifecycleOwnsMonitor",
                                  "stoppedObserverCannotPublishCarrier",
                                  "unregisteredObserverCannotPublishCarrier",
                                  "replacedObserverCannotPublishCarrier",
                                  "retiredObserverCapabilitiesAndLinksCannotPublishCarrier",
                                  "retiredObserverLostCannotEraseCarrier"]
            selector = "com.qeli.TrustedWifiInstrumentedTest," + ",".join(
                "com.qeli.TransportLifecycleInstrumentedTest#" + name for name in protection_methods)
            phases=[("fixed",selector)]
            expected_tests=13
        if args.suite == "profile-ui":
            phases=[("fixed","com.qeli.ProfileUiInstrumentedTest,com.qeli.DiagnosticLogStoreInstrumentedTest")];expected_tests=10
        if args.suite == "settings-ui":
            phases=[("fixed","com.qeli.SettingsReconnectInstrumentedTest")];expected_tests=3
        for folder, selector in phases:
            manifest = json.loads((root / folder / "manifest.json").read_text())
            assert manifest.get("build_type", "debug") == args.variant, "APK manifest does not match requested variant"
            result[folder + "_apks"] = manifest
            for name, digest in manifest["apks"].items():
                apk = root / folder / name
                assert sha(apk) == digest
                (evidence / (folder + "-" + name + "-install.log")).write_text(arun("install", "-r", "-t", str(apk), timeout=90).stdout)
            package = arun("shell", "dumpsys", "package", "com.qeli").stdout
            (evidence / (folder + "-package.txt")).write_text(package)
            if args.variant == "release":
                nondebug = arun("shell", "run-as", "com.qeli", "true", check=False)
                (evidence / (folder + "-run-as.txt")).write_text(nondebug.stdout + nondebug.stderr)
                assert nondebug.returncode != 0 and "not debuggable" in nondebug.stdout + nondebug.stderr, nondebug
                assert not re.search(r"(?:pkgFlags|flags)=\[[^\]]*\bDEBUGGABLE\b", package), package
            arun("shell", "appops", "set", "com.qeli", "ACTIVATE_VPN", "allow")
            arun("shell", "pm", "grant", "com.qeli", "android.permission.POST_NOTIFICATIONS")
            if args.suite == "trusted-wifi":
                for permission in ("ACCESS_COARSE_LOCATION","ACCESS_FINE_LOCATION","NEARBY_WIFI_DEVICES"):
                    arun("shell","pm","grant","com.qeli","android.permission."+permission)
                arun("shell","cmd","location","set-location-enabled","true")
            if args.variant == "release" and args.suite in ("system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns"):
                from audit_android_release_ui import import_release_profile
                # Power/system fixtures are TCP; --transport selects only recovery/handover/nat64.
                ui_transport = args.transport if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") else "tcp"
                import_release_profile(arun, evidence, result, keys, ui_transport, server="q29-v4-only.test" if nat64 is not None else None, tunnel_dns=args.suite in ("startup", "app-policy", "endurance", "private-dns"), apps_mode=args.apps_mode, policy_fixture=args.suite == "app-policy")
                result[folder + "_output"]="UI_IMPORT_PASS; INSTRUMENTATION_NOT_RUN"
                result[folder + "_echo_receipts"]=len(echo.rows)
            else:
                proc = arun("shell", "am", "instrument", "-w", "-r", "-e", "class", selector,
                            "-e", "q29_private_fixture", "1", "-e", "q29_key_tcp", keys["tcp"],
                            "-e", "q29_key_udp", keys["udp"],
                            *(["-e", "q29_transport", args.transport, "-e", "q29_roaming", "off" if args.transport == "tcp" else "required"] if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") else []),
                            "com.qeli.test/androidx.test.runner.AndroidJUnitRunner", timeout=240)
                (evidence / (folder + "-instrumentation.log")).write_text(proc.stdout + proc.stderr)
                result[folder + "_output"] = proc.stdout
                result[folder + "_echo_receipts"] = len(echo.rows)
                (evidence / (folder + "-vpn-logcat.log")).write_text(arun("shell", "logcat", "-d", "-s", "VpnSvc:D", "Q29Traffic:I", "Q29System:I", "Q29Trusted:I", "AndroidRuntime:E").stdout)
                if folder == "fixed":
                    assert f"OK ({expected_tests} {'test' if expected_tests == 1 else 'tests'})" in proc.stdout, proc.stdout
            print(folder.upper() + "_COMPLETE", flush=True)
        if args.suite == "app-policy":
            probe_manifest=json.loads((root / "probe/manifest.json").read_text())
            probe_apk=root / "probe/audit-probe.apk"
            assert sha(probe_apk)==probe_manifest["apks"][probe_apk.name]
            (evidence / "probe-install.log").write_text(arun("install", "-t", str(probe_apk), timeout=90).stdout)
            result["second_probe_apk"]=probe_manifest
            from audit_android_app_policy import app_policy_lifecycle
            app_policy_lifecycle(arun,evidence,echo,dns,result)
        elif args.suite in ("system", "power", "recovery", "handover", "nat64", "startup", "endurance", "private-dns"):
            system_lifecycle(arun, evidence, echo, result, dot=dot)
        if nat64 is not None:
            result["nat64_final_carrier"] = nat64.verify_carrier(arun, "nat64-final")
        assert not any("error" in row for row in echo.rows), echo.rows
        if dns is not None:
            assert not any("error" in row for row in dns.rows), dns.rows
            accepted = [row for row in dns.rows if row["answered"]]
            if args.suite == "routed":
                assert len({row["name"] for row in accepted}) == 6, accepted
                assert all(row["peer"].startswith(("10.86.0.", "10.87.0.")) for row in accepted), accepted
            elif args.suite == "private-dns":
                names={p["name"] for p in result["dns_probes"]}
                accepted=[row for row in accepted if row["name"] in names]
                encrypted=[row for row in dot.rows if row["kind"]=="DNS" and row["answered"] and row["name"] in names]
                baseline={p["name"] for p in result["dns_probes"] if p["stage"]=="physical-baseline"}
                assert all(row["peer"].startswith(("10.86.0.", "10.87.0.")) for row in accepted+encrypted if row["name"] not in baseline)
                result["dns_plaintext_answers"]=len(accepted);result["dns_tls_answers"]=len(encrypted)
                accepted+=encrypted
            elif args.suite == "endurance":
                assert result["dns_probes"] and all(row["peer"].startswith(("10.86.0.", "10.87.0.")) for row in accepted)
            elif args.suite != "app-policy":
                baseline={p["name"] for p in result["dns_probes"] if p["stage"]=="physical-baseline"}
                assert len(baseline)==1
                assert all(row["peer"].startswith(("10.86.0.", "10.87.0.")) for row in accepted if row["name"] not in baseline), accepted
            result["dns_answered_questions"] = len(accepted)
        profiles = [("tcp", "10.86.0.", "fd86:29:1:")] if args.suite in ("system", "power", "recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns", "trusted-wifi") else [("tcp", "10.86.0.", "fd86:29:1:"), ("udp", "10.87.0.", "fd86:29:2:")]
        if args.suite in ("recovery", "handover", "nat64", "startup", "app-policy", "endurance", "private-dns") and args.transport != "tcp": profiles = [("udp", "10.87.0.", "fd86:29:2:")]
        if args.suite in ("profile-ui", "settings-ui"):
            assert not echo.rows, "profile UI fixture must not emit VPN payload"
            profiles = []
        for profile, subnet, v6 in profiles:
            for family_prefix in (subnet, v6):
                for protocol in ("tcp", "udp"):
                    assert any(row.get("peer", "").startswith(family_prefix) and row.get("protocol") == protocol
                               for row in echo.rows), (profile, family_prefix, protocol, echo.rows)
        arun("shell", "am", "force-stop", "com.qeli")
        links = arun("shell", "su", "0", "ip", "-o", "link", "show").stdout
        (evidence / "android-links-after.txt").write_text(links)
        assert not re.search(r"^\d+: tun\d", links, re.M), links
        for name, command in (("android-services-after.txt", ["shell", "dumpsys", "activity", "services", "com.qeli"]),
                              ("android-runtime.log", ["shell", "logcat", "-d", "-s", "AndroidRuntime:E"])):
            (evidence / name).write_text(arun(*command).stdout)
        assert "FATAL EXCEPTION" not in (evidence / "android-runtime.log").read_text()
        result["status"] = "FAIL" if result.get("sigkill_recovery", {}).get("status") == "FAIL" else "PASS"
    except BaseException:
        result["status"] = "FAIL"
        result["error"] = traceback.format_exc()
        print(result["error"], flush=True)
        try:
            (evidence / "failure-vpn-logcat.log").write_text(arun("shell", "logcat", "-d", "-s", "VpnSvc:D", "Q29Probe:I", "ActivityManager:I", "AndroidRuntime:E", timeout=20, check=False).stdout)
        except Exception:
            pass
    finally:
        if dot is not None:
            try:dot.close()
            except BaseException:
                result["status"]="FAIL";result["dot_cleanup_error"]=traceback.format_exc()
        if dns is not None:
            try:
                dns.close()
            except BaseException:
                result["status"] = "FAIL"
                result["cleanup_error"] = traceback.format_exc()
        if echo is not None:
            try:
                echo.close()
            except BaseException:
                result["status"] = "FAIL"
                result["cleanup_error"] = traceback.format_exc()
        stop(leak_capture)
        stop(capture)
        stop(emulator)
        if server is not None and server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                stop(server)
        result["server_exit_code"] = None if server is None else server.returncode
        for address, ipv6 in reversed(fixture_installed):
            cmd("ip", *(["-6"] if ipv6 else []), "addr", "del", address, "dev", "lo")
        if nat64 is not None:
            try:
                nat64.close()
            except BaseException:
                result["status"] = "FAIL"
                result["nat64_cleanup_error"] = traceback.format_exc()
        namespace_after = cmd("ip", "-br", "addr")
        (evidence / "namespace-network-after.txt").write_text(namespace_after)
        result["namespace_addresses_restored"] = namespace_after == namespace_before
        if server is not None and (server.returncode != 0 or namespace_after != namespace_before):
            result["status"] = "FAIL"
            result["cleanup_error"] = "server exit/network cleanup failed"
        subprocess.run([adb, "kill-server"], timeout=15, capture_output=True)
        after = userdata()
        dump("avd-userdata-after.json", after)
        result["avd_userdata_unchanged"] = before == after
        if before != after:
            result["status"] = "FAIL"
            result["error"] = "persistent AVD userdata changed"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        dump("result.json", result)
        print("FINISHED " + result["status"] + "; USERDATA_UNCHANGED=" + str(before == after), flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
