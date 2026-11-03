#!/usr/bin/env python3
"""Private packet NAT64 + SLAAC/RDNSS fixture for the readonly Android AVD.

Debian binaries are unpacked in the caller-owned lab directory, never installed.
This helper must only run inside the data-plane harness's verified private namespaces.
"""
import hashlib
import ipaddress
import json
import socket
import struct
import subprocess
import threading
from pathlib import Path
from audit_udp_handshake_contracts import stop
from audit_android_network_handover import default_carrier
from android_lab_ui import wait_until

# TAYGA 0.9.2 treats the entire first 32 bits 64:ff9b as the WKP and
# rejects private/documentation IPv4 destinations even under 64:ff9b:1::/96.
# Use a separate network-specific /96 outside the carrier's on-link /64.
PREFIX = "2001:db8:29:ffff::/96"
ROUTER = "2001:db8:29:64::1"
BACKEND = "192.0.2.10"
TOOLS = Path("/var/tmp/qeli-q29-nat64-tools-20261005/unpack/usr/sbin")
TOOL_SHA = {"tayga": "79645bd765188553cc0795b931b22f86dd3ef6ffd258478a2fc1c5a4dd382cd0",
            "radvd": "0988217cca87df004bf0435765237746a9cf53aa29dfdf2bbb0ef1af3a67017a"}


class Dns64:
    """A-only fixture zone, RFC7050 answers, and DNS64 AAAA synthesis over IPv6."""
    def __init__(self, evidence):
        self.evidence = evidence
        self.rows = []
        self.done = threading.Event()
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind((ROUTER, 53))
        self.sock.settimeout(.5)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.done.is_set():
                try:
                    data, peer = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) < 17 or struct.unpack_from("!H", data, 4)[0] != 1:
                    continue
                offset = 12
                labels = []
                while offset < len(data) and data[offset]:
                    length = data[offset]
                    if length > 63 or offset + 1 + length >= len(data):
                        break
                    labels.append(data[offset+1:offset+1+length].decode("ascii"))
                    offset += 1 + length
                if offset + 5 > len(data) or data[offset]:
                    continue
                offset += 1
                kind, klass = struct.unpack_from("!HH", data, offset)
                name = ".".join(labels).lower()
                # The upstream fixture has A records only, never native AAAA.
                records = [BACKEND] if name == "q29-v4-only.test" else (["192.0.0.170", "192.0.0.171"] if name == "ipv4only.arpa" else [])
                values = []
                if klass == 1 and kind in (1, 28):
                    for address in records:
                        v4 = ipaddress.IPv4Address(address)
                        values.append(v4.packed if kind == 1 else (int(ipaddress.IPv6Network(PREFIX).network_address) | int(v4)).to_bytes(16, "big"))
                answer = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(v)) + v for v in values)
                question = data[12:offset+4]
                flags = 0x8180 if records else 0x8183
                response = data[:2] + struct.pack("!HHHHH", flags, 1, len(values), 0, 0) + question + answer
                self.sock.sendto(response, peer)
                self.rows.append(dict(name=name, qtype=kind, peer=peer[0], upstream_A=records, upstream_AAAA=[], synthesized=kind == 28 and bool(values), answers=[str(ipaddress.ip_address(v)) for v in values]))
                (self.evidence / "nat64-dns-receipts.json").write_text(json.dumps(self.rows, indent=2)+"\n")
        except BaseException as error:
            if not self.done.is_set():
                self.rows.append(dict(error=repr(error)))
                (self.evidence / "nat64-dns-receipts.json").write_text(json.dumps(self.rows, indent=2)+"\n")

    def close(self):
        self.done.set()
        self.sock.close()
        self.thread.join(2)
        assert not self.thread.is_alive(), "DNS64 worker remained"
        assert not any("error" in r for r in self.rows), self.rows


class Nat64Fixture:
    def __init__(self, root, evidence, cmd):
        self.root, self.evidence, self.cmd = root, evidence, cmd
        self.processes, self.links = [], []
        self.dns = None
        self.old_sysctl = {}
        self.backend_installed = False

    def start(self):
        for name, digest in TOOL_SHA.items():
            assert hashlib.sha256((TOOLS/name).read_bytes()).hexdigest() == digest, name
        for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
            self.old_sysctl[key] = self.cmd("sysctl", "-n", key).strip()
            self.cmd("sysctl", "-w", key+"=1")
        self.cmd("ip", "link", "add", "q29uplink", "type", "bridge")
        self.links.append("q29uplink")
        for tap in ("q29eth", "q29wifi"):
            self.cmd("ip", "tuntap", "add", "dev", tap, "mode", "tap")
            self.links.append(tap)
            self.cmd("ip", "link", "set", tap, "master", "q29uplink")
            self.cmd("ip", "link", "set", tap, "up")
        self.cmd("ip", "link", "set", "q29uplink", "up")
        self.cmd("ip", "-6", "addr", "add", ROUTER+"/64", "dev", "q29uplink", "nodad")
        self.cmd("ip", "addr", "add", BACKEND+"/32", "dev", "lo")
        self.backend_installed = True
        state = self.root/"nat64-state"
        state.mkdir(mode=0o700)
        config = self.root/"tayga.conf"
        config.write_text("tun-device q29nat64\nipv4-addr 198.18.64.1\nipv6-addr 2001:db8:29:64::64\nprefix "+PREFIX+"\ndynamic-pool 198.18.64.0/24\ndata-dir "+str(state)+"\n")
        self.cmd(str(TOOLS/"tayga"), "-c", str(config), "--mktun")
        self.links.append("q29nat64")
        self.cmd("ip", "link", "set", "q29nat64", "up")
        self.cmd("ip", "route", "add", "198.18.64.0/24", "dev", "q29nat64")
        self.cmd("ip", "-6", "route", "add", PREFIX, "dev", "q29nat64")
        def launch(argv, name):
            proc = subprocess.Popen(argv, stdout=(self.evidence/name).open("wb"), stderr=subprocess.STDOUT, start_new_session=True)
            self.processes.append(proc)
            return proc
        launch([str(TOOLS/"tayga"), "-c", str(config), "-d"], "nat64-tayga.log")
        self.dns = Dns64(self.evidence)
        ra = self.root/"radvd.conf"
        ra.write_text("interface q29uplink { AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 4; AdvDefaultLifetime 12; prefix 2001:db8:29:64::/64 { AdvOnLink on; AdvAutonomous on; }; RDNSS "+ROUTER+" { AdvRDNSSLifetime 120; }; };\n")
        launch([str(TOOLS/"radvd"), "-n", "-C", str(ra), "-p", str(self.root/"radvd.pid"), "-m", "stderr", "-d", "1"], "nat64-radvd.log")
        for iface in ("q29uplink", "q29nat64"):
            launch(["tcpdump", "-i", iface, "-U", "-s", "0", "-w", str(self.evidence/(iface+".pcap"))], iface+"-capture.log")
        (self.evidence/"nat64-tools.json").write_text(json.dumps(TOOL_SHA, indent=2)+"\n")
        self.verify_translation()

    def verify_translation(self):
        """Exercise the actual translator before spending time booting Android."""
        expected = b"Q29-NAT64-fixture-selftest"
        translated = str(ipaddress.IPv6Network(PREFIX).network_address + int(ipaddress.IPv4Address(BACKEND)))
        receipts, failures = [], []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((BACKEND, 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]
            def receive():
                try:
                    conn, peer = listener.accept()
                    with conn:
                        conn.settimeout(5)
                        data = bytearray()
                        while len(data) < len(expected):
                            part = conn.recv(len(expected)-len(data))
                            if not part:
                                raise AssertionError("short NAT64 fixture request")
                            data.extend(part)
                        assert bytes(data) == expected
                        conn.sendall(data)
                        receipts.append(dict(peer=peer[0], bytes=len(data)))
                except BaseException as error:
                    failures.append(repr(error))
            worker = threading.Thread(target=receive, daemon=True)
            worker.start()
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
                    client.settimeout(5)
                    client.bind((ROUTER, 0))
                    client.connect((translated, port))
                    client.sendall(expected)
                    reply = bytearray()
                    while len(reply) < len(expected):
                        part = client.recv(len(expected)-len(reply))
                        if not part:
                            raise AssertionError("short NAT64 fixture reply")
                        reply.extend(part)
                    assert bytes(reply) == expected
            finally:
                worker.join(6)
            assert not worker.is_alive() and not failures and len(receipts) == 1, failures
            assert ipaddress.ip_address(receipts[0]["peer"]) in ipaddress.ip_network("198.18.64.0/24"), receipts
        (self.evidence/"nat64-fixture-selftest.json").write_text(json.dumps(dict(status="PASS", prefix=PREFIX, ipv6_destination=translated, ipv4_destination=BACKEND, receipts=receipts), indent=2)+"\n")

    def emulator_options(self):
        return ["-feature", "-WiFiPacketStream", "-net-tap", "q29eth", "-wifi-tap", "q29wifi"]

    def verify_carrier(self, arun, label):
        def ready():
            text = arun("shell", "dumpsys", "connectivity").stdout
            carrier = default_carrier(text)
            if not carrier:
                return False
            addresses = arun("shell", "su", "0", "ip", "-o", "addr", "show", "dev", carrier["interface"]).stdout
            return "2001:db8:29:64:" in addresses and not __import__('re').search(r"\binet ", addresses)
        wait_until(ready, "selected carrier is not IPv6-only SLAAC", 60)
        text = arun("shell", "dumpsys", "connectivity").stdout
        carrier = default_carrier(text)
        addresses = arun("shell", "su", "0", "ip", "-o", "addr", "show", "dev", carrier["interface"]).stdout
        (self.evidence/(label+"-connectivity.txt")).write_text(text)
        (self.evidence/(label+"-addresses.txt")).write_text(addresses)
        for family in ("-4", "-6"):
            (self.evidence/(label+family+"-routes.txt")).write_text(arun("shell", "su", "0", "ip", family, "route", "show", "table", "all").stdout)
        assert all(p.poll() is None for p in self.processes), "NAT64 fixture process exited"
        return carrier

    def close(self):
        if self.dns is not None:
            self.dns.close()
        for proc in reversed(self.processes):
            stop(proc)
        for link in reversed(self.links):
            self.cmd("ip", "link", "del", link)
        if self.backend_installed:
            self.cmd("ip", "addr", "del", BACKEND+"/32", "dev", "lo")
        for key, value in self.old_sysctl.items():
            self.cmd("sysctl", "-w", key+"="+value)
