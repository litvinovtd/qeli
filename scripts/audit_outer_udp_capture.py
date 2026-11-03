#!/usr/bin/env python3
"""Observe real IPv4 UDP carrier packets on the private release-fixture router."""
import argparse, ipaddress, json, socket, struct, time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("interface")
    p.add_argument("output", type=Path)
    args = p.parse_args()
    peers = {ipaddress.IPv4Address(x).packed for x in ("10.46.1.2", "10.46.2.2")}
    counts = {"packets": 0, "fragmented": 0, "over_1280": 0, "uplink": 0, "downlink": 0, "max_ip_length": 0}
    ready, stop = Path(str(args.output)+".ready"), Path(str(args.output)+".stop")
    with Path(str(args.output)+".pcap").open("wb") as pcap, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        pcap.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        sock.bind((args.interface, 0)); sock.settimeout(0.1)
        ready.touch()
        deadline = time.monotonic()+120
        while not stop.exists():
            if time.monotonic() >= deadline:
                raise SystemExit("capture exceeded its private fixture deadline")
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 34 or frame[12:14] != b"\x08\x00": continue
            packet = frame[14:]
            if packet[0] >> 4 != 4 or packet[9] != 17 or {packet[12:16], packet[16:20]} != peers: continue
            length, flags = struct.unpack_from("!H", packet, 2)[0], struct.unpack_from("!H", packet, 6)[0]
            stamp = time.time_ns()
            pcap.write(struct.pack("<IIII", stamp//1_000_000_000, stamp%1_000_000_000//1000, len(frame), len(frame)))
            pcap.write(frame)
            counts["packets"] += 1
            counts["fragmented"] += bool(flags & 0x3fff)
            counts["over_1280"] += length > 1280
            counts["max_ip_length"] = max(counts["max_ip_length"], length)
            counts["uplink" if packet[12:16] == ipaddress.IPv4Address("10.46.1.2").packed else "downlink"] += 1
    passed = counts["uplink"] > 0 and counts["downlink"] > 0 and not counts["fragmented"] and not counts["over_1280"]
    args.output.write_text(json.dumps(dict(status="PASS" if passed else "FAIL", **counts))+"\n")
    print(args.output.read_text(), end="", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
