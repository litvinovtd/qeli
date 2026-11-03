#!/usr/bin/env python3
"""Check raw upload/download stability against an already prepared iperf3 server.

This gate never resets the hosts or starts/stops their services. Prepare an idle,
dedicated lab and an iperf3 server yourself. Failed/missing/nonfinite measurements
refuse admission; every requested run in both directions is mandatory.
QELI_GATE_RUNS (2..20, default 5), QELI_GATE_MAX_SPREAD (0..100 exclusive,
default 8 percent), QELI_GATE_PORT (default 5201). SSH credentials/hosts use
QELI_LAB_PASS, QELI_LAB_SERVER and QELI_LAB_CLIENT.
Exit 0 means this raw measurement window met the criteria, not future stability.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import sys
import tempfile
import time

OUT = Path(__file__).resolve().parents[1] / "docs/data/benchmarks/stability_gate_last.json"


def settings(environ):
    runs = int(environ.get("QELI_GATE_RUNS", "5"))
    limit = float(environ.get("QELI_GATE_MAX_SPREAD", "8"))
    port = int(environ.get("QELI_GATE_PORT", "5201"))
    if not 2 <= runs <= 20:
        raise ValueError("QELI_GATE_RUNS must be between 2 and 20")
    if not math.isfinite(limit) or not 0 <= limit < 100:
        raise ValueError("QELI_GATE_MAX_SPREAD must be finite and in [0, 100)")
    if not 1 <= port <= 65535:
        raise ValueError("QELI_GATE_PORT must be between 1 and 65535")
    server = str(ipaddress.ip_address(environ.get("QELI_LAB_SERVER", "10.66.116.10")))
    client = str(ipaddress.ip_address(environ.get("QELI_LAB_CLIENT", "10.66.116.11")))
    if server == client:
        raise ValueError("raw gate needs two different lab addresses")
    return runs, limit, port, server, client


def valid_rate(value):
    try:
        return (type(value) in (int, float) and math.isfinite(value) and value > 0)
    except OverflowError:
        return False


def stats(vals):
    # Keep the entire requested sample population; never discard failed runs.
    if len(vals) < 2 or any(not valid_rate(value) for value in vals):
        return None
    high, low = max(vals), min(vals)
    # Normalize before subtraction to avoid overflow with finite extreme inputs.
    spread = (1 - low / high) * 100
    return {"n": len(vals), "min": low, "max": high,
            "median": statistics.median(vals),
            "stdev": statistics.pstdev(vals), "spread_pct": spread}


def inspection_program(port):
    """Read-only Linux probes. Any missing tool or failed probe refuses admission."""
    return (
        "import json,subprocess\n"
        "def query(args):\n"
        " return subprocess.check_output(args,text=True,timeout=15)\n"
        "print(json.dumps(dict("
        "processes=query(['ps','-eo','comm=,args=']),"
        "links=json.loads(query(['ip','-j','link','show'])),"
        "qdiscs=json.loads(query(['tc','-j','qdisc','show'])),"
        f"connections=query(['ss','-Htn','( sport = :{port} or dport = :{port} )'])"
        ")))\n"
    )


def inspect(connection, port):
    report = json.loads(connection.checked(
        "python3 -c " + shlex.quote(inspection_program(port)), "read-only lab inspection", timeout=60))
    if (not isinstance(report, dict) or
        not isinstance(report.get("processes"), str) or
        not isinstance(report.get("connections"), str) or
        not isinstance(report.get("links"), list) or
        not isinstance(report.get("qdiscs"), list)):
        raise RuntimeError("invalid lab inspection response")
    busy = []
    for line in report["processes"].splitlines():
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        name, args = parts[0], parts[1] if len(parts) > 1 else ""
        if (name in {"qeli", "qemu-system-x86", "qemu-system-x86_64", "pidstat", "nc"} or
            (name == "top" and "-b" in args.split()) or
            (name == "iperf3" and any(flag in args.split() for flag in ("-c", "--client")))):
            busy.append("process " + name)
    for link in report["links"]:
        if not isinstance(link, dict):
            raise RuntimeError("invalid link inspection")
        info = link.get("linkinfo", {})
        if not isinstance(info, dict):
            raise RuntimeError("invalid link metadata")
        if info.get("info_kind") in {"tun", "tap"}:
            busy.append("tunnel interface " + str(link.get("ifname")))
    for qdisc in report["qdiscs"]:
        if not isinstance(qdisc, dict):
            raise RuntimeError("invalid qdisc inspection")
        if qdisc.get("kind") in {"netem", "tbf", "htb", "cake", "hfsc"}:
            busy.append("shaping qdisc " + qdisc["kind"])
    if report["connections"].strip():
        busy.append("existing iperf connections")
    if busy:
        raise RuntimeError("lab is busy: " + ", ".join(busy))
    return {"quiet": True, "interfaces": [link.get("ifname") for link in report["links"]],
            "qdiscs": [item.get("kind") for item in report["qdiscs"]],
            "iperf_connections": 0}


def measure(connection, server, port, reverse):
    try:
        command = (f"timeout 40 iperf3 -c {shlex.quote(server)} -p {port} "
                   f"-t 12 -i 0 {'-R ' if reverse else ''}--json")
        reply = json.loads(connection.checked(command, "raw iperf3 measurement", timeout=55))
        if not isinstance(reply, dict) or reply.get("error"):
            raise ValueError("iperf3 reported an error")
        bits = reply["end"]["sum_received"]["bits_per_second"]
        if not valid_rate(bits):
            raise ValueError("iperf3 returned an invalid throughput")
        value = bits / 1e6
        if not valid_rate(value):
            raise ValueError("iperf3 returned an invalid throughput")
        return {"mbps": value}
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        return {"mbps": None, "error": str(error)}


def save_result(path, payload):
    path = Path(path)
    data = (json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as stream:
            staged = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def main(environ=None, connect=None, sleep=time.sleep, output=OUT):
    environ = os.environ if environ is None else environ
    # Validate before importing optional SSH dependencies or connecting.
    try:
        runs, limit, port, server, client = settings(environ)
    except (ValueError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    payload = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "runs": runs, "max_spread_pct": limit, "server": server, "client": client,
               "port": port, "directions": {}, "inspections": {}, "verdict_quiet": False,
               "errors": []}
    connections = []
    try:
        if connect is None:
            from native_lab import connect_lab
            connect = connect_lab
        s = connect(server, "root", environ.get("QELI_LAB_PASS", ""))
        connections.append(s)
        cl = connect(client, "root", environ.get("QELI_LAB_PASS", ""))
        connections.append(cl)
        for label, connection in (("server", s), ("client", cl)):
            payload["inspections"][label + "_before"] = inspect(connection, port)
        for direction, reverse in (("up", False), ("down", True)):
            samples = []
            for index in range(runs):
                sample = measure(cl, server, port, reverse)
                samples.append(sample)
                print(f"{direction} {index + 1}/{runs}: {sample['mbps']} Mbps")
                if index + 1 < runs:
                    sleep(2)
            payload["directions"][direction] = {
                "samples": samples, "stats": stats([sample["mbps"] for sample in samples])}
        for label, connection in (("server", s), ("client", cl)):
            payload["inspections"][label + "_after"] = inspect(connection, port)
        payload["verdict_quiet"] = all(
            row["stats"] is not None and row["stats"]["n"] == runs and
            row["stats"]["spread_pct"] <= limit
            for row in payload["directions"].values())
    except Exception as error:
        payload["errors"].append(str(error))
        payload["verdict_quiet"] = False
    finally:
        for connection in reversed(connections):
            try:
                connection.close()
            except Exception as error:
                payload["errors"].append("SSH close failed: " + str(error))
                payload["verdict_quiet"] = False
    try:
        save_result(output, payload)
    except (OSError, ValueError, TypeError) as error:
        print(f"FAIL: result publication failed: {error}", file=sys.stderr)
        return 1
    print("PASS: raw measurement window is stable" if payload["verdict_quiet"] else
          "FAIL: incomplete, noisy or busy lab measurement")
    for error in payload["errors"]:
        print(error, file=sys.stderr)
    return 0 if payload["verdict_quiet"] else 1


if __name__ == "__main__":
    sys.exit(main())
