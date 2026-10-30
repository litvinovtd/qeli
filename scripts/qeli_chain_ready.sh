#!/bin/sh
# Read-only ingress gate. Defaults must match qeli_chain_guard.py.
set -eu
for tool in iptables ip6tables; do
    "$tool" -w 5 -t mangle -C FORWARD -i qeli-in -j QELI_CHAIN_IN
    "$tool" -w 5 -t mangle -C QELI_CHAIN_IN -j DROP
done
iptables -w 5 -t mangle -C QELI_CHAIN_IN -o qeli-out -j RETURN
python3 -c 'import json,subprocess; r=json.loads(subprocess.check_output(["ip","-4","-j","rule","show"])); assert any(x.get("priority")==20800 and x.get("iif")=="qeli-in" and str(x.get("table"))=="208" for x in r); r=json.loads(subprocess.check_output(["ip","-4","-j","route","show","table","208"])); assert any(x.get("type")=="blackhole" and x.get("dst")=="default" and x.get("metric")==32767 for x in r)'
