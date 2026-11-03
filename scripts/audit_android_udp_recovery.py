#!/usr/bin/env python3
"""UDP/QUIC same-network soft recovery and grace expiry in the private Q29 namespace."""
import json
import re
import subprocess
import time
from android_lab_ui import wait_until


def udp_recovery(arun, evidence, probe, result):
    checks = result["udp_recovery"] = {"cells": []}
    def save(name, value):
        (evidence / name).write_text(value)
        return value
    def logs():
        return arun("shell", "logcat", "-d", "-s", "VpnSvc:D").stdout
    def counts():
        text = logs()
        return dict(auth=text.count("Auth OK:"), plans=len(re.findall(r"Native NetworkPlan [0-9]+ APPLIED:", text)),
                    commits=text.count("Roaming path committed:"))
    def snapshot(label):
        pid = arun("shell", "pidof", "com.qeli").stdout.strip()
        assert re.fullmatch(r"[0-9]+", pid), pid
        links = save(label+"-links.txt",arun("shell","su","0","ip","-o","link","show").stdout)
        tun = re.findall(r"(?m)^([0-9]+): (tun[0-9]+):", links);assert len(tun)==1,links
        index,name=tun[0]
        addresses=save(label+"-addresses.txt",arun("shell","su","0","ip","-o","addr","show","dev",name).stdout)
        state=save(label+"-services.txt",arun("shell","dumpsys","activity","services","com.qeli").stdout)
        assert "isForeground=true" in state and "startRequested=true" in state,state
        save(label+"-vpn.txt",arun("shell","dumpsys","vpn_management").stdout)
        return dict(pid=pid,tun=name,ifindex=index,addresses=addresses)
    marker="UDP same-network NAT recovery"
    assert "Experimental UDP roaming path adapter active" in logs(),logs()
    original_firewall=subprocess.check_output(["iptables-save"],text=True)
    for kind in ("soft","grace-expiry"):
        label="udp-"+kind
        before=snapshot(label+"-before");prior_counts=counts();initial_logs=logs();initial_requests=initial_logs.count(marker)
        start=time.monotonic()
        rules=[("INPUT",["-p","udp","--dport","24967","-m","comment","--comment","q29-private-"+kind,"-j","DROP"]),
               ("OUTPUT",["-p","udp","--sport","24967","-m","comment","--comment","q29-private-"+kind,"-j","DROP"])]
        installed=[]
        try:
            for chain,rule in rules:
                subprocess.run(["iptables","-I",chain,"1",*rule],check=True,capture_output=True,text=True);installed.append((chain,rule))
            save(label+"-fault-firewall.txt",subprocess.check_output(["iptables-save"],text=True))
            wait_until(lambda:logs().count(marker)>initial_requests,"no actual same-network NAT recovery request",45)
            request_elapsed=round(time.monotonic()-start,2)
            fault=snapshot(label+"-fault");assert fault==before,(before,fault)
            if kind=="grace-expiry":
                errors=initial_logs.count("Native transport error")
                wait_until(lambda:logs().count("Native transport error")>errors,"UDP grace did not fall back",25)
                denied=probe("Q29BLOCKED",False,label=label+"-blocked")
                save(label+"-fault-logcat.log",logs())
            else:
                # Restore while the newly requested path transaction is in its bounded grace.
                denied=None
                save(label+"-fault-logcat.log",logs())
            fault_seconds=round(time.monotonic()-start,2)
        finally:
            for chain,rule in reversed(installed):
                subprocess.run(["iptables","-D",chain,*rule],check=True,capture_output=True,text=True)
        if kind=="soft":
            wait_until(lambda:counts()["commits"]>prior_counts["commits"],"soft recovery did not commit",25)
        else:
            wait_until(lambda:counts()["plans"]>prior_counts["plans"],"full UDP recovery did not apply a fresh plan",65)
        reply=probe("Q29RECOVERED" if kind=="soft" else "Q29MANUAL",True,label=label+"-recovered")
        after=snapshot(label+"-after");after_counts=counts()
        assert before==after,(before,after)
        if kind=="soft":
            assert after_counts["auth"]==prior_counts["auth"] and after_counts["plans"]==prior_counts["plans"],(prior_counts,after_counts)
        else:
            assert after_counts["auth"]==prior_counts["auth"]+1 and after_counts["plans"]==prior_counts["plans"]+1,(prior_counts,after_counts)
            delta=logs()[len(initial_logs):]
            sequence=[delta.find(v) for v in (marker,"Native transport error","Auth OK:","Native NetworkPlan")]
            assert all(v>=0 for v in sequence) and sequence==sorted(sequence),delta
            assert fault_seconds-request_elapsed>=15,(request_elapsed,fault_seconds)
        checks["cells"].append(dict(name=kind,status="PASS",before=before,fault=fault,after=after,before_counts=prior_counts,
                                   after_counts=after_counts,request_elapsed_seconds=request_elapsed,fault_seconds=fault_seconds,
                                   blocked_probe=denied,recovered_probe=reply))
        save(label+"-complete-logcat.log",logs())
        print("UDP_"+kind.upper()+"_PASS",flush=True)
    # Ignore changing packet counters while requiring exact ownership/rule restoration.
    normal=lambda value:re.sub(r"\[\d+:\d+\]","[COUNTERS]","\n".join(l for l in value.splitlines() if not l.startswith("#")))
    restored=save("udp-firewall-restored.txt",subprocess.check_output(["iptables-save"],text=True))
    assert normal(restored)==normal(original_firewall)
    checks["private_firewall_restored"]="PASS"
    (evidence/"udp-recovery-results.json").write_text(json.dumps(checks,indent=2)+"\n")
