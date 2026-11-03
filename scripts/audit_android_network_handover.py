#!/usr/bin/env python3
"""Actual Android carrier-network switching in a disposable private AVD."""
import json
import re
import time
from android_lab_ui import wait_until


def default_carrier(text):
    match = re.search(r"Active default network:\s*(\d+)", text)
    if match is None:
        return None
    netid = match.group(1)
    # Only Current Networks; historical/default-event logs must not supply stale facts.
    current = text.split("Current Networks:", 1)[1].split("Status for known UIDs:", 1)[0]
    for chunk in current.split("NetworkAgentInfo{")[1:]:
        if not re.search(r"network\{"+netid+r"\}",chunk):continue
        handle = re.search(r"(?:handle|nethandle)\{(\d+)\}",chunk)
        kind = re.search(r"Transports:\s*([A-Z]+)",chunk)
        interface = re.search(r"InterfaceName:\s*([^\s}]+)",chunk)
        assert handle and kind and interface, chunk
        assert kind.group(1) in ("WIFI","CELLULAR","ETHERNET"),chunk
        return dict(netid=netid,handle=handle.group(1),transport=kind.group(1),interface=interface.group(1))
    raise AssertionError("default network absent from current network agents: "+netid)


def carrier_committed_since(before, current, handle):
    """Require a fresh commit, even when a carrier handle appeared in an earlier cycle."""
    marker = "Roaming path committed: android:" + handle
    # A delimiter prevents handle 12 matching handle 123. No log rotation can
    # increase this count without a new record; a loss of evidence fails closed.
    pattern = re.compile(re.escape(marker) + r"(?=\s|$)")
    return len(pattern.findall(current)) > len(pattern.findall(before))


def network_handover(arun,evidence,probe,result, *, bursts=None, cycles=1, dns_probe=None):
    if not isinstance(cycles, int) or not 1 <= cycles <= 5:raise ValueError("cycles must be 1..5")
    checks=result["network_handover"]={"cells":[], "requested_cycles":cycles}
    tcp = result["recovery_transport"] == "tcp"
    checks["contract"] = "TCP_FULL_RECONNECT_RETAINED_TUN" if tcp else "UDP_SOFT_ROAMING_RETAINED_SESSION_TUN"
    def save(name,value):
        (evidence/name).write_text(value)
        return value
    def logs():return arun("shell","logcat","-d","-s","VpnSvc:D").stdout
    def counts():
        text=logs()
        return dict(published=text.count("Android VPN CONNECTED:"),auth=text.count("Auth OK:"),plans=len(re.findall(r"Native NetworkPlan [0-9]+ APPLIED:",text)),commits=text.count("Roaming path committed:"))
    def carrier():return default_carrier(arun("shell","dumpsys","connectivity").stdout)
    def snapshot(label):
        conn=save(label+"-connectivity.txt",arun("shell","dumpsys","connectivity").stdout)
        physical=default_carrier(conn);assert physical,conn
        pid=arun("shell","pidof","com.qeli").stdout.strip();assert re.fullmatch(r"[0-9]+",pid),pid
        links=save(label+"-links.txt",arun("shell","su","0","ip","-o","link","show").stdout)
        tun=re.findall(r"(?m)^([0-9]+): (tun[0-9]+):",links);assert len(tun)==1,links
        index,name=tun[0]
        addresses=save(label+"-addresses.txt",arun("shell","su","0","ip","-o","addr","show","dev",name).stdout)
        service=save(label+"-services.txt",arun("shell","dumpsys","activity","services","com.qeli").stdout)
        assert "isForeground=true" in service and "startRequested=true" in service,service
        save(label+"-vpn.txt",arun("shell","dumpsys","vpn_management").stdout)
        return dict(pid=pid,tun=name,ifindex=index,addresses=addresses),physical
    initial,first=snapshot("handover-initial")
    save("handover-phone-help.txt",arun("shell","cmd","phone","help",check=False).stdout)
    save("handover-wifi-status.txt",arun("shell","cmd","wifi","status",check=False).stdout)
    wifi=arun("shell","settings","get","global","wifi_on").stdout.strip()
    data=arun("shell","settings","get","global","mobile_data").stdout.strip()
    assert wifi in ("0","1","2") and data in ("0","1"),(wifi,data)
    checks["original_settings"]={"wifi_on":wifi,"mobile_data":data}
    checks["initial_carrier"]=first
    original_iface=None
    if tcp:
        assert "Service started: TCP/fake-tls" in logs() and "Experimental UDP roaming path adapter active" not in logs(),logs()
    else:
        assert "Experimental UDP roaming path adapter active" in logs(),logs()
    try:
        # Enable the alternate transport first; these controls affect only readonly AVD state.
        arun("shell","svc","data","enable")
        if first["transport"]=="ETHERNET":
            arun("shell","svc","wifi","enable")
            interface=first["interface"];assert re.fullmatch(r"eth[0-9]+",interface),interface
            original_iface=interface
            actions=[("away",["su","0","ip","link","set",interface,"down"],None),
                     ("return",["su","0","ip","link","set",interface,"up"],"ETHERNET")]
        elif first["transport"]=="WIFI":
            actions=[("away",["svc","wifi","disable"],"CELLULAR"),("return",["svc","wifi","enable"],"WIFI")]
        else:
            actions=[("away",["svc","wifi","enable"],"WIFI"),("return",["svc","wifi","disable"],"CELLULAR")]
        if cycles > 1:actions=[(f"{label}-{cycle+1:02d}",action,expected) for cycle in range(cycles) for label,action,expected in actions]
        for label,action,expected in actions:
            before,old=snapshot("handover-"+label+"-before");oldcounts=counts();initial_logs=logs();start=time.monotonic()
            if bursts is None:arun("shell",*action)
            else:bursts.run("handover-"+label,lambda:arun("shell",*action))
            wait_until(lambda:(new:=carrier()) is not None and new["handle"]!=old["handle"] and (expected is None or new["transport"]==expected),"default carrier did not switch",45)
            new=carrier();assert new and new["handle"]!=old["handle"]
            if tcp:
                wait_until(lambda:counts()["plans"]>oldcounts["plans"] and counts()["auth"]>oldcounts["auth"],"TCP did not reconnect/apply a fresh plan",40)
                if oldcounts["published"]:
                    wait_until(lambda:counts()["published"]>oldcounts["published"],"TCP did not publish fresh CONNECTED",20)
                assert "reconnecting on the current network" in logs()[len(initial_logs):],logs()
            else:
                wait_until(lambda:carrier_committed_since(initial_logs,logs(),new["handle"]),"Android did not commit the new actual carrier token",35)
            reply=[probe("Q29RECOVERED" if label.startswith("away") else "Q29MANUAL",True,
                         label="handover-"+label+"-"+family+"-"+protocol,
                         family=family,protocol=protocol,payload_bytes=16384 if protocol=="tcp" else 257)
                   for family in ("ipv4","ipv6") for protocol in ("tcp","udp")]
            if dns_probe is not None:dns_probe("handover-"+label,True,modes=("system",))
            after,physical=snapshot("handover-"+label+"-after");nowcounts=counts()
            assert after==before==initial and physical==new,(before,after,initial,new,physical)
            committed_handles=re.findall(r"Roaming path committed: android:([0-9]+)",logs()[len(initial_logs):])
            if tcp:
                assert nowcounts["auth"]>oldcounts["auth"] and nowcounts["plans"]>oldcounts["plans"] and nowcounts["commits"]==oldcounts["commits"]==0,(oldcounts,nowcounts)
                assert not committed_handles and "Android TUN reused for NetworkPlan" in logs()[len(initial_logs):],logs()
            else:
                assert nowcounts["auth"]==oldcounts["auth"] and nowcounts["plans"]==oldcounts["plans"] and nowcounts["commits"]>=oldcounts["commits"]+1,(oldcounts,nowcounts)
                assert committed_handles and all(handle==new["handle"] for handle in committed_handles),committed_handles
            checks["cells"].append(dict(name=label,status="PASS",before=before,after=after,old_carrier=old,new_carrier=new,committed_carrier_handles=committed_handles,before_counts=oldcounts,after_counts=nowcounts,probe=reply,elapsed_seconds=round(time.monotonic()-start,2)))
            save("handover-"+label+"-logcat.log",logs())
            print("HANDOVER_"+label.upper()+"_PASS "+old["transport"]+" -> "+new["transport"],flush=True)
    finally:
        if original_iface:arun("shell","su","0","ip","link","set",original_iface,"up",check=False)
        arun("shell","svc","wifi","enable" if wifi in ("1","2") else "disable",check=False)
        arun("shell","svc","data","enable" if data=="1" else "disable",check=False)
        save("handover-final-logcat.log",logs())
        save("handover-final-connectivity.txt",arun("shell","dumpsys","connectivity",check=False).stdout)
        (evidence/"handover-results.json").write_text(json.dumps(checks,indent=2)+"\n")
    wait_until(lambda:arun("shell","settings","get","global","wifi_on").stdout.strip()==wifi,"Wi-Fi setting not restored",15)
    assert arun("shell","settings","get","global","mobile_data").stdout.strip()==data
    assert len(checks["cells"]) == cycles * 2
    checks["settings_restored"]="PASS"
    (evidence/"handover-results.json").write_text(json.dumps(checks,indent=2)+"\n")
