#!/usr/bin/env python3
"""Arm trusted SSID through real Release UI while Android lockdown keeps VPN active."""
import re
from android_lab_ui import AndroidVpnSettings


def connected_ssid(text):
    match=re.search(r'^Wifi is connected to "([^"\n]+)"$',text,re.M)
    if match is None or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}",match.group(1)):
        raise ValueError("fixture requires an observed simple ASCII SSID")
    return match.group(1)


def has_location_foreground_type(text):
    # API34 dumpsys prints an unprefixed hexadecimal `types`, not an API field name.
    active=text.split("User 0 active services:",1)[-1]
    record=re.search(r"ServiceRecord\{[^\n]*com\.qeli/\.VpnServiceImpl\}([\s\S]*?)(?=\n  \* ServiceRecord|\n  Connection bindings|\Z)",active)
    if record is None:return False
    types=re.findall(r"isForeground=true foregroundId=\d+ types=([0-9a-f]+)\b",record.group(1),re.I)
    return len(types)==1 and bool(int(types[0],16)&8)


def enable_trusted_wifi(arun,evidence,result):
    for permission in ("ACCESS_COARSE_LOCATION","ACCESS_FINE_LOCATION","NEARBY_WIFI_DEVICES"):
        arun("shell","pm","grant","com.qeli","android.permission."+permission)
    arun("shell","cmd","location","set-location-enabled","true")
    status=arun("shell","cmd","wifi","status").stdout
    (evidence/"trusted-wifi-observed-status.txt").write_text(status)
    ssid=connected_ssid(status)
    ui=AndroidVpnSettings(arun,evidence,result,"Qeli",prefix="trusted-")
    arun("shell","am","start","-n","com.qeli/.MainActivity")
    tree=ui.ui("main")
    button=next((n for n in tree.iter("node") if n.get("resource-id")=="com.qeli:id/btnSettings"),None)
    assert button is not None,"Qeli Settings button absent"
    ui.tap(button);tree=ui.ui("settings")
    checkbox=ui.text_node(tree,"Pause VPN on trusted Wi-Fi")
    assert checkbox is not None and checkbox.get("checkable")=="true"
    if checkbox.get("checked")!="true":ui.tap(checkbox)
    tree=ui.ui("trusted-enabled")
    fields=[n for n in tree.iter("node") if n.get("class","").endswith("EditText") and n.get("enabled")=="true" and (not n.get("text","") or n.get("text","").startswith("Trusted Wi-Fi names (one SSID per line)"))]
    assert len(fields)==1,"trusted SSID editor not unique"
    ui.tap(fields[0]);arun("shell","input","text",ssid)
    arun("shell","input","keyevent","KEYCODE_BACK")
    tree=ui.ui("edited")
    save=ui.text_node(tree,"SAVE");assert save is not None and save.get("class","").endswith("Button")
    ui.tap(save);tree=ui.ui("saved")
    button=next(n for n in tree.iter("node") if n.get("resource-id")=="com.qeli:id/btnSettings")
    ui.tap(button);tree=ui.ui("readback")
    checkbox=ui.text_node(tree,"Pause VPN on trusted Wi-Fi")
    assert checkbox is not None and checkbox.get("checked")=="true"
    assert any(n.get("class","").endswith("EditText") and n.get("text")==ssid for n in tree.iter("node")),"trusted SSID was not persisted by UI"
    cancel=ui.text_node(tree,"CANCEL");assert cancel is not None
    ui.tap(cancel)
    service=arun("shell","dumpsys","activity","services","com.qeli/.VpnServiceImpl").stdout
    (evidence/"trusted-wifi-service.txt").write_text(service)
    assert has_location_foreground_type(service),"visible trusted UI did not arm location foreground type"
    result["trusted_wifi_lockdown"]={"status":"ARMED","SSID":ssid,"UI_readback":True,"prefs_injection":False,"location_foreground_type":True}
