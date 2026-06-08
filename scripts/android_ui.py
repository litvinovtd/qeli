#!/usr/bin/env python3
"""Tiny adb UI-automation helper for the .11 emulator (qeli multipath e2e)."""
import os, sys, time, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

ADB = "/root/android-sdk/platform-tools/adb"
_c = None


def conn():
    global _c
    if _c is None:
        _c = paramiko.SSHClient(); _c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        _c.connect("10.66.116.11", username="root", password=os.environ["QELI_LAB_PASS"],
                   timeout=25, look_for_keys=False, allow_agent=False)
    return _c


def sh(cmd, t=120):
    i, o, e = conn().exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


def adb(args, t=120):
    return sh(f"{ADB} {args}", t)


def dump():
    sh(f"{ADB} shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1")
    return sh(f"{ADB} shell cat /sdcard/ui.xml 2>/dev/null")


def nodes(ui=None):
    if ui is None:
        ui = dump()
    out = []
    for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?resource-id="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui):
        t, rid, x1, y1, x2, y2 = m.groups()
        out.append((t, rid, (int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2))
    return out


def tap_text(needle, ui=None, partial=True):
    for t, rid, cx, cy in nodes(ui):
        if (needle == t) or (partial and needle.lower() in t.lower()):
            adb(f"shell input tap {cx} {cy}")
            return (t, cx, cy)
    return None


def texts(ui=None):
    ui = ui if ui is not None else dump()
    return [t for t in re.findall(r'text="([^"]*)"', ui) if t.strip()]


if __name__ == "__main__":
    print(texts())
