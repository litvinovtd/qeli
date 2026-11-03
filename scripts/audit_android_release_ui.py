#!/usr/bin/env python3
"""Import a production R8 INI profile through the file picker, outside instrumentation."""
import hashlib
import json
import subprocess
import time
from android_lab_ui import AndroidVpnSettings

STORAGE_PROBE = """printf 'Q29_STORAGE_PATH='; readlink -f /sdcard
df -P /sdcard
if [ -d /sdcard ] && [ -w /sdcard ]; then printf 'Q29_STORAGE_WRITABLE\\n'; fi
"""


def download_storage_ready(proc):
    """Admit this API34 AVD's published FUSE storage, not an underlying directory."""
    lines = proc.stdout.splitlines()
    paths = [line for line in lines if line.startswith('Q29_STORAGE_PATH=')]
    filesystems = [line.split() for line in lines if line.startswith('/dev/fuse ')]
    return (proc.returncode == 0 and paths == ['Q29_STORAGE_PATH=/storage/emulated/0']
            and 'Q29_STORAGE_WRITABLE' in lines and len(filesystems) == 1
            and len(filesystems[0]) == 6 and filesystems[0][-1] == '/storage/emulated')


def await_download_storage(arun, evidence, result, *, label, budget_seconds=60):
    """Bound external-storage readiness before package/UI work or INI push."""
    if label not in ('before-install', 'before-import'):
        raise ValueError('unknown storage observation phase')
    started = time.monotonic()
    deadline = started + budget_seconds
    samples = result.setdefault('external_storage_admission', {}).setdefault(label, [])
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            proc = arun('shell', STORAGE_PROBE, check=False, timeout=min(10, remaining))
            row = dict(stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
                       ready=download_storage_ready(proc))
        except subprocess.TimeoutExpired as error:
            row = dict(ready=False, error='ADB_STORAGE_PROBE_TIMEOUT', timeout=error.timeout)
        samples.append(dict(row, elapsed_seconds=round(time.monotonic()-started, 3)))
        (evidence / ('external-storage-' + label + '.json')).write_text(json.dumps(samples, indent=2)+'\n')
        if row['ready']:
            return
        remaining = deadline-time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise AssertionError('AVD_EXTERNAL_STORAGE_NOT_READY: ' + label)


def await_import_button(ui, tree, stable_ui):
    """Observe the completed tab transition instead of treating one dump as ready."""
    deadline=time.monotonic()+30
    for _ in range(5):
        button=next((n for n in tree.iter('node') if n.get('resource-id')=='com.qeli:id/btnImport'),None)
        if button is not None:return button
        tab=ui.text_node(tree,'Profiles')
        assert tab is not None,'product Profiles tab absent'
        if tab.get('selected')!='true':ui.tap(tab)
        if time.monotonic()>=deadline:break
        tree=stable_ui('profiles-ready')
    raise AssertionError('product Import button absent after bounded tab observation')


def import_release_profile(arun, evidence, result, keys, transport, *, server=None, tunnel_dns=False, apps_mode="all", policy_fixture=False):
    ui=AndroidVpnSettings(arun,evidence,result,"Qeli",prefix="release-")
    arun("shell","am","start","-n","com.qeli/.MainActivity")
    def stable_ui(label):
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            tree=ui.ui(label)
            waiting=next((n for n in tree.iter("node") if n.get("resource-id")=="android:id/aerr_wait"),None)
            if waiting is None:return tree
            result.setdefault("release_system_ui_anr_waits",[]).append(dict(label=label,sequence=ui.sequence))
            ui.tap(waiting)
        raise AssertionError("system UI ANR did not recover")
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        tree=stable_ui("launcher")
        if ui.text_node(tree,"Let app always run in background?") is not None:
            deny=ui.text_node(tree,"DENY");assert deny is not None
            ui.tap(deny);result["release_battery_exemption_denied"]=True
            continue
        if any(n.get("package")=="com.qeli" for n in tree.iter("node")):break
        time.sleep(.5)
    else:raise AssertionError("product Activity did not open")
    profile="tcp" if transport=="tcp" else "udp"
    fields=dict(server=(server or "10.0.2.2")+":"+str(24966 if profile=="tcp" else 24967),proto=profile,
                user="fixture",**{"pass":"fixture-password"},key=keys[profile],mode="fake-tls",
                quic=str(transport=="quic").lower(),gateway="true",kill_switch="false" if policy_fixture else "true",ipv6="required",dns="off",
                roaming="off" if profile=="tcp" else "required",mtu_probe="false",reconnect="true",
                reconnect_base_delay="1",reconnect_max_delay="2",timeout="15")
    if tunnel_dns:fields.update(dns="tunnel",dns_servers="198.19.0.53")
    assert apps_mode in ("all", "include", "exclude")
    fields["apps_mode"] = apps_mode
    if apps_mode != "all":fields["apps"] = "com.qeli.test" if apps_mode == "include" else "com.qeli.auditprobe" if policy_fixture else "com.android.settings"
    result["release_apps_mode"] = apps_mode
    ini="# Release fixture\n[qeli]\n"+"".join(k+" = "+v+"\n" for k,v in fields.items())+"[logging]\nlevel = debug\n"
    path=evidence/"release-fixture.ini";path.write_text(ini)
    await_download_storage(arun, evidence, result, label='before-import')
    arun("shell", "mkdir", "-p", "/sdcard/Download")
    arun("push",str(path),"/sdcard/Download/q29-release-fixture.ini")
    uploaded=arun("shell", "sha256sum", "/sdcard/Download/q29-release-fixture.ini").stdout.split()
    assert len(uploaded)==2 and uploaded[0]==hashlib.sha256(path.read_bytes()).hexdigest(), 'uploaded INI bytes differ'
    button=await_import_button(ui,tree,stable_ui)
    ui.tap(button);tree=stable_ui("import-chooser")
    option=ui.text_node(tree,"Import config file");assert option is not None
    ui.tap(option);tree=stable_ui("file-picker")
    file=ui.text_node(tree,"q29-release-fixture.ini")
    # DocumentsUI can return its toolbar before asynchronously loading file rows.
    for _ in range(3):
        if file is not None:break
        tree=stable_ui("file-picker-loaded");file=ui.text_node(tree,"q29-release-fixture.ini")
    if file is None:
        nav=next((n for n in tree.iter("node") if n.get("content-desc")=="Show roots"),None)
        assert nav is not None,"file-picker roots button absent"
        ui.tap(nav);tree=stable_ui("file-roots")
        # Select the unique observed storage root, not a Downloads label behind the drawer.
        storage=next((n for n in tree.iter("node") if n.get("text","").startswith("Android SDK built for ")),None)
        assert storage is not None,"AVD internal storage root absent"
        ui.tap(storage);tree=stable_ui("internal-storage")
        downloads=ui.text_node(tree,"Download");assert downloads is not None
        ui.tap(downloads);tree=stable_ui("download-folder")
        file=ui.text_node(tree,"q29-release-fixture.ini")
    assert file is not None,"fixture INI absent from actual file picker"
    ui.tap(file);tree=stable_ui("imported-profile")
    assert any(n.get("text")=="Release fixture" for n in tree.iter("node")),"imported profile not visible"
    result["release_ui_import"]={"status":"PASS","profile":"Release fixture","instrumentation":"NOT_RUN","private_prefs_injection":False,"format":"INI"}
