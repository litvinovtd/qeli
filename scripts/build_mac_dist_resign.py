#!/usr/bin/env python3
"""п.4 release — refresh the macOS distributable with the post-п.2 libqeli.dylib.

The C# code is unchanged, so only the native REALITY core differs vs the prior
universal Qeli.app. We swapped libqeli.dylib locally, ship the bundle to .10
(which has rcodesign), re-sign every Mach-O ad-hoc + the bundle, repack the zip
with Unix perms, and pull it back to qeli-mac/dist/."""
import os, sys, posixpath
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

HOST = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
LOCAL_TAR = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-mac\dist\Qeli.app.fresh.tar.gz"
LOCAL_ZIP = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-mac\dist\Qeli-macOS-universal.zip"
RDIR = "/root/mac-resign"
RCS = "/usr/local/bin/rcodesign"


def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20, look_for_keys=False, allow_agent=False)
    return c


def r(c, cmd, t=300):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


c = conn()
print("[rcodesign]", r(c, f"{RCS} --version 2>/dev/null || echo MISSING"))

# 1. upload + extract
r(c, f"rm -rf {RDIR}; mkdir -p {RDIR}")
sf = c.open_sftp(); sf.put(LOCAL_TAR, f"{RDIR}/Qeli.app.tar.gz"); sf.close()
print("[upload] Qeli.app.tar.gz")
print("[extract]", r(c, f"cd {RDIR} && tar -xzf Qeli.app.tar.gz && echo OK && du -sh Qeli.app"))
print("[dylib in bundle]", r(c, f"stat -c %s {RDIR}/Qeli.app/Contents/MacOS/libqeli.dylib"),
      "| arch:", r(c, f"file {RDIR}/Qeli.app/Contents/MacOS/libqeli.dylib | grep -oE 'universal binary.*' | head -1"))

# 2. ad-hoc sign every Mach-O in Contents/MacOS
macho_list = r(c, f"cd {RDIR} && for f in Qeli.app/Contents/MacOS/*; do "
                  f"file \"$f\" | grep -q Mach-O && echo \"$f\"; done")
machos = [m for m in macho_list.splitlines() if m.strip()]
print(f"[machos] {len(machos)} Mach-O files to sign")
ok = 0
for m in machos:
    out = r(c, f"cd {RDIR} && {RCS} sign \"{m}\" 2>&1 | tail -1")
    if "error" in out.lower() or "fail" in out.lower():
        print(f"   SIGN FAIL {m}: {out}")
    else:
        ok += 1
print(f"[machos] signed {ok}/{len(machos)} ad-hoc")

# 3. sign the bundle
print("[bundle sign]", r(c, f"cd {RDIR} && {RCS} sign Qeli.app 2>&1 | tail -2"))

# 4. sanity: verify one Mach-O carries a signature
print("[verify lib]", r(c, f"{RCS} verify {RDIR}/Qeli.app/Contents/MacOS/libqeli.dylib 2>&1 | tail -2 || echo '(verify n/a)'"))
print("[apphost sig]", r(c, f"{RCS} print-signature-info {RDIR}/Qeli.app/Contents/MacOS/QeliMac 2>/dev/null | grep -iE 'signature|flags|identifier' | head -3 || codesign-like-skip"))

# 5. repack zip with Unix perms (python3 zipfile; +x survives)
zip_py = (
    "import os,zipfile,stat,sys\n"
    f"root=r'{RDIR}'\n"
    "app='Qeli.app'\n"
    f"out=os.path.join(root,'Qeli-macOS-universal.zip')\n"
    "zf=zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6)\n"
    "base=os.path.join(root,app)\n"
    "for dp,dn,fn in os.walk(base):\n"
    " for name in fn:\n"
    "  full=os.path.join(dp,name)\n"
    "  rel=os.path.relpath(full,root)\n"
    "  st=os.stat(full)\n"
    "  zi=zipfile.ZipInfo(rel.replace(os.sep,'/'))\n"
    "  zi.external_attr=(st.st_mode & 0xFFFF)<<16\n"
    "  zi.compress_type=zipfile.ZIP_DEFLATED\n"
    "  with open(full,'rb') as f: zf.writestr(zi,f.read())\n"
    "zf.close()\n"
    "print(os.path.getsize(out))\n"
)
r(c, f"cat > {RDIR}/mkzip.py <<'PYZIP'\n{zip_py}PYZIP")
zsize = r(c, f"cd {RDIR} && python3 mkzip.py")
print(f"[zip] Qeli-macOS-universal.zip = {zsize} bytes")

# 6. pull the zip back
sf = c.open_sftp(); sf.get(f"{RDIR}/Qeli-macOS-universal.zip", LOCAL_ZIP); sf.close()
print(f"[pull] -> qeli-mac/dist/Qeli-macOS-universal.zip ({os.path.getsize(LOCAL_ZIP)} bytes)")
c.close()
print("[done]")
