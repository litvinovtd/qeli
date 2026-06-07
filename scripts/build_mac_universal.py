#!/usr/bin/env python3
"""Assemble a signed universal (arm64+x86_64) Qeli.app on the Linux lab (.10),
WITHOUT a Mac.

Inputs (built locally first — Windows/Linux with the .NET 8 SDK):
  qeli-mac/dist/osx-arm64.tar.gz   (dotnet publish -r osx-arm64 --self-contained)
  qeli-mac/dist/osx-x64.tar.gz     (dotnet publish -r osx-x64  --self-contained)

On .10 (has llvm-lipo-19 + rcodesign): merges every per-arch Mach-O into a fat
binary (the already-universal libqeli.dylib is copied as-is), assembles the .app
(Info.plist from Info.plist.in, Qeli.icns), ad-hoc-signs each Mach-O + the bundle
with rcodesign, repacks a Unix-perm zip, and pulls it back to qeli-mac/dist/.
"""
import os, sys, posixpath
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

ROOT = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE"
DIST = os.path.join(ROOT, "qeli-mac", "dist")
INFO_PLIST_IN = os.path.join(ROOT, "qeli-mac", "Info.plist.in")
ICNS = os.path.join(DIST, "Qeli.app", "Contents", "Resources", "Qeli.icns")
HOST = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
RDIR = "/root/mac-build"
LIPO = "/usr/bin/llvm-lipo-19"
RCS = "/usr/local/bin/rcodesign"


def conn():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST[0], username=HOST[1], password=HOST[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def r(c, cmd, t=600):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()


# Remote assembly script (runs on .10).
REMOTE_PY = r'''
import os, subprocess, shutil, sys
RDIR="/root/mac-build"; ARM=RDIR+"/osx-arm64"; X64=RDIR+"/osx-x64"
APP=RDIR+"/Qeli.app"; MACOS=APP+"/Contents/MacOS"; RES=APP+"/Contents/Resources"
LIPO="/usr/bin/llvm-lipo-19"
shutil.rmtree(APP, ignore_errors=True)
os.makedirs(MACOS); os.makedirs(RES)
def fileb(p):
    try: return subprocess.run(["file","-b",p],capture_output=True).stdout
    except Exception: return b""
def is_macho(p): return b"Mach-O" in fileb(p)
def is_universal(p): return b"universal binary" in fileb(p)
lipo_n=copy_n=mac_n=0
for dp,dn,fn in os.walk(ARM):
    for name in fn:
        a=os.path.join(dp,name); rel=os.path.relpath(a,ARM)
        dst=os.path.join(MACOS,rel); os.makedirs(os.path.dirname(dst),exist_ok=True)
        x=os.path.join(X64,rel)
        # Already-fat files (libqeli.dylib + NuGet native assets like
        # libSkiaSharp/libHarfBuzzSharp/libAvaloniaNative ship universal2) -> copy
        # as-is; lipo refuses to re-fatten them.
        if name=="libqeli.dylib" or is_universal(a):
            shutil.copy2(a,dst); copy_n+=1; continue
        if is_macho(a) and os.path.exists(x):
            rc=subprocess.run([LIPO,"-create",a,x,"-output",dst]).returncode
            if rc!=0:                          # fallback: not lipo-able -> copy arm64
                shutil.copy2(a,dst); copy_n+=1
            else: lipo_n+=1; mac_n+=1
        else:
            shutil.copy2(a,dst); copy_n+=1
print(f"[assemble] lipo={lipo_n} copy={copy_n} (universal Mach-O={mac_n})")
# verify a key binary is fat
v=subprocess.run(["/usr/bin/file","-b",MACOS+"/QeliMac"],capture_output=True).stdout.decode()
print("[apphost]", v.strip()[:80])
d=subprocess.run(["/usr/bin/file","-b",MACOS+"/libqeli.dylib"],capture_output=True).stdout.decode()
print("[dylib]", d.strip()[:80])
'''


def main():
    c = conn()
    print("[rcodesign]", r(c, f"{RCS} --version 2>/dev/null || echo MISSING"))
    print("[lipo]", r(c, f"{LIPO} -version 2>/dev/null | head -1 || echo MISSING"))

    r(c, f"rm -rf {RDIR}; mkdir -p {RDIR}")
    sf = c.open_sftp()
    for t in ("osx-arm64.tar.gz", "osx-x64.tar.gz"):
        sf.put(os.path.join(DIST, t), f"{RDIR}/{t}")
        print(f"[upload] {t}")
    sf.put(INFO_PLIST_IN, f"{RDIR}/Info.plist.in")
    sf.put(ICNS, f"{RDIR}/Qeli.icns")
    sf.close()
    print("[extract]", r(c, f"cd {RDIR} && tar -xzf osx-arm64.tar.gz && tar -xzf osx-x64.tar.gz && echo OK"))

    # Assemble the universal Contents/MacOS via lipo.
    r(c, f"cat > {RDIR}/assemble.py <<'PYEOF'\n{REMOTE_PY}\nPYEOF")
    print(r(c, f"cd {RDIR} && python3 assemble.py", t=900))

    # Info.plist (universal: both arches in LSArchitecturePriority) + icns.
    r(c, f"cd {RDIR} && sed 's|<string>__ARCH__</string>|<string>arm64</string>\\n        <string>x86_64</string>|' "
         f"Info.plist.in > Qeli.app/Contents/Info.plist")
    r(c, f"cp {RDIR}/Qeli.icns {RDIR}/Qeli.app/Contents/Resources/Qeli.icns")
    r(c, f"chmod +x {RDIR}/Qeli.app/Contents/MacOS/QeliMac")

    # Ad-hoc sign every Mach-O, then the bundle.
    machos = [m for m in r(c, f"cd {RDIR} && for f in $(find Qeli.app/Contents/MacOS -type f); do "
                              f"file -b \"$f\" | grep -q Mach-O && echo \"$f\"; done").splitlines() if m.strip()]
    print(f"[sign] {len(machos)} Mach-O files")
    ok = 0
    for m in machos:
        out = r(c, f"cd {RDIR} && {RCS} sign \"{m}\" 2>&1 | tail -1")
        if "error" in out.lower() or "fail" in out.lower():
            print("   SIGN FAIL", m, out)
        else:
            ok += 1
    print(f"[sign] {ok}/{len(machos)} ad-hoc")
    print("[bundle sign]", r(c, f"cd {RDIR} && {RCS} sign Qeli.app 2>&1 | tail -1"))

    # Zip with Unix perms (executable bits survive).
    zip_py = (
        "import os,zipfile\n"
        f"root=r'{RDIR}'; app='Qeli.app'; out=os.path.join(root,'Qeli-macOS-universal.zip')\n"
        "zf=zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6)\n"
        "for dp,dn,fn in os.walk(os.path.join(root,app)):\n"
        " for n in fn:\n"
        "  full=os.path.join(dp,n); rel=os.path.relpath(full,root)\n"
        "  zi=zipfile.ZipInfo(rel.replace(os.sep,'/')); st=os.stat(full)\n"
        "  zi.external_attr=(st.st_mode & 0xFFFF)<<16; zi.compress_type=zipfile.ZIP_DEFLATED\n"
        "  zf.writestr(zi, open(full,'rb').read())\n"
        "zf.close(); print(os.path.getsize(out))\n"
    )
    r(c, f"cat > {RDIR}/mkzip.py <<'PYZIP'\n{zip_py}PYZIP")
    zsize = r(c, f"cd {RDIR} && python3 mkzip.py")
    print(f"[zip] Qeli-macOS-universal.zip = {zsize} bytes")

    sf = c.open_sftp()
    out_zip = os.path.join(DIST, "Qeli-macOS-universal.zip")
    sf.get(f"{RDIR}/Qeli-macOS-universal.zip", out_zip)
    sf.close()
    c.close()
    print(f"[pull] -> {out_zip} ({os.path.getsize(out_zip)} bytes)")
    print("[done]")


if __name__ == "__main__":
    main()
