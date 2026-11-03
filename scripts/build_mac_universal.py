#!/usr/bin/env python3
"""Assemble a signed universal (arm64+x86_64) Qeli.app on the Linux lab (.10),
WITHOUT a Mac.

Inputs (built locally first — Windows/Linux with the .NET 10 SDK):
  qeli-mac/dist/osx-arm64.tar.gz   (dotnet publish -r osx-arm64 --self-contained)
  qeli-mac/dist/osx-x64.tar.gz     (dotnet publish -r osx-x64  --self-contained)

On .10 (has llvm-lipo-19 + rcodesign): merges every per-arch Mach-O into a fat
binary (the already-universal libqeli.dylib is copied as-is), assembles the .app
(Info.plist from Info.plist.in, Qeli.icns), ad-hoc-signs each Mach-O + the bundle
with rcodesign, repacks a Unix-perm zip, and pulls it back to qeli-mac/dist/.
"""
import os, sys
import re
import shlex
import tarfile
from pathlib import PurePosixPath
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from native_lab import connect_lab, pull_verified_artifact, remote_sha256
from native_repro import DEFAULT_RCODESIGN, require_lab_password, sha256_file
from check_macos_deployment import declared_minimum

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "qeli-mac" / "dist"
INFO_PLIST_IN = ROOT / "qeli-mac" / "Info.plist.in"
ICNS = DIST / "Qeli.icns"
CANONICAL_DYLIB = ROOT / "qeli-mac" / "QeliMac" / "native" / "libqeli.dylib"
HOST = ("10.66.116.10", os.environ.get("QELI_LAB_USER", "root"))
LIPO = "/usr/bin/llvm-lipo-19"
RCS = "/usr/local/bin/rcodesign"
DEPLOYMENT_CHECK = Path(__file__).with_name('check_macos_deployment.py')
MACHO_READER = Path(__file__).with_name('macho_repro.py')


def conn():
    return connect_lab(HOST[0], HOST[1], require_lab_password())


def r(c, cmd, t=600):
    return c.checked(cmd, "macOS universal packaging", timeout=t)


# Remote assembly script (runs on .10).
REMOTE_PY = r'''
from pathlib import Path
import shutil
import subprocess

MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
REQUIRED_ARCHES = {"arm64", "x86_64"}

def macho(path):
    with path.open("rb") as stream:
        return stream.read(4) in MACHO_MAGICS

def architectures(lipo, path):
    result = subprocess.run(
        [lipo, "-archs", str(path)], check=True, capture_output=True,
        text=True, timeout=60,
    )
    names = result.stdout.split()
    if not names or len(names) != len(set(names)):
        raise RuntimeError(f"ambiguous architecture inventory: {path}")
    return set(names)

def inventory(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f"expected payload directory: {directory}")
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"symlinked universal input: {path}")
        if path.is_file():
            files[path.relative_to(directory)] = path
        elif not path.is_dir():
            raise RuntimeError(f"unsupported universal input: {path}")
    return files

def assemble(root, lipo="/usr/bin/llvm-lipo-19"):
    root = Path(root)
    arm = inventory(root / "osx-arm64")
    x64 = inventory(root / "osx-x64")
    arm_machos = {rel for rel, path in arm.items() if macho(path)}
    x64_machos = {rel for rel, path in x64.items() if macho(path)}
    for required in ("QeliMac", "libqeli.dylib"):
        if Path(required) not in arm_machos:
            raise RuntimeError(f"missing required Mach-O: {required}")
    if x64_machos - arm_machos:
        raise RuntimeError(f"x64-only Mach-O inputs: {sorted(map(str, x64_machos - arm_machos))}")

    # .NET ReadyToRun DLLs and dependency graphs can be RID-specific even when
    # every Mach-O can be merged. lipo cannot make those managed payloads universal.
    # Validate both inventories before touching a previous working output.
    for rel in sorted(set(arm) | set(x64)):
        if str(rel).lower().endswith((".dll", ".deps.json", ".runtimeconfig.json")):
            if rel not in arm or rel not in x64 or arm[rel].read_bytes() != x64[rel].read_bytes():
                raise RuntimeError(
                    f"architecture-specific .NET payload: {rel}; "
                    "use separate osx-arm64 and osx-x64 app archives"
                )

    # Admit the complete input graph before replacing the old bundle.
    merge = set()
    for rel in sorted(arm_machos):
        arches = architectures(lipo, arm[rel])
        if arches == REQUIRED_ARCHES:
            continue
        if rel == Path("libqeli.dylib"):
            raise RuntimeError("canonical libqeli.dylib must already contain arm64 and x86_64")
        if arches != {"arm64"} or rel not in x64_machos:
            raise RuntimeError(f"missing universal pair: {rel}")
        if architectures(lipo, x64[rel]) != {"x86_64"}:
            raise RuntimeError(f"wrong x64 partner architecture: {rel}")
        merge.add(rel)

    app = root / "Qeli.app"
    if app.is_symlink():
        raise RuntimeError("refusing symlinked app output")
    if app.exists():
        shutil.rmtree(app)
    macos = app / "Contents/MacOS"
    macos.mkdir(parents=True)
    (app / "Contents/Resources").mkdir()
    for rel, path in arm.items():
        output = macos / rel
        output.parent.mkdir(parents=True, exist_ok=True)
        if rel in merge:
            subprocess.run(
                [lipo, "-create", str(path), str(x64[rel]), "-output", str(output)],
                check=True, capture_output=True, text=True, timeout=60,
            )
        else:
            shutil.copy2(path, output)
        if rel in arm_machos and architectures(lipo, output) != REQUIRED_ARCHES:
            raise RuntimeError(f"assembled Mach-O is not universal2: {rel}")
    # Match build_app.sh: versioned license directories are resources, not code bundles.
    # Leaving Legal under MacOS makes strict bundle signing reject dotted directory names.
    legal = macos / "Legal"
    if legal.is_dir():
        shutil.move(str(legal), str(app / "Contents/Resources/Legal"))
    print(f"[assemble] lipo={len(merge)} copy={len(arm)-len(merge)}; all Mach-O arm64+x86_64")
    return {"merged": len(merge), "copied": len(arm)-len(merge)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        raise SystemExit("expected one owned workspace path")
    assemble(sys.argv[1])
'''


REMOTE_SIGN_PY = r'''
import os, subprocess, sys
from check_macos_deployment import check_bundle
RDIR=sys.argv[1]; APP=RDIR+"/Qeli.app"; MACOS=APP+"/Contents/MacOS"
print(f"[deployment] {check_bundle(APP)} Mach-O files satisfy Info.plist minimum")
RCS=sys.argv[2]
MACHO_MAGICS={
    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
def invoke(args, label):
    result=subprocess.run(args,capture_output=True,text=True)
    output=(result.stdout+result.stderr).strip()
    lowered=output.lower()
    if result.returncode or "error:" in lowered or "failed" in lowered:
        raise RuntimeError(f"{label} failed (rc={result.returncode}):\n{output}")
    return output
machos=[]
for dp,dn,fn in os.walk(MACOS):
    dn.sort()
    for name in sorted(fn):
        path=os.path.join(dp,name)
        with open(path,"rb") as stream: magic=stream.read(4)
        if magic in MACHO_MAGICS: machos.append(path)
for path in machos:
    invoke([RCS,"sign",path],f"sign {path}")
    info=invoke([RCS,"print-signature-info",path],f"inspect {path}")
    if "CodeSignatureFlags(ADHOC" not in info:
        raise RuntimeError(f"{path}: ad-hoc signature flag missing:\n{info}")
invoke([RCS,"sign",APP],"sign app bundle")
print(f"[sign] {len(machos)}/{len(machos)} Mach-O ad-hoc; bundle OK")
'''


def inspect_payload(local, arch, native_sha):
    """Reject unsafe members and stale core bytes before any SSH connection."""
    seen = set()
    regular = set()
    with tarfile.open(local, "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if ("\\" in member.name or path.is_absolute() or ".." in path.parts
                    or not path.parts or path.parts[0] != arch
                    or not (member.isdir() or member.isfile()) or path in seen):
                raise RuntimeError(f"unsafe or duplicate macOS payload member: {member.name}")
            seen.add(path)
            if member.isfile():
                regular.add(path)
            if member.isfile() and path == PurePosixPath(arch, "libqeli.dylib"):
                import hashlib
                with archive.extractfile(member) as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != native_sha:
                        raise RuntimeError(f"stale canonical dylib in {local}")
    for required in ("QeliMac", "libqeli.dylib"):
        if PurePosixPath(arch, required) not in regular:
            raise RuntimeError(f"missing {required} in {local}")


def prepare_inputs():
    declared_minimum(INFO_PLIST_IN.read_bytes())
    native_sha = sha256_file(CANONICAL_DYLIB)
    files = []
    for arch in ("osx-arm64", "osx-x64"):
        local = DIST / (arch + ".tar.gz")
        digest = sha256_file(local)
        inspect_payload(local, arch, native_sha)
        if sha256_file(local) != digest:
            raise RuntimeError(f"macOS payload changed during admission: {local}")
        files.append((local, digest))
    for local in (INFO_PLIST_IN, ICNS, DEPLOYMENT_CHECK, MACHO_READER):
        files.append((local, sha256_file(local)))
    return files, native_sha


def build(c, inputs, native_sha, workspace):
    quoted = shlex.quote(workspace)
    sf = c.open_sftp()
    try:
        for local, expected in inputs:
            remote = workspace + "/" + local.name
            sf.put(os.fspath(local), remote)
            if remote_sha256(c, remote) != expected:
                raise RuntimeError(f"macOS input changed after upload: {local.name}")
            print(f"[input] {local.name} sha256={expected}")
    finally:
        sf.close()
    print("[extract]", r(c, f"cd {quoted} && tar -xzf osx-arm64.tar.gz && tar -xzf osx-x64.tar.gz"))
    r(c, f"cat > {quoted}/assemble.py <<'PYEOF'\n{REMOTE_PY}\nPYEOF")
    print(r(c, f"cd {quoted} && python3 assemble.py {quoted}", t=900))
    assembled_dylib = remote_sha256(c, workspace + "/Qeli.app/Contents/MacOS/libqeli.dylib")
    if assembled_dylib != native_sha:
        raise RuntimeError(f"assembled dylib {assembled_dylib}, expected {native_sha}")
    r(c, f"cd {quoted} && sed 's|<string>__ARCH__</string>|<string>arm64</string>\\n        <string>x86_64</string>|' "
         "Info.plist.in > Qeli.app/Contents/Info.plist")
    r(c, f"cp {quoted}/Qeli.icns {quoted}/Qeli.app/Contents/Resources/Qeli.icns")
    r(c, f"chmod +x {quoted}/Qeli.app/Contents/MacOS/QeliMac")
    r(c, f"cat > {quoted}/sign_app.py <<'PYSIGN'\n{REMOTE_SIGN_PY}\nPYSIGN")
    print(r(c, f"cd {quoted} && python3 sign_app.py {quoted} {shlex.quote(RCS)}", t=900))
    zip_py = (
        "import os,zipfile\n"
        f"root={workspace!r}; app='Qeli.app'; out=os.path.join(root,'Qeli-macOS-universal.zip')\n"
        "with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as zf:\n"
        " for dp,dn,fn in os.walk(os.path.join(root,app)):\n"
        "  dn.sort()\n"
        "  for n in sorted(fn):\n"
        "   full=os.path.join(dp,n); rel=os.path.relpath(full,root)\n"
        "   zi=zipfile.ZipInfo(rel.replace(os.sep,'/')); st=os.stat(full)\n"
        "   zi.external_attr=(st.st_mode & 0xFFFF)<<16; zi.compress_type=zipfile.ZIP_DEFLATED\n"
        "   with open(full,'rb') as incoming: zf.writestr(zi,incoming.read())\n"
        "print(os.path.getsize(out))\n"
    )
    r(c, f"cat > {quoted}/mkzip.py <<'PYZIP'\n{zip_py}PYZIP")
    print("[zip]", r(c, f"cd {quoted} && python3 mkzip.py"))
    remote_zip = workspace + "/Qeli-macOS-universal.zip"
    zip_digest = remote_sha256(c, remote_zip)
    sf = c.open_sftp()
    try:
        size, digest, _changes = pull_verified_artifact(
            sf, remote_zip, zip_digest, ROOT, ("qeli-mac/dist/Qeli-macOS-universal.zip",),
        )
    finally:
        sf.close()
    print(f"[pull] -> {DIST / 'Qeli-macOS-universal.zip'} ({size} bytes, sha256={digest})")
    print("[done]")


def main():
    inputs, native_sha = prepare_inputs()
    c = conn()
    try:
        rcodesign = r(c, f"{RCS} --version")
        if rcodesign != DEFAULT_RCODESIGN:
            raise RuntimeError(f"rcodesign is {rcodesign}, expected {DEFAULT_RCODESIGN}")
        print("[rcodesign]", rcodesign)
        print("[lipo]", r(c, f"{LIPO} --version"))
        workspace = r(c, "mktemp -d /var/tmp/qeli-mac-build.XXXXXXXX")
        if not re.fullmatch(r"/var/tmp/qeli-mac-build\.[A-Za-z0-9]{8}", workspace):
            raise RuntimeError(f"unexpected macOS workspace: {workspace!r}")
        print("[workspace]", workspace, "(retained for diagnostics)")
        build(c, inputs, native_sha, workspace)
    finally:
        c.close()


if __name__ == "__main__":
    main()
