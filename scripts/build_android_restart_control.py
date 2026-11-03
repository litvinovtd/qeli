#!/usr/bin/env python3
"""Build a standalone platform-only audit APK; no product Gradle/JNI inputs are used."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sdk", type=Path, required=True)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--build-tools", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--debug-keystore", type=Path, required=True)
    args = ap.parse_args()
    source = Path(__file__).resolve().parent / "fixtures/android_restart_control"
    output = args.output.resolve()
    output.mkdir(mode=0o700)  # Fresh output only; never delete/reuse another run.
    classes = output / "classes"; classes.mkdir()
    dex = output / "dex"; dex.mkdir()
    android = args.sdk / "platforms" / args.platform / "android.jar"
    tools = args.sdk / "build-tools" / args.build_tools
    assert android.is_file() and args.debug_keystore.is_file()
    javac = shutil.which("javac"); assert javac is not None
    commands = []
    def run(argv):
        commands.append([str(v) for v in argv])
        subprocess.run(commands[-1], check=True)
    run([javac, "--release", "8", "-classpath", android, "-d", classes, *sorted(source.glob("*.java"))])
    run([tools / "aapt2.exe", "link", "-I", android, "--manifest", source / "AndroidManifest.xml",
         "-o", output / "resources.apk"])
    run([tools / "d8.bat", "--lib", android, "--min-api", "28", "--output", dex, *sorted(classes.rglob("*.class"))])
    unsigned = output / "unsigned.apk"
    shutil.copyfile(output / "resources.apk", unsigned)
    with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    apk = output / "restart-control.apk"
    run([tools / "zipalign.exe", "-f", "4", unsigned, apk])
    run([tools / "apksigner.bat", "sign", "--ks", args.debug_keystore, "--ks-key-alias", "androiddebugkey",
         "--ks-pass", "pass:android", "--key-pass", "pass:android", apk])
    run([tools / "apksigner.bat", "verify", "--verbose", apk])
    manifest = dict(apks={apk.name: sha(apk)}, source_inputs={p.name: sha(p) for p in sorted(source.iterdir()) if p.is_file()},
                    builder_sha256=sha(Path(__file__)), android_jar_sha256=sha(android),
                    build_tools=args.build_tools, platform=args.platform, commands=commands)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("CONTROL_APK", manifest["apks"])


if __name__ == "__main__":
    main()
