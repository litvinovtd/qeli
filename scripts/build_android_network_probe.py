#!/usr/bin/env python3
"""Build a second ordinary-UID lab sender from the existing framework-only receiver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--build-tools', default='36.0.0')
    parser.add_argument('--android-platform', default='android-37.0')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keystore', type=Path, default=Path.home() / '.android/debug.keystore')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'qeli-android/app/src/androidTest/java/com/qeli/SystemNetworkProbeReceiver.java'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tools = args.sdk / 'build-tools' / args.build_tools
    android = args.sdk / 'platforms' / args.android_platform / 'android.jar'
    jdk = Path(os.environ['JAVA_HOME']) / 'bin'
    exe = '.exe' if os.name == 'nt' else ''
    bat = '.bat' if os.name == 'nt' else ''
    commands = []

    def run(argv):
        commands.append([str(v) for v in argv])
        proc = subprocess.run(commands[-1], capture_output=True, text=True, encoding='utf-8', timeout=120)
        (out / 'build.log').open('a', encoding='utf-8').write(proc.stdout + proc.stderr)
        if proc.returncode:raise RuntimeError('Probe build failed; see build.log')

    manifest = out / 'AndroidManifest.xml'
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.qeli.auditprobe">
<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="37" />
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<application android:label="Qeli audit probe" android:allowBackup="false">
<receiver android:name="com.qeli.SystemNetworkProbeReceiver" android:exported="true" />
</application></manifest>''', encoding='utf-8')
    classes = out / 'classes';classes.mkdir()
    dex = out / 'dex';dex.mkdir()
    run([jdk / ('javac' + exe), '--release', '17', '-classpath', android, '-d', classes, source])
    run([tools / ('d8' + bat), '--release', '--min-api', '28', '--lib', android, '--output', dex, *sorted(classes.rglob('*.class'))])
    apk = out / 'audit-probe.apk'
    run([tools / ('aapt2' + exe), 'link', '-I', android, '--manifest', manifest, '-o', apk])
    with zipfile.ZipFile(apk, 'a') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    aligned = out / 'aligned.apk'
    run([tools / ('zipalign' + exe), '-f', '4', apk, aligned])
    apk.unlink();aligned.rename(apk)
    run([tools / ('apksigner' + bat), 'sign', '--ks', args.keystore, '--ks-key-alias', 'androiddebugkey', '--ks-pass', 'pass:android', '--key-pass', 'pass:android', apk])
    run([tools / ('apksigner' + bat), 'verify', '--verbose', apk])
    sha = lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    proof = dict(status='PASS', package='com.qeli.auditprobe', apks={apk.name:sha(apk)},
                 receiver_source_sha256=sha(source), android_jar_sha256=sha(android),
                 purpose='Private lab only; same receiver implementation, independent ordinary UID; no JNI/instrumentation', commands=commands)
    (out / 'manifest.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    print('PROBE_BUILD_PASS', sha(apk))


if __name__ == '__main__':main()