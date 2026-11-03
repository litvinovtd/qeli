#!/usr/bin/env python3
"""Infer instrumented Release ABI from pre-R8 classes and resolved classpaths.

Build releaseAndroidTest first, capture :app:printInstrumentationAbiClasspaths,
then run this tool and rebuild. --check detects stale committed rules.
The rules are used only with -PqeliTestBuildType=release.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

HEADER = ('# Generated from pre-R8 AndroidTest/runner references; instrumented Release only.\n'
          '# Regenerate after AndroidTest/dependency changes; see qeli-android/README.md.\n')
# Runner's consumer rules already account for these platform stub omissions. The
# JVM concatenation bootstrap is desugared by D8. No app/dependency omission is accepted.
PLATFORM_ONLY = ('Missing class android.test.AndroidTestCase (',
    'Missing class android.test.InstrumentationTestCase (',
    'Missing method void android.test.AndroidTestCase.setContext(',
    'Missing method void android.test.InstrumentationTestCase.injectInstrumentation(',
    'Missing method android.app.Instrumentation$ActivityResult androidx.test.internal.runner.hidden.ExposedInstrumentationApi.execStartActivity(',
    'Missing class java.lang.invoke.StringConcatFactory ',
    'Missing method java.lang.invoke.CallSite java.lang.invoke.StringConcatFactory.makeConcatWithConstants(')


def classes(path):
    if path.suffix == '.jar':return [path.read_bytes()]
    if path.suffix == '.aar':
        with zipfile.ZipFile(path) as apk:
            return [apk.read(n) for n in apk.namelist() if n == 'classes.jar' or (n.startswith('libs/') and n.endswith('.jar'))]
    raise ValueError(f'Unsupported classpath artifact: {path}')


def merge(destination, artifacts, directories):
    rows = {}
    def add(name, data):
        if name.endswith('.class') and not name.startswith('META-INF/') and name != 'module-info.class':
            if name in rows and rows[name] != data:raise ValueError(f'Conflicting class: {name}')
            rows[name] = data
    for path in artifacts:
        for jar in classes(path):
            with zipfile.ZipFile(io.BytesIO(jar)) as archive:
                for name in archive.namelist():
                    if name.endswith('.class'):add(name, archive.read(name))
    for directory in directories:
        files = list(directory.rglob('*.class'))
        if not files:raise ValueError(f'Compile matching tests before inference: {directory}')
        for path in files:add(path.relative_to(directory).as_posix(), path.read_bytes())
    with zipfile.ZipFile(destination, 'w') as archive:
        for name, data in sorted(rows.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0));info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--classpath-log', type=Path, required=True)
    parser.add_argument('--r8-jar', type=Path, required=True)
    parser.add_argument('--android-jar', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--java', default=str(Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')) if os.environ.get('JAVA_HOME') else shutil.which('java'))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args();root = args.root.resolve();out = args.evidence_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cp = {}
    for line in args.classpath_log.read_text(encoding='utf-8-sig').splitlines():
        if line.startswith('Q29_CP '):
            _, name, values = line.split(' ', 2);cp[name] = [Path(p) for p in json.loads(values)]
    if set(cp) != {'releaseRuntimeClasspath', 'releaseAndroidTestRuntimeClasspath'}:raise ValueError('Both resolved classpaths required')
    main_cp = cp['releaseRuntimeClasspath'];shared = set(main_cp)
    test_cp = [p for p in cp['releaseAndroidTestRuntimeClasspath'] if p not in shared]
    build = root / 'qeli-android/app/build/intermediates'
    target = main_cp + [build / 'runtime_app_classes_jar/release/bundleReleaseClassesToRuntimeJar/classes.jar', build / 'compile_and_runtime_r_class_jar/release/processReleaseResources/R.jar']
    directories = [build / 'built_in_kotlinc/releaseAndroidTest/compileReleaseAndroidTestKotlin/classes', build / 'javac/releaseAndroidTest/compileReleaseAndroidTestJavaWithJavac/classes']
    sizes = dict(target=merge(out / 'target.jar', target, []), source=merge(out / 'source.jar', test_cp, directories))
    command = [args.java, '-cp', str(args.r8_jar.resolve()), 'com.android.tools.r8.tracereferences.TraceReferences', '--keep-rules', '--source', str(out / 'source.jar'), '--target', str(out / 'target.jar'), '--lib', str(args.android_jar.resolve()), '--map-diagnostics:MissingDefinitionsDiagnostic', 'error', 'warning', '--output', str(out / 'shared-abi.pro')]
    proc = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=120)
    (out / 'trace.log').write_text(proc.stdout + proc.stderr, encoding='utf-8')
    (out / 'command.json').write_text(json.dumps(command, indent=2), encoding='utf-8')
    if proc.returncode:raise RuntimeError('TraceReferences failed; see trace.log')
    missing = [s.removeprefix('Warning: ') for s in proc.stderr.splitlines() if s.startswith(('Missing ', 'Warning: Missing '))]
    if any(not s.startswith(PLATFORM_ONLY) for s in missing):raise RuntimeError('Unexpected unresolved ABI: ' + '\n'.join(missing))
    # Keep ABI names, but let R8 widen package-private parents if children move.
    generated = HEADER + (out / 'shared-abi.pro').read_text(encoding='utf-8').replace('-keep ', '-keep,allowaccessmodification ')
    destination = root / 'qeli-android/app/instrumentation-abi.pro'
    if args.check:
        if destination.read_text(encoding='utf-8') != generated:raise RuntimeError('Stale instrumentation-abi.pro; regenerate and rebuild')
    else:destination.write_text(generated, encoding='utf-8')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    proof = dict(status='PASS', class_counts=sizes, known_platform_stub_diagnostics=missing,
                 artifact_sha256={str(p):sha(p) for p in target + test_cp + [args.r8_jar, args.android_jar]},
                 class_sha256={str(p):sha(p) for d in directories for p in sorted(d.rglob('*.class'))},
                 generated_rules_sha256=sha(destination))
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    print('ABI_INFERENCE_PASS', sizes, 'known platform diagnostics', len(missing))


if __name__ == '__main__':main()