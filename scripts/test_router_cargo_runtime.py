"""Real pinned Cargo on a dependency-free owned Linux probe; no Zig/router build.
Compiler and build-directory configuration live only in fixture CARGO_HOME.
Set QELI_ROUTER_CARGO_RUNTIME=1; optional QELI_CARGO_BASELINE selects old scripts.
"""
import contextlib
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get('QELI_CARGO_BASELINE', str(ROOT/'scripts')))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('qeli_probe_policy', BASE/'router_toolchain.py')
gate = load('qeli_probe_gate', BASE/'keenetic_verify.py')


@unittest.skipUnless(os.name == 'posix' and os.environ.get('QELI_ROUTER_CARGO_RUNTIME') == '1',
                     'requires explicit owned Linux Cargo runtime')
class CargoRuntimeTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, kind='keenetic'):
        # Production validation requires exactly six random router checkout letters.
        if kind == 'host':
            root = Path(subprocess.check_output(['mktemp', '-d',
                '/var/tmp/qeli-keenetic-verify.XXXXXX'], text=True).strip())
        else:
            root = Path(subprocess.check_output(['mktemp', '-d',
                '/var/tmp/qeli-router-'+kind+'-XXXXXX'], text=True).strip())
        try:
            home = root/'fixture-home';home.mkdir(mode=0o700)
            (root/'src').mkdir()
            (root/'Cargo.toml').write_text('[package]\nname="qeli"\nversion="0.8.2"\nedition="2021"\n'
                '[features]\nclient-bin=[]\njemalloc=[]\n'
                '[[bin]]\nname="qeli-client"\npath="src/main.rs"\n')
            (root/'src/lib.rs').write_text('#[test] fn compiler_receipt() { assert_eq!(option_env!("QELI_PROBE_COMPILER"), None); }\n')
            (root/'src/main.rs').write_text('fn main() { println!("{}", '
                'option_env!("QELI_PROBE_COMPILER").unwrap_or("pinned")); }\n')
            (root/'Cargo.lock').write_text('version = 4\n[[package]]\nname = "qeli"\nversion = "0.8.2"\n')
            env = dict(os.environ, CARGO_HOME=str(home), CARGO_TARGET_DIR=str(root/'target'))
            for key in ['QELI_PROBE_COMPILER', 'CARGO_BUILD_BUILD_DIR']:
                env.pop(key, None)
            real = subprocess.check_output(['rustup', 'which', '--toolchain', policy.ROUTER_RUST,
                                           'rustc'], text=True).strip()
            compiler = root/'configured-rustc'
            compiler.write_text('#!/bin/sh\nprintf "called\n" >> '+shlex.quote(str(root/'compiler-calls'))+
                '\nexport QELI_PROBE_COMPILER=redirected\nexec '+shlex.quote(real)+' "$@"\n')
            compiler.chmod(0o700)
            yield root, home, env, compiler
        finally:
            shutil.rmtree(root)

    def host_command(self, root, entry='client_build'):
        # Capture the production gate's client command; only that tiny probe compiles.
        c = Mock();c.client=object();commands={}
        def checked(command, label, **kwargs):
            commands[label]=command
            if label == 'create isolated verification checkout':return str(root)
            if label == 'client dependency graph':return 'qeli v0.8.2\n'
            if label == 'nonempty executable ELF client artifact':return 'Magic: 7f 45 4c 46 02\n'
            return ''
        c.checked.side_effect=checked
        with patch.object(gate, 'sync_router_source'), patch.object(gate, 'require_router_source_ready'), \
             patch.object(gate, 'remote_sha256', return_value='a'*64), contextlib.redirect_stdout(io.StringIO()):
            gate.verify(c)
        return commands[entry]

    def command(self, root, kind):
        if kind == 'host':return self.host_command(root)
        # Exercise the exact compiler environment. Cross/Zig/ABI are out of scope.
        return 'cd '+shlex.quote(str(root))+' && '+policy.router_cargo_prefix(
            str(root), 'x86_64-unknown-linux-musl')+' build --locked --jobs 1 --release --bin qeli-client --offline'

    def build(self, root, env, command):
        result = subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True,
                                text=True, timeout=30)
        binary = root/'target/release/qeli-client'
        output = subprocess.check_output([str(binary)], text=True).strip() if result.returncode == 0 and binary.is_file() else None
        receipt = os.environ.get('QELI_CARGO_RUNTIME_RECEIPTS')
        if receipt:
            with Path(receipt).open('a') as sink:
                sink.write(json.dumps({'root':str(root), 'command':command, 'rc':result.returncode,
                    'stdout':result.stdout, 'stderr':result.stderr, 'binary_output':output,
                    'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None,
                    'configured_compiler_called':(root/'compiler-calls').exists(),
                    'ambient_intermediates_created':(root/'ambient-intermediates').exists()})+'\n')
        self.last_build_result = result
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(binary.is_file())
        return output

    def configured_compiler(self, kinds):
        for kind in kinds:
            with self.subTest(kind=kind), self.fixture(kind) as (root, home, env, compiler):
                (home/'config.toml').write_text('[build]\nrustc='+repr(str(compiler))+'\n')
                self.assertEqual(self.build(root, env, self.command(root, kind)), 'pinned')
                self.assertFalse((root/'compiler-calls').exists())

    def build_directory(self, kinds):
        for kind in kinds:
            for source in ['config', 'environment']:
                with self.subTest(kind=kind, source=source), self.fixture(kind) as (root, home, env, _):
                    outside = root/'ambient-intermediates'
                    if source == 'config':
                        (home/'config.toml').write_text('[build]\nbuild-dir='+repr(str(outside))+'\n')
                    else:env['CARGO_BUILD_BUILD_DIR']=str(outside)
                    self.assertEqual(self.build(root, env, self.command(root, kind)), 'pinned')
                    self.assertFalse(outside.exists(), 'intermediates escaped recipe target directory')
                    self.assertTrue(list((root/'target/release').glob('.fingerprint/*')))

    def test_router_compiler_configuration_cannot_redirect_pinned_rustc(self):
        self.configured_compiler(['keenetic', 'openwrt'])

    def test_router_config_and_environment_cannot_redirect_intermediates(self):
        self.build_directory(['keenetic', 'openwrt'])

    def test_host_gate_compiler_configuration_cannot_redirect_pinned_rustc(self):
        self.configured_compiler(['host'])

    def test_host_gate_config_and_environment_cannot_redirect_intermediates(self):
        self.build_directory(['host'])

    def test_host_test_clippy_and_graph_commands_use_the_same_compiler_policy(self):
        with self.fixture('host') as (root, home, env, compiler):
            (home/'config.toml').write_text('[build]\nrustc='+repr(str(compiler))+'\n')
            for entry in ['unit_tests', 'client_clippy', 'client dependency graph']:
                command=self.host_command(root, entry)
                result=subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True,
                                      text=True, timeout=30)
                receipt=os.environ.get('QELI_CARGO_RUNTIME_RECEIPTS')
                if receipt:
                    with Path(receipt).open('a') as sink:
                        sink.write(json.dumps({'root':str(root), 'entry':entry, 'command':command,
                            'rc':result.returncode,'stdout':result.stdout,'stderr':result.stderr})+'\n')
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertFalse((root/'compiler-calls').exists())
                if entry == 'unit_tests':self.assertIn('1 passed',result.stdout)
                if entry == 'client dependency graph':gate.client_graph_without_ring(result.stdout)

    def test_release_profile_resists_environment_home_and_ancestor_overrides(self):
        profile = ('[profile.release]\nlto="fat"\ncodegen-units=1\nopt-level=3\n'
                   'strip=true\npanic="abort"\n')
        adverse = ('[profile.release]\nlto=false\ncodegen-units=16\nopt-level=0\n'
                   'strip=false\npanic="unwind"\n')
        values = {'LTO':'false', 'CODEGEN_UNITS':'16', 'OPT_LEVEL':'0',
                  'STRIP':'false', 'PANIC':'unwind'}
        for kind in ['keenetic', 'openwrt', 'host']:
            for source in ['environment', 'cargo-home', 'ancestor', 'forced-child-env']:
                with self.subTest(kind=kind, source=source), self.fixture(kind) as (root, home, env, _):
                    manifest = root/'Cargo.toml'
                    manifest.write_text(manifest.read_text()+profile)
                    (root/'build.rs').write_text('fn main() { println!("cargo:rustc-env=QELI_PROFILE_OPT={}", '
                        'std::env::var("OPT_LEVEL").unwrap()); }\n')
                    (root/'src/main.rs').write_text('fn main() { println!("{}|{}", '
                        'if cfg!(panic="abort") { "abort" } else { "unwind" }, '
                        'env!("QELI_PROFILE_OPT")); }\n')
                    command = self.command(root, kind)+' -vv'
                    if source == 'environment':
                        env.update({'CARGO_PROFILE_RELEASE_'+key:value for key,value in values.items()})
                    elif source == 'cargo-home':
                        (home/'config.toml').write_text(adverse)
                    elif source == 'ancestor':
                        # All ancestor configuration stays inside this owned root.
                        crate = root/'nested-crate';crate.mkdir()
                        for name in ['Cargo.toml','Cargo.lock','build.rs','src']:
                            (root/name).rename(crate/name)
                        config = root/'.cargo';config.mkdir()
                        (config/'config.toml').write_text(adverse)
                        command = command.replace('cd '+shlex.quote(str(root))+' && ',
                                                  'cd '+shlex.quote(str(crate))+' && ', 1)
                    else:
                        (home/'config.toml').write_text(''.join(
                            '[env.CARGO_PROFILE_RELEASE_'+key+']\nvalue="'+value+'"\nforce=true\n'
                            for key,value in values.items()))
                    self.assertEqual(self.build(root, env, command), 'abort|3')
                    compiler = next(line for line in self.last_build_result.stderr.splitlines()
                                    if '--crate-name qeli_client' in line)
                    for flag in ['-C opt-level=3', '-C lto=fat', '-C codegen-units=1',
                                 '-C panic=abort', '-C strip=symbols']:
                        self.assertIn(flag, compiler)

    def test_owned_absolute_source_location_is_remapped(self):
        for kind in ['keenetic', 'openwrt', 'host']:
            with self.subTest(kind=kind), self.fixture(kind) as (root, home, env, _):
                (root/'src/location.rs').write_text('file!()\n')
                (root/'src/main.rs').write_text('fn main() { println!("{}", '
                    'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/location.rs"))); }\n')
                self.assertEqual(self.build(root, env, self.command(root, kind)),
                                 '/usr/src/qeli/src/location.rs')

    def test_failed_compiler_resolution_stops_before_cargo_or_build(self):
        for kind in ['keenetic', 'openwrt', 'host']:
            with self.subTest(kind=kind), self.fixture(kind) as (root, home, env, _):
                tools = root/'fixture-bin';tools.mkdir()
                stub = tools/'rustup';stub.write_text('#!/bin/sh\nexit 17\n');stub.chmod(0o700)
                env['PATH']=str(tools)+':'+env['PATH']
                # Host command exports /root/.cargo/bin ahead of PATH; inject exactly
                # this owned verifier PATH in the captured command for the failure case.
                command=self.command(root, kind).replace('export PATH=/root/.cargo/bin:$PATH; ', '')
                result=subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True,
                                      text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root/'target').exists())

    def test_nonexecutable_resolved_compiler_stops_before_cargo(self):
        for kind in ['keenetic', 'openwrt', 'host']:
            with self.subTest(kind=kind), self.fixture(kind) as (root, home, env, _):
                tools = root/'fixture-bin';tools.mkdir()
                invalid=root/'not executable';invalid.write_text('sentinel')
                stub=tools/'rustup';stub.write_text('#!/bin/sh\nprintf "%s\n" '+shlex.quote(str(invalid))+'\n');stub.chmod(0o700)
                env['PATH']=str(tools)+':'+env['PATH']
                command=self.command(root, kind).replace('export PATH=/root/.cargo/bin:$PATH; ', '')
                result=subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True,
                                      text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root/'target').exists())


if __name__ == '__main__':unittest.main()
