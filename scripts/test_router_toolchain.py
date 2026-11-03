"""Pinned router toolchain failure paths and recipe flag isolation."""
import unittest
from unittest.mock import Mock, patch
import router_toolchain as policy

ROOT = "/var/tmp/qeli-router-keenetic-ABC123"

class Connection:
    def __init__(self, override=None):
        self.commands=[]
        self.override=override or {}
    def checked(self, command, label, timeout=0):
        self.commands.append(command)
        if command in self.override:
            value=self.override[command]
            if isinstance(value,Exception):raise value
            return value() if callable(value) else value
        if command=="zig version":return "0.13.0"
        if command=="rustup toolchain list":return "1.97.0-x86_64-unknown-linux-gnu\nnightly-2026-06-10-x86_64-unknown-linux-gnu"
        if command=="rustc +1.97.0 --version":return "rustc 1.97.0 (fixture)"
        if command=="rustc +nightly-2026-06-10 --version":return "rustc 1.98.0-nightly (fixture)"
        if "target list" in command:return "\n".join(t for t,n in policy.TARGETS.items() if not n)
        if "component list" in command:return "rust-src\nrustc-x86_64-unknown-linux-gnu"
        if command=="cargo +1.97.0 install --list":return "cargo-zigbuild v0.23.0:"
        if command=="cargo-zigbuild --version":return "cargo-zigbuild 0.23.0"
        if " install " in command or " add " in command:return ""
        raise AssertionError(command)

class RouterToolchainTests(unittest.TestCase):
    def invoke(self, connection, targets=("aarch64-unknown-linux-musl",)):
        with patch.object(policy,"LabConnection",return_value=connection):
            return policy.ensure_router_toolchain(Mock(),targets)

    def test_stable_and_all_targets_use_pins_and_nightly_only_for_mips(self):
        for targets in [("aarch64-unknown-linux-musl",),tuple(policy.TARGETS)]:
            c=Connection();identities=self.invoke(c,targets)
            self.assertEqual(identities["zig"],"0.13.0")
            self.assertEqual(any("nightly" in x for x in c.commands),len(targets)>1)
            self.assertFalse(any("+stable" in x or "+nightly " in x for x in c.commands))
            if len(targets)>1:self.assertIn("nightly-2026-06-10",identities)

    def test_invalid_targets_make_no_remote_call(self):
        for targets in [(),("unknown",),("x86_64;bad",)]:
            c=Connection()
            with self.assertRaises(ValueError):self.invoke(c,targets)
            self.assertEqual(c.commands,[])

    def test_wrong_or_failed_zig_stops_before_installation(self):
        for value in ["0.14.0","0.13.0\nunexpected",RuntimeError("failed")]:
            c=Connection({"zig version":value})
            with self.assertRaises(RuntimeError):self.invoke(c)
            self.assertEqual(c.commands,["zig version"])

    def test_exact_inventory_and_missing_pin_installer_failures(self):
        for targets,pin in [(("aarch64-unknown-linux-musl",),policy.ROUTER_RUST),
                            (("mipsel-unknown-linux-musl",),policy.ROUTER_NIGHTLY)]:
            inventory="nightly-x86_64-unknown-linux-gnu\n1.97.00-x86_64-unknown-linux-gnu"
            command=f"rustup toolchain install {pin} --profile minimal"
            c=Connection({"rustup toolchain list":inventory,command:RuntimeError("install failed")})
            with self.assertRaisesRegex(RuntimeError,"install failed"):self.invoke(c,targets)
            self.assertIn(command,c.commands)
        self.assertFalse(policy._toolchain_present("nightly-x86_64-unknown-linux-gnu",policy.ROUTER_NIGHTLY))
        self.assertFalse(policy._toolchain_present("1.97.00-x86_64-unknown-linux-gnu",policy.ROUTER_RUST))

    def test_wrong_or_failed_rust_identity_rejects(self):
        for cmd in ["rustc +1.97.0 --version","rustc +nightly-2026-06-10 --version"]:
            for value in ["rustc 1.96.0 (fixture)",RuntimeError("probe failed")]:
                c=Connection({cmd:value})
                with self.assertRaises(RuntimeError):self.invoke(c,tuple(policy.TARGETS))
                self.assertNotIn("cargo +1.97.0 install --list",c.commands)

    def test_target_add_failure_and_false_success_are_rejected(self):
        query="export PATH=/root/.cargo/bin:$PATH; rustup target list --toolchain 1.97.0 --installed"
        install="export PATH=/root/.cargo/bin:$PATH; rustup target add --toolchain 1.97.0 aarch64-unknown-linux-musl"
        for value in ["",RuntimeError("target add failed")]:
            c=Connection({query:"",install:value})
            with self.assertRaises(RuntimeError):self.invoke(c)
            self.assertIn(install,c.commands)

    def test_nightly_sources_failure_and_false_success_are_rejected(self):
        add="rustup component add rust-src --toolchain nightly-2026-06-10"
        check="rustup component list --toolchain nightly-2026-06-10 --installed"
        for overrides in [{add:RuntimeError("source add failed")},{check:"rustc-x86_64-unknown-linux-gnu"}]:
            c=Connection(overrides)
            with self.assertRaises(RuntimeError):self.invoke(c,("mipsel-unknown-linux-musl",))

    def test_tool_install_failure_and_false_inventory_success_reject(self):
        add="cargo +1.97.0 install cargo-zigbuild --version 0.23.0 --locked --jobs 1 --force"
        for value in ["",RuntimeError("tool install failed")]:
            c=Connection({"cargo +1.97.0 install --list":"cargo-zigbuild v0.22.0:",add:value})
            with self.assertRaises(RuntimeError):self.invoke(c)
            self.assertIn(add,c.commands)

    def test_wrong_executable_version_rejects_even_with_correct_inventory(self):
        c=Connection({"cargo-zigbuild --version":"cargo-zigbuild 0.22.0"})
        with self.assertRaisesRegex(RuntimeError,"executable mismatch"):self.invoke(c)

    def test_release_environment_matches_manifest_and_ci_uses_common_export(self):
        from pathlib import Path
        import subprocess
        import sys
        import tomllib
        root = Path(__file__).resolve().parents[1]
        profile = tomllib.loads((root/'qeli/Cargo.toml').read_text())['profile']['release']
        keys = {'LTO':'lto','CODEGEN_UNITS':'codegen-units','OPT_LEVEL':'opt-level',
                'STRIP':'strip','PANIC':'panic'}
        expected = {'CARGO_PROFILE_RELEASE_'+key:str(profile[field]).lower()
                    for key,field in keys.items()}
        self.assertEqual(policy.router_release_environment(), expected)
        output = subprocess.check_output([sys.executable, str(root/'scripts/router_toolchain.py'),
                                          '--print-release-profile'], text=True)
        self.assertEqual(dict(line.split('=',1) for line in output.splitlines()), expected)
        workflow = (root/'.github/workflows/ci.yml').read_text().split('  keenetic-cross:',1)[1]
        self.assertIn('Canonical standalone router release profile\n        working-directory: .\n        run: python3 scripts/router_toolchain.py --print-release-profile >> "$GITHUB_ENV"', workflow)
        for key,value in expected.items():
            self.assertIn(key+'='+value, policy.router_build_command(ROOT,'x86_64-unknown-linux-musl'))

    def test_build_environment_pins_flags_and_rejects_unsafe_root_target_binary(self):
        for target,nightly in policy.TARGETS.items():
            command=policy.router_build_command(ROOT,target)
            self.assertIn("+nightly-2026-06-10 " if nightly else "+1.97.0 ",command)
            self.assertIn("env -u CARGO_ENCODED_RUSTFLAGS",command)
            self.assertIn("RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER=''",command)
            flags = ("-C link-arg=-msoft-float " if nightly else "") + "--remap-path-prefix="+ROOT+"=/usr/src/qeli"
            self.assertIn("RUSTFLAGS="+__import__("shlex").quote(flags),command)
            self.assertIn("-Z build-std=std,panic_abort " if nightly else "zigbuild --locked",command)
            self.assertIn("--jobs 1",command)
            self.assertIn('rustup which --toolchain '+(policy.ROUTER_NIGHTLY if nightly else policy.ROUTER_RUST)+' rustc',command)
            self.assertIn('test -x "$QELI_ROUTER_RUSTC"',command)
            self.assertIn('RUSTC="$QELI_ROUTER_RUSTC"',command)
            self.assertIn('CARGO_BUILD_BUILD_DIR='+ROOT+'/target',command)
        for root,target,binary in [("/opt/qeli-src",next(iter(policy.TARGETS)),"qeli-client"),(ROOT,"unknown","qeli-client"),(ROOT,next(iter(policy.TARGETS)),"qeli")]:
            with self.assertRaises(ValueError):policy.router_build_command(root,target,binary)

if __name__=="__main__":unittest.main()
