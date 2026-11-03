"""SDK Kconfig and actual LuCI IPK checks; optional explicit audit inputs.
QELI_OPENWRT_SDK must be an owned working SDK with pinned feeds registered and
.qeli-audit-sdk containing qeli-sdk-audit-fixture-v1. Kconfig cases change .config.
QELI_OPENWRT_LUCI_IPK selects the SDK output, never an installed router package.
SDK and IPK classes can be run separately; packaged JS executes existing fixtures.
"""
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SDK = os.environ.get('QELI_OPENWRT_SDK', '')
IPK = os.environ.get('QELI_OPENWRT_LUCI_IPK', '')
LUCI = ROOT/'qeli-openwrt/luci-app-qeli'


def members(data):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive.getmembers():
            if member.isdir():continue
            name = member.name.removeprefix('./')
            if not member.isfile() or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
                raise ValueError('unexpected archive member: '+name)
            if name in result or member.size > 32*1024*1024:
                raise ValueError('duplicate/oversized archive member: '+name)
            result[name] = (archive.extractfile(member).read(), member.mode)
    return result


def ipk_contents(path):
    outer = members(Path(path).read_bytes())
    if set(outer) != {'debian-binary', 'control.tar.gz', 'data.tar.gz'} or outer['debian-binary'][0] != b'2.0\n':
        raise ValueError('unexpected OpenWrt IPK layout')
    control = members(outer['control.tar.gz'][0])['control'][0].decode()
    fields = dict(row.split(': ', 1) for row in control.splitlines() if ': ' in row and not row.startswith(' '))
    return fields, members(outer['data.tar.gz'][0])


@unittest.skipUnless(SDK and Path(SDK).is_dir(), 'requires owned prepared OpenWrt SDK')
class SdkTests(unittest.TestCase):
    def setUp(self):
        self.sdk = Path(SDK).resolve()
        self.assertEqual((self.sdk/'.qeli-audit-sdk').read_text().strip(), 'qeli-sdk-audit-fixture-v1')
        for source, target in [(ROOT/'qeli-openwrt/Makefile', self.sdk/'package/qeli/Makefile'),
                               (LUCI/'Makefile', self.sdk/'package/luci-app-qeli/Makefile')]:
            self.assertEqual(source.read_bytes(), target.read_bytes(), 'SDK must use exact test source')
        self.saved_config = (self.sdk/'.config').read_bytes()
        self.saved_build = (self.sdk/'Config-build.in').read_bytes()
        self.addCleanup((self.sdk/'Config-build.in').write_bytes, self.saved_build)
        self.addCleanup((self.sdk/'.config').write_bytes, self.saved_config)
    def command(self, *args):
        result = subprocess.run(args, cwd=self.sdk, capture_output=True, text=True, timeout=75)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotRegex(result.stdout+result.stderr, r'(?i)error:|recursive dependency detected|command not found')
        return result.stdout
    def configure(self, ipv6):
        if not ipv6:
            # This SDK fixes its hidden IPV6 symbol to y. Exercise the n branch
            # in a private Kconfig profile; do not claim a stock IPv4-only SDK.
            build = self.saved_build.decode()
            old = 'config IPV6\n\tbool\n\tdefault y'
            self.assertIn(old, build)
            (self.sdk/'Config-build.in').write_text(build.replace(old, 'config IPV6\n\tbool\n\tdefault n', 1))
        config = '# CONFIG_ALL is not set\n# CONFIG_ALL_KMODS is not set\n# CONFIG_ALL_NONSHARED is not set\n'
        config += 'CONFIG_PACKAGE_qeli=m\nCONFIG_PACKAGE_luci-app-qeli=m\n'
        config += 'CONFIG_IPV6=y\n' if ipv6 else '# CONFIG_IPV6 is not set\n'
        (self.sdk/'.config').write_text(config)
        self.command('make', 'defconfig', 'V=s', '-j1')
        # The SDK top-level make may hide Kconfig failure behind exit0.
        self.command('./scripts/config/conf', '--defconfig=.config', 'Config.in')
        actual = (self.sdk/'.config').read_text()
        self.assertIn('CONFIG_PACKAGE_qeli=m', actual)
        self.assertIn('CONFIG_PACKAGE_luci-app-qeli=m', actual)
        self.assertEqual('CONFIG_IPV6=y' in actual, ipv6)
    def test_private_ipv4_only_kconfig_profile(self):self.configure(False)
    def test_ipv6_configuration(self):self.configure(True)
    def test_actual_package_metadata_keeps_virtual_backend_and_conditional_ipv6(self):
        output = self.command('make', '-C', 'package/qeli', 'TOPDIR='+str(self.sdk), 'DUMP=1')
        self.assertIn('Build-Depends: rust/host', output)
        self.assertRegex(output, r'Depends: .*\+iptables \+IPV6:ip6tables')
        self.assertRegex(output, r'Source: qeli-0\.8\.2\.tar\.(?:zst|xz)')


@unittest.skipUnless(IPK and Path(IPK).is_file(), 'requires actual SDK LuCI IPK')
class IpkTests(unittest.TestCase):
    def setUp(self):self.control, self.payload = ipk_contents(IPK)
    def test_control_version_architecture_owner_dependencies(self):
        self.assertEqual(self.control['Package'], 'luci-app-qeli')
        recipe = (LUCI/'Makefile').read_text()
        version = re.search(r'^PKG_VERSION:=(.+)$', recipe, re.M)[1]
        release = re.search(r'^PKG_RELEASE:=(.+)$', recipe, re.M)[1]
        self.assertEqual(self.control['Version'], version+'-r'+release)
        self.assertEqual(self.control['Architecture'], 'all')
        self.assertEqual(self.control['License'], 'AGPL-3.0-only')
        self.assertEqual(self.control['Maintainer'], 'Alexandr')
        self.assertEqual(self.control['URL'], 'https://github.com/litvinovtd/qeli')
        deps = {item.strip().split()[0] for item in self.control['Depends'].split(',')}
        self.assertEqual(deps, {'libc', 'luci-base', 'qeli', 'rpcd-mod-ucode', 'ucode-mod-fs'})
    def test_payload_exact_paths_modes_and_production_rpc_acl_menu_bytes(self):
        expected = {}
        for prefix, install in [('root', ''), ('htdocs', 'www/')]:
            for source in (LUCI/prefix).rglob('*'):
                if source.is_file():expected[install+source.relative_to(LUCI/prefix).as_posix()] = source
        self.assertEqual(set(self.payload), set(expected))
        for name, source in expected.items():
            content, mode = self.payload[name]
            self.assertEqual(mode, 0o644, name)
            if not name.endswith('.js'):self.assertEqual(content, source.read_bytes(), name)
            else:self.assertLess(len(content), len(source.read_bytes()), 'actual jsmin must run')
    @unittest.skipUnless(shutil.which('node'), 'requires Node for existing packaged-JS fixtures')
    def test_minified_js_with_existing_control_and_secret_fixtures(self):
        with tempfile.TemporaryDirectory(prefix='qeli-ipk-js-') as temporary:
            root = Path(temporary)
            for name, (content, _) in self.payload.items():
                relative = 'htdocs/'+name.removeprefix('www/') if name.startswith('www/') else 'root/'+name
                target = root/'qeli-openwrt/luci-app-qeli'/relative
                target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(content)
            target = root/'scripts/test_openwrt_luci.js'
            target.parent.mkdir();target.write_bytes((ROOT/'scripts/test_openwrt_luci.js').read_bytes())
            result = subprocess.run(['node', str(target)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('LuCI fixture tests: 14 PASS', result.stdout)

if __name__ == '__main__':unittest.main()
