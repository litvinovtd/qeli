"""Actual uhttpd HTTP/session bridge to the owned native rpcd fixture.
Run as root inside private mount AND network namespaces with loopback up.
QELI_OPENWRT_ROOTFS_TEMPLATE selects official musl uhttpd/rootfs; rpcd/ucode
use the existing native GNU template. QELI_OPENWRT_LUCI_IPK must be SDK output.
No authentication bypass flag, host service/socket or actual VPN is used.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import unittest
import urllib.error
import urllib.request

import test_openwrt_rpcd as rpcd
import test_openwrt_sdk as sdk

ROOTFS = os.environ.get('QELI_OPENWRT_ROOTFS_TEMPLATE', '')
IPK = os.environ.get('QELI_OPENWRT_LUCI_IPK', '')
ANONYMOUS = '0' * 32


@unittest.skipUnless(ROOTFS and Path(ROOTFS).is_dir() and IPK and Path(IPK).is_file()
                    and rpcd.CHROOT and rpcd.TEMPLATE and Path(rpcd.TEMPLATE).is_dir()
                    and os.name == 'posix' and os.geteuid() == 0,
                    'requires private Linux namespaces, rootfs, native rpcd and built IPK')
class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        for kind in ['mnt', 'net']:
            self.assertNotEqual(os.readlink('/proc/self/ns/' + kind),
                                os.readlink('/proc/1/ns/' + kind),
                                'must run inside private mount/network namespaces')
        self.runtime = rpcd.RpcdIntegrationTests('runTest')
        self.mounted = False
        self.addCleanup(self.cleanup)
        self.runtime.setUp()
        r = self.runtime
        self.http_jail = r.root / 'http-jail'
        shutil.copytree(ROOTFS, self.http_jail, symlinks=True)
        self.mount_target = self.http_jail / 'tmp/run'
        self.mount_target.mkdir(parents=True, exist_ok=True)
        subprocess.run(['mount', '--bind', str(r.jail / 'var/run'), str(self.mount_target)],
                       check=True, capture_output=True, timeout=5)
        self.mounted = True
        _, self.payload = sdk.ipk_contents(IPK)
        for name, (content, _) in self.payload.items():
            target = self.http_jail / name if name.startswith('www/') else r.jail / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        # Reload only the owned rpcd after admitting exact packaged module/ACL bytes.
        r.rpcd.terminate(); r.rpcd.wait(timeout=3)
        r.start_rpcd()
        # LuCI supplies transport-level UCI methods through its mandatory base ACL.
        # Qeli grants only config/object scope; use genuine framework permissions.
        acl = r.jail / 'usr/share/rpcd/acl.d/luci-base.json'
        acl.write_bytes((Path(ROOTFS) / 'usr/share/rpcd/acl.d/luci-base.json').read_bytes())
        r.configure_login()
        login = r.jail / 'etc/config/rpcd'
        config = login.read_text().replace(" list read 'luci-app-qeli'",
            " list read 'luci-app-qeli'\n list read 'luci-base'").replace(
            " list write 'luci-app-qeli'", " list write 'luci-app-qeli'\n list write 'luci-base'")
        login.write_text(config)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(port)
        # Do not use environment proxy settings for this private loopback fixture.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        log = (r.root / 'daemon-http.log').open('wb')
        r.logs.append(log)
        self.http = subprocess.Popen([rpcd.CHROOT, str(self.http_jail), '/usr/sbin/uhttpd',
            '-f', '-p', '127.0.0.1:' + str(port), '-h', '/www', '-u', '/ubus',
            '-U', '/var/run/ubus.sock', '-t', '5', '-T', '5'], stdout=log, stderr=log,
            env={'PATH': '/usr/bin:/usr/sbin:/bin:/sbin', 'LC_ALL': 'C'},
            start_new_session=True)
        r.processes.append(self.http)
        limit = time.monotonic() + 3
        while time.monotonic() < limit:
            self.assertIsNone(self.http.poll(), r.log_text())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.02)
        self.fail('HTTP listener unavailable: ' + r.log_text())

    def cleanup(self):
        r = self.runtime
        if hasattr(r, 'processes'):
            r.stop()
        try:
            if self.mounted:
                subprocess.run(['umount', str(self.mount_target)], check=True,
                               capture_output=True, timeout=5)
                self.mounted = False
        finally:
            r.doCleanups()

    def request(self, packet, path='/ubus'):
        request = urllib.request.Request(self.url + path,
            data=json.dumps(packet, ensure_ascii=False).encode(),
            headers={'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertIn('application/json', response.headers['Content-Type'])
            return json.loads(response.read())

    def call(self, method, args=None, sid=ANONYMOUS, object_name='luci.qeli'):
        return self.request({'jsonrpc': '2.0', 'id': 1, 'method': 'call',
                             'params': [sid, object_name, method, args or {}]})

    def success(self, response):
        self.assertNotIn('error', response, response)
        self.assertEqual(response['result'][0], 0, response)
        return response['result'][1] if len(response['result']) > 1 else None

    def denied(self, response):
        self.assertEqual(response.get('error', {}).get('code'), -32002, response)

    def login(self, user, timeout=5):
        result = self.success(self.call('login', {'username': user,
            'password': 'fixture-password', 'timeout': timeout}, object_name='session'))
        self.assertEqual(len(result['ubus_rpc_session']), 32)
        return result['ubus_rpc_session']

    def test_http_anonymous_invalid_session_and_wrong_password_cannot_mutate(self):
        r = self.runtime
        for sid in [ANONYMOUS, 'f' * 32]:
            for method, args in [('service_status', {}), ('secret_status', {}),
                ('set_secret', {'name': 'pass', 'value': 'denied'}),
                ('clear_secret', {'name': 'pass'}), ('service_action', {'action': 'start'})]:
                with self.subTest(sid=sid, method=method):
                    self.denied(self.call(method, args, sid))
        wrong = self.call('login', {'username': 'writer', 'password': 'wrong'},
                          object_name='session')
        self.assertEqual(wrong['result'][0], 6, wrong)
        self.assertFalse((r.run / 'password').exists())
        self.assertFalse((r.fixture / 'argv').exists())

    def test_http_reader_cannot_access_secrets_service_actions_or_other_uci(self):
        sid = self.login('reader')
        self.assertEqual(self.success(self.call('service_status', sid=sid)), {'enabled': False})
        values = self.success(self.call('get', {'config': 'qeli'}, sid, 'uci'))
        self.assertIn('main', values['values'])
        previous_argv = (self.runtime.fixture / 'argv').read_bytes()
        for method, args in [('secret_status', {}), ('set_secret', {'name': 'pass', 'value': 'x'}),
            ('clear_secret', {'name': 'pass'}), ('service_action', {'action': 'restart'})]:
            self.denied(self.call(method, args, sid))
        for config in ['qeli', 'firewall', 'rpcd']:
            response = self.call('set', {'config': config, 'section': 'main',
                                        'values': {'enabled': '1'}}, sid, 'uci')
            if 'error' in response:
                self.denied(response)
            else:
                self.assertEqual(response['result'][0], 6, response)
        self.assertFalse((self.runtime.run / 'password').exists())
        self.assertEqual((self.runtime.fixture / 'argv').read_bytes(), previous_argv)

    def test_http_writer_literal_secret_status_clear_and_invalid_action(self):
        sid = self.login('writer')
        for action in ['start', 'stop', 'restart', 'enable', 'disable']:
            self.assertEqual(self.success(self.call('service_action', {'action': action}, sid)),
                             {'result': True, 'code': 0})
            self.assertEqual((self.runtime.fixture / 'argv').read_text().splitlines(), [action])
        value = r'  Unicode-Ж😀 "quoted" \ $(touch /fixture/injected) `false`  '
        self.assertEqual(self.success(self.call('set_secret', {'name': 'pass', 'value': value}, sid)),
                         {'result': True})
        self.assertEqual((self.runtime.run / 'password').read_bytes(), value.encode())
        self.assertEqual(self.success(self.call('secret_status', sid=sid)),
                         {'pass': True, 'obfs_key': False})
        for method, args in [('service_action', {'action': 'restart; touch /fixture/injected'}),
            ('set_secret', {'name': 'pass', 'value': 'x\npost_up=bad'}),
            ('clear_secret', {'name': 'other'})]:
            response = self.call(method, args, sid)
            self.assertEqual(response['result'][0], 2, response)
        self.assertEqual((self.runtime.run / 'password').read_bytes(), value.encode())
        self.assertFalse((self.runtime.fixture / 'injected').exists())
        self.assertEqual(self.success(self.call('clear_secret', {'name': 'pass'}, sid)),
                         {'result': True, 'code': 0})
        self.assertFalse((self.runtime.run / 'password').exists())

    def test_http_uci_session_staging_commit_and_embedded_session_rejected(self):
        writer = self.login('writer')
        reader = self.login('reader')
        args = {'config': 'qeli', 'section': 'main', 'values': {'enabled': '1'}}
        self.success(self.call('set', args, writer, 'uci'))
        self.assertFalse(self.success(self.call('service_status', sid=writer))['enabled'])
        self.success(self.call('apply', {'rollback': True, 'timeout': 10}, writer, 'uci'))
        self.success(self.call('confirm', {}, writer, 'uci'))
        self.assertTrue(self.success(self.call('service_status', sid=reader))['enabled'])
        forged = dict(args, ubus_rpc_session=reader)
        response = self.call('set', forged, writer, 'uci')
        self.assertEqual(response.get('error', {}).get('code'), -32602, response)
        self.denied(self.call('set_secret', {'name': 'pass', 'value': 'forged',
                                           'ubus_rpc_session': writer}, reader))
        response = self.call('set', dict(args, config='firewall'), writer, 'uci')
        self.assertEqual(response['result'][0], 6, response)
        self.assertFalse((self.runtime.run / 'password').exists())

    def test_http_revoked_and_expired_sessions_are_denied(self):
        sid = self.login('writer')
        self.success(self.call('service_status', sid=sid))
        # Revoke using the owned local session API; no extra UI/session ACL is fabricated.
        self.runtime.result(self.runtime.call('destroy', {'ubus_rpc_session': sid}, 'session'))
        self.denied(self.call('service_status', sid=sid))
        sid = self.login('writer', timeout=1)
        self.success(self.call('service_status', sid=sid))
        # session.access refreshes idle expiry; polling itself keeps it alive.
        time.sleep(1.3)
        self.denied(self.call('service_status', sid=sid))

    def test_http_serves_actual_packaged_js_and_recovers_after_bad_request(self):
        path = 'www/luci-static/resources/view/qeli/config.js'
        with self.opener.open(self.url + '/' + path.removeprefix('www/'), timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), self.payload[path][0])
        response = self.request({'jsonrpc': '2.0', 'id': 2, 'method': 'call', 'params': []})
        self.assertEqual(response.get('error', {}).get('code'), -32700, response)
        sid = self.login('writer')
        self.assertEqual(self.success(self.call('service_status', sid=sid)), {'enabled': False})


if __name__ == '__main__':
    unittest.main()
