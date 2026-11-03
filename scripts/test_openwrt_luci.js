// Execute the actual LuCI module with deterministic RPC/UCI fixtures, no browser/router.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../qeli-openwrt/luci-app-qeli/htdocs/luci-static/resources/view/qeli/config.js'), 'utf8');
function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}
function fixture(options = {}) {
    const events = [];
    let staged = '0', committed = '0';
    const context = vm.createContext({
        view: { extend: v => v }, form: {}, poll: {},
        ui: { addNotification() {} }, E: () => ({}), _: v => v,
        rpc: { declare: spec => async (action, value) => {
            if (spec.method === 'service_status') {
                if (options.statusFailure) throw new Error('status unavailable');
                return { enabled: options.backendEnabled };
            }
            if (spec.method === 'set_secret') { events.push(['secret', action, value]); return !options.failSecret; }
            if (spec.method !== 'service_action') return {};
            events.push(`${action}:${committed}`);
            if (options.failService === action) return false;
            return true;
        } },
        uci: {
            set(a, b, c, value) { staged = value; events.push(`set:${value}`); },
            async save() { events.push('save'); if (options.save) await options.save.promise; },
            async apply() {
                events.push('apply');
                if (options.apply) await options.apply.promise;
                committed = staged;
                events.push(`commit:${committed}`);
                return 0;
            }
        }
    });
    vm.runInContext("String.prototype.format = function(v) { return this.replace('%s',v); };", context);
    vm.runInContext('(function(){' + source.replace('return view.extend({', 'globalThis.audit = { controlService, getEnabled, statusText, setSecret }; return view.extend({') + '\n})()', context);
    return { control: context.audit.controlService, status: context.audit.getEnabled, text: context.audit.statusText, secret: context.audit.setSecret, events };
}
async function flush() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
(async () => {
    let passed = 0;
    async function test(name, run) { await run(); console.log(`PASS ${name}`); passed++; }
    await test('connect waits for confirmed UCI before enable/start', async () => {
        const apply = deferred(), f = fixture({ apply });
        const request = f.control('connect'); await flush();
        assert.deepEqual(f.events, ['set:1', 'save', 'apply']);
        apply.resolve(); await request;
        assert.deepEqual(f.events, ['set:1', 'save', 'apply', 'commit:1', 'enable:1', 'start:1']);
    });
    await test('disconnect commits disabled intent before stop/disable', async () => {
        const f = fixture(); await f.control('disconnect');
        assert.deepEqual(f.events, ['set:0', 'save', 'apply', 'commit:0', 'stop:0', 'disable:0']);
    });
    await test('failed apply issues no service commands and queue recovers', async () => {
        const apply = deferred(), f = fixture({ apply });
        const request = f.control('connect');
        const rejected = assert.rejects(request, /apply failure/);
        await flush(); apply.reject(new Error('apply failure')); await rejected;
        assert.deepEqual(f.events, ['set:1', 'save', 'apply']);
        await f.control('restart'); assert.equal(f.events.at(-1), 'restart:0');
    });
    await test('failed save issues no apply or service commands', async () => {
        const save = deferred(), f = fixture({ save });
        const rejected = assert.rejects(f.control('connect'), /save failure/);
        await flush(); save.reject(new Error('save failure')); await rejected;
        assert.deepEqual(f.events, ['set:1', 'save']);
    });
    await test('concurrent connect/disconnect/restart preserve whole-operation order', async () => {
        const apply = deferred(), f = fixture({ apply });
        const requests = [f.control('connect'), f.control('disconnect'), f.control('restart')];
        await flush(); assert.deepEqual(f.events, ['set:1', 'save', 'apply']);
        apply.resolve(); await Promise.all(requests);
        assert.deepEqual(f.events, ['set:1', 'save', 'apply', 'commit:1', 'enable:1', 'start:1',
            'set:0', 'save', 'apply', 'commit:0', 'stop:0', 'disable:0', 'restart:0']);
    });
    await test('failed enable stops connect chain and later disconnect works', async () => {
        const f = fixture({ failService: 'enable' });
        await assert.rejects(f.control('connect'), /enable failed/);
        assert.ok(!f.events.includes('start:1'));
        await f.control('disconnect'); assert.equal(f.events.at(-1), 'disable:0');
    });
    await test('unknown action cannot mutate UCI or issue service commands', async () => {
        const f = fixture(); await assert.rejects(f.control('invalid'), /Unknown/);
        assert.deepEqual(f.events, []);
    });
    await test('fresh status does not load/unload the form cache', async () => {
        const options = { backendEnabled: false }, f = fixture(options);
        assert.equal(await f.status(), false);
        options.backendEnabled = true;
        assert.equal(await f.status(), true);
        assert.deepEqual(f.events, []);
    });
    await test('status failure or invalid response is unknown, not disabled', async () => {
        assert.equal(await fixture({ statusFailure: true }).status(), null);
        assert.equal(await fixture({ backendEnabled: '1' }).status(), null);
        assert.match(fixture().text(false, null), /unavailable/);
    });
    await test('status adapter maps only actual 0/1 exit codes and ACL stays scoped', async () => {
        // Parse the compatible adapter in JS with system/fs mocks, not an ucode interpreter.
        const rpcSource = fs.readFileSync(path.join(__dirname, '../qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/ucode/qeli.uc'), 'utf8');
        for (const [code, expected] of [[0, true], [1, false], [2, null], [127, null], [null, null]]) {
            const calls = [];
            const context = vm.createContext({ system: command => { calls.push(command); return code; } });
            const methods = vm.runInContext('(function(){' + rpcSource.replace(/^#![^\n]*\n/, '').replace("import * as fs from 'fs';", 'const fs = {};') + '\n})()', context);
            assert.equal(methods['luci.qeli'].service_status.call().enabled, expected);
            assert.deepEqual(calls, ['/etc/init.d/qeli status_enabled >/dev/null 2>&1']);
        }
        const acl = JSON.parse(fs.readFileSync(path.join(__dirname, '../qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/acl.d/luci-app-qeli.json'), 'utf8'))['luci-app-qeli'];
        assert.deepEqual(acl.read.ubus['luci.qeli'], ['service_status']);
        assert.ok(!acl.read.ubus['luci.qeli'].includes('service_action'));
        assert.deepEqual(acl.write.uci, ['qeli']);
    });
    await test('secret clear delegates to init and reports failure without direct unlink', async () => {
        const rpcSource = fs.readFileSync(path.join(__dirname, '../qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/ucode/qeli.uc'), 'utf8');
        for (const code of [0, 1, 17, 127, null]) {
            const calls = [];
            const context = vm.createContext({ system: command => { calls.push(command); return code; },
                exit: value => { throw new Error(`invalid:${value}`); }, UBUS_STATUS_INVALID_ARGUMENT: 2 });
            const methods = vm.runInContext('(function(){' + rpcSource.replace(/^#![^\n]*\n/, '').replace("import * as fs from 'fs';", 'const fs = { unlink() { throw new Error("direct unlink forbidden"); } };') + '\n})()', context);
            for (const name of ['pass', 'obfs_key']) {
                const result = methods['luci.qeli'].clear_secret.call({ args: { name } });
                assert.equal(result.result, code === 0); assert.equal(result.code, code);
                assert.equal(calls.at(-1), `/etc/init.d/qeli clear_secrets ${name} >/dev/null 2>&1`);
            }
            const admitted = calls.length;
            for (const name of ['all', '', 'pass;touch /tmp/bad', '../password'])
                assert.throws(() => methods['luci.qeli'].clear_secret.call({ args: { name } }), /invalid:2/);
            assert.equal(calls.length, admitted);
        }
    });
    await test('secret controls and invalid types are rejected before RPC', async () => {
        const f = fixture();
        for (const name of ['pass', 'obfs_key']) {
            for (const code of [...Array(32).keys(), 127])
                await assert.rejects(f.secret(name, 'left' + String.fromCharCode(code) + 'right'), /control/i);
            for (const value of [false, 0, 1, [], {}])
                await assert.rejects(f.secret(name, value), /text/i);
        }
        assert.deepEqual(f.events, []);
    });
    await test('secret UTF-8 byte limits and malformed Unicode reject before RPC', async () => {
        const f = fixture();
        for (const value of ['a'.repeat(4097), 'é'.repeat(2049), '😀'.repeat(1025)])
            await assert.rejects(f.secret('pass', value), /4096/);
        for (const value of ['\ud800', '\udc00'])
            await assert.rejects(f.secret('pass', value), /Unicode/);
        assert.deepEqual(f.events, []);
        for (const value of ['a'.repeat(4096), 'é'.repeat(2048), '😀'.repeat(1024), '  "quoted" \\ $ ; `  ']) {
            await f.secret('pass', value);
            assert.deepEqual(f.events.at(-1), ['secret', 'pass', value]);
        }
    });
    await test('blank secrets keep the current value and storage errors propagate', async () => {
        const f = fixture();
        for (const value of ['', null, undefined]) await f.secret('pass', value);
        assert.deepEqual(f.events, []);
        const failed = fixture({ failSecret: true });
        await assert.rejects(failed.secret('obfs_key', 'fixture'), /Failed to store/);
        assert.deepEqual(failed.events, [['secret', 'obfs_key', 'fixture']]);
    });
    console.log(`LuCI fixture tests: ${passed} PASS (not rpcd/procd device qualification)`);
})().catch(error => { console.error(error); process.exitCode = 1; });
