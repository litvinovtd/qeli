/* Regression tests execute the actual embedded components; no DOM or VPN server is required. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const templates = path.join(__dirname, '..', 'qeli', 'src', 'web', 'templates');
let passed = 0;
function component(file, factory, overrides = {}) {
  const html = fs.readFileSync(path.join(templates, file), 'utf8');
  const events = [];
  const context = {
    console, document: { addEventListener() {} }, window: {},
    qeliT: s => s, qeliTf: s => s, qeliConfirm: async () => true,
    apiFetch: async () => ({ ok: true }), fetch: async () => ({ json: async () => ({ ok: false }) }),
    ...overrides,
  };
  vm.createContext(context);
  for (const match of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]).runInContext(context);
  const model = context[factory]();
  model.$dispatch = (...args) => events.push(args);
  return { model, context, events, html };
}
async function check(name, fn) { await fn(); passed++; console.log('PASS ' + name); }
async function main() {
  await check('configuration exposes Form and INI only', async () => {
    const { model, html } = component('config.html', 'configPage');
    assert(!html.includes("switchView('json')"));
    assert(!('onJsonEdit' in model)); assert(!('jsonText' in model));
    await model.switchView('json'); assert.equal(model.view, 'form');
  });
  await check('failed load is visible and blocks writes', async () => {
    let writes = 0;
    const { model, events } = component('config.html', 'configPage', {
      apiFetch: async (url, opts) => { if (opts) writes++; return { ok: false, error: 'fixture read failed' }; },
    });
    model.loadIdentity = () => {};
    await model.load(); assert.equal(model.loaded, false); assert.match(model.loadError, /fixture read failed/);
    assert(events.length); model.dirty = true;
    await model.save(); await model.saveRaw(); await model.applyRestart(); assert.equal(writes, 0);
  });
  await check('reload restores the pending full restart requirement', async () => {
    const { model } = component('config.html', 'configPage', {
      apiFetch: async () => ({ ok: true, config: { profiles: [] }, revision: 'r1', needs_full_restart: true }),
    });
    model.loadIdentity = () => {};
    await model.load(); assert(model.loaded); assert(model.needsFullRestart); assert.equal(model.loadError, '');
  });
  for (const raw of [false, true]) await check((raw ? 'INI' : 'form') + ' keeps edits made during a save dirty', async () => {
    let start, resolve, sent;
    const started = new Promise(r => { start = r; });
    const { model, context } = component('config.html', 'configPage');
    model.loaded = true; model.dirty = true; model.revision = 'r1';
    model.cfg = { profiles: [], logging: { level: 'debug' } };
    model._original = JSON.stringify({ profiles: [], logging: { level: 'info' } });
    model.rawOriginal = 'old'; model.rawText = 'sent';
    context.apiFetch = async (url, opts) => { sent = JSON.parse(opts.body); start(); return new Promise(r => { resolve = r; }); };
    const saving = raw ? model.saveRaw() : model.save(); await started;
    if (raw) model.rawText = 'later'; else model.cfg.logging.level = 'trace';
    model.dirty = true; resolve({ ok: true, revision: 'r2', needs_full_restart: true }); await saving;
    assert(model.dirty); assert.equal(model.revision, 'r2'); assert(model.needsFullRestart);
    assert.equal(raw ? model.rawOriginal : JSON.parse(model._original).logging.level, raw ? 'sent' : 'debug');
    assert.equal(raw ? sent.raw : sent.config.logging.level, raw ? 'sent' : 'debug');
    context.apiFetch = async () => ({ ok: true, revision: 'r3' });
    await (raw ? model.saveRaw() : model.save()); assert(!model.dirty);
  });
  await check('INI socket changes never fall back to worker restart', async () => {
    let workers = 0;
    const { model, events } = component('config.html', 'configPage', {
      apiFetch: async () => ({ ok: true, revision: 'r2', needs_full_restart: true }),
      fullRestartServer: async () => ({ ok: false, kind: 'no_systemd', container: true, error: 'full restart required' }),
      restartServer: async () => { workers++; return true; },
    });
    model.loaded = true; model.view = 'raw'; model.rawOriginal = 'old'; model.rawText = 'new'; model.dirty = true;
    await model.applyRestart(); assert.equal(workers, 0); assert(events.some(e => e[1].type === 'error'));
  });
  await check('failed INI reload remains explicit', async () => {
    const { model } = component('config.html', 'configPage', { apiFetch: async () => ({ ok: false, error: 'unavailable' }) });
    model.loaded = true; await model.loadRaw(); assert(!model.loaded); assert.equal(model.loadError, 'unavailable');
  });
  const keys = ['gateway', 'quic', 'awg', 'autostart', 'route_local', 'allow_ipv4_leak', 'allow_ipv6_leak'];
  for (const literal of ['on', 'YES', 'True', '1', '"ON"']) await check('client INI accepts true spelling ' + literal, () => {
    const { model } = component('client.html', 'clientPage');
    const f = model.blankForm(); model.parseIni('[ qeli ]\nserver=fixture.invalid:443\n' + keys.map(k => `${k}=${literal}`).join('\n'), f);
    assert.equal(f.server, 'fixture.invalid:443'); for (const key of keys) assert.equal(f[key], true, key);
  });
  for (const literal of ['off', 'NO', 'False', '0']) await check('client INI accepts false spelling ' + literal, () => {
    const { model } = component('client.html', 'clientPage');
    const f = model.blankForm(); model.parseIni('[qeli]\nserver=fixture.invalid:443\n' + keys.map(k => `${k}=${literal}`).join('\n'), f);
    for (const key of keys) assert.equal(f[key], false, key);
  });
  await check('removing raw keys clears former field values', () => {
    const { model } = component('client.html', 'clientPage');
    model.form = model.blankForm(); Object.assign(model.form, { name: 'retained', editing: true, pass: 'old', gateway: true, key: 'old-key', rawMode: true, raw: '[qeli]\nserver=fixture.invalid:443\n' });
    model.toggleRaw(); assert.equal(model.form.pass, ''); assert(!model.form.gateway); assert.equal(model.form.key, '');
    assert.equal(model.form.name, 'retained'); assert(model.form.editing); assert(!model.form.rawMode);
  });
  await check('invalid raw input preserves the draft and stays in INI', () => {
    const { model } = component('client.html', 'clientPage'); model.notify = () => {};
    for (const extra of ['gateway=maybe', 'jc=1oops', 'jc=4294967296', 'jmin=65536', 'server=second.invalid:443', '[qeli]']) {
      model.form = model.blankForm(); model.form.rawMode = true; model.form.raw = '[qeli]\nserver=fixture.invalid:443\n' + extra;
      const raw = model.form.raw; model.toggleRaw(); assert(model.form.rawMode); assert.equal(model.form.raw, raw);
    }
  });
  await check('passwords survive Fields to INI to Fields exactly', () => {
    const { model } = component('client.html', 'clientPage');
    for (const secret of ['plain', '"secret"', ' secret ', '\tsecret\t', '\u00a0secret\u00a0', 'a\\b"c', '#;=']) {
      model.form = model.blankForm(); model.form.server = 'fixture.invalid:443'; model.form.pass = secret;
      const ini = model.formToIni(); const f = model.blankForm(); model.parseIni(ini, f); assert.equal(f.pass, secret);
      assert.equal(model.iniValue(model.iniQuote(secret)), secret);
    }
  });
  await check('repeated route lists and non-form sections are retained', () => {
    const { model } = component('client.html', 'clientPage'); const f = model.blankForm();
    model.parseIni('[qeli]\nserver=x:443\ninclude=10.0.0.0/8\ninclude=192.168.0.0/16\nkill_switch=true\n[logging]\nlevel=debug\n', f);
    model.form = f; const text = model.formToIni(); assert(text.includes('include = 10.0.0.0/8, 192.168.0.0/16')); assert(text.includes('kill_switch=true')); assert(text.includes('[logging]\nlevel=debug'));
  });
  await check('changing quota preserves exact expiry; editing or clearing date remains supported', async () => {
    let sent; const { model } = component('users.html', 'usersPage', { apiFetch: async (u, opts) => { sent = JSON.parse(opts.body); return { ok: true }; } });
    model.loadUsage = () => {};
    const expiry = 1790847000;
    model.openUsage('alice', { expire_at: expiry, data_limit_gb: 10 }, 'limit'); model.usageForm.data_limit_gb = 20;
    await model.saveLimit(); assert.equal(sent.expire_at, expiry); assert.equal(sent.data_limit_gb, 20);
    model.usageForm.expire_date = '2026-10-03'; model.syncFromDate(); await model.saveLimit();
    assert.equal(sent.expire_at, Math.floor(new Date('2026-10-03T23:59:59').getTime() / 1000));
    model.usageForm.expire_date = ''; model.syncFromDate(); await model.saveLimit(); assert.equal(sent.expire_at, null);
  });
  console.log(`Panel editor regressions: ${passed} passed`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
