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
    clearInterval() {}, clearTimeout() {}, setTimeout() { return 0; },
    console, document: { readyState: 'loading', hidden: false, addEventListener() {}, removeEventListener() {}, getElementById() { return null; } }, window: {},
    qeliT: s => s, qeliTf: s => s, qeliConfirm: async () => true,
    apiFetch: async () => ({ ok: true }), fetch: async () => ({ json: async () => ({ ok: false }) }),
    ...overrides,
  };
  vm.createContext(context);
  if (file !== 'layout.html') {
    const layout = fs.readFileSync(path.join(templates, 'layout.html'), 'utf8');
    const helpers = [...layout.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].find(m => m[1].includes('function qeliPoll'))[1];
    new vm.Script(helpers).runInContext(context);
    context.apiFetch = overrides.apiFetch || (async () => ({ok:true}));
  }
  for (const match of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]).runInContext(context);
  if (file === 'layout.html') context.apiFetch = overrides.apiFetch || (async () => ({ok:true}));
  if (file === 'quickstart.html') context.window.location ||= {hostname:'fixture'};
  const model = context[factory]();
  model.$dispatch = (...args) => events.push(args);
  return { model, context, events, html };
}
async function check(name, fn) { await fn(); passed++; console.log('PASS ' + name); }
async function main() {
  await check('Recordizer mode defaults to timed and preserves opportunistic plus rollback delays', async () => {
    const {model,html}=component('config.html','configPage');
    const cfg={profiles:[{obfuscation:{recordizer:{policy:'required',batch:{mode:'opportunistic',delay_min_ms:3,delay_max_ms:11}}}},{}]};
    model.normalizeProfiles(cfg);
    const batch=cfg.profiles[0].obfuscation.recordizer.batch;
    assert.equal(batch.mode,'opportunistic');
    assert.equal(batch.delay_min_ms,3);
    assert.equal(batch.delay_max_ms,11);
    assert.equal(cfg.profiles[1].obfuscation.recordizer.batch.mode,'timed');
    batch.mode='timed';
    model.normalizeProfiles(cfg);
    assert.equal(batch.delay_min_ms,3);
    assert.equal(batch.delay_max_ms,11);
    assert(html.includes('x-model="cfg.profiles[activeTab].obfuscation.recordizer.batch.mode"'));
    assert.equal((html.match(/:disabled="cfg\.profiles\[activeTab\]\.obfuscation\.recordizer\.batch\.mode === 'opportunistic'"/g)||[]).length,2);
  });
  await check('TCP zero autotuning and manual buffers remain editable without normalization changes', async () => {
    const {model,html}=component('config.html','configPage');
    for (const field of ['send','recv']) {
      assert(html.includes(`min="0" x-model.number="cfg.profiles[activeTab].performance.tcp.${field}_buffer_size"`));
    }
    const cfg={profiles:[{performance:{tcp:{send_buffer_size:0,recv_buffer_size:262144}}}]};
    model.normalizeProfiles(cfg);
    assert.equal(cfg.profiles[0].performance.tcp.send_buffer_size,0);
    assert.equal(cfg.profiles[0].performance.tcp.recv_buffer_size,262144);
  });
  await check('background polls back off, reset after success, skip hidden tabs and stop after an in-flight read', async () => {
    const timers = new Map(); let id = 0, calls = 0, outcome = false, finish;
    const {context} = component('layout.html', 'app', {
      setTimeout(fn, delay) { timers.set(++id, {fn, delay}); return id; },
      clearTimeout(key) { timers.delete(key); },
    });
    const poll = context.qeliPoll(async () => { calls++; return outcome; }, 2000);
    async function tick(delay) {
      assert.equal(timers.size, 1);
      const [key, timer] = timers.entries().next().value;
      assert.equal(timer.delay, delay); timers.delete(key); await timer.fn();
    }
    for (const delay of [2000, 4000, 8000, 16000, 32000, 60000, 60000]) await tick(delay);
    outcome = true; await tick(60000); assert.equal([...timers.values()][0].delay, 2000);
    const count = calls; context.document.hidden = true; await tick(2000); assert.equal(calls, count);
    context.document.hidden = false; poll.stop(); assert.equal(timers.size, 0);
    const pending = context.qeliPoll(() => new Promise(resolve => { finish = resolve; }), 5000);
    const [key, timer] = timers.entries().next().value; timers.delete(key);
    const running = timer.fn(); assert.equal(timers.size, 0); pending.stop(); finish(false); await running;
    assert.equal(timers.size, 0);
  });
  await check('GET timeout covers the response body and leaves writes and caller cancellation untouched', async () => {
    const timers = new Map(); let id = 0, request, bodyStarted = false;
    const {context} = component('layout.html', 'app', {
      AbortController,
      setTimeout(fn, delay) { timers.set(++id, {fn, delay}); return id; },
      clearTimeout(key) { timers.delete(key); },
    });
    // component() supplies a fake API; run the real head helper for this check.
    const html = fs.readFileSync(path.join(templates, 'layout.html'), 'utf8');
    new vm.Script([...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].find(m => m[1].includes('async function apiFetch'))[1]).runInContext(context);
    context.fetch = async (_url, options) => {
      request = options;
      return {text: () => new Promise((_resolve, reject) => {
        bodyStarted = true;
        options.signal.addEventListener('abort', () => reject(new Error('timeout')));
      })};
    };
    const read = context.apiFetch('api/status');
    for (let n=0; n<10 && !bodyStarted; n++) await Promise.resolve();
    assert(bodyStarted);
    assert.equal([...timers.values()][0].delay, 15000); [...timers.values()][0].fn();
    assert.equal((await read).ok, false); assert.equal(timers.size, 0); assert(request.signal.aborted);
    context.fetch = async (_url, options) => { request = options; return {ok:true, text:async () => '{"ok":true}'}; };
    await context.apiFetch('api/users', {method:'POST'}); assert.equal(request.signal, undefined); assert.equal(timers.size, 0);
    const signal = new AbortController().signal; await context.apiFetch('api/status', {signal}); assert.equal(request.signal, signal); assert.equal(timers.size, 0);
  });
  await check('disabled profiles are labelled, remain exportable and are not preferred for new shares', async () => {
    const {model, html} = component('users.html', 'usersPage', {apiFetch:async () => ({ok:true, config:{profiles:[
      {name:'disabled',enabled:false,bind:{port:443}}, {name:'active',enabled:true,bind:{port:8443}}
    ]}}), window:{location:{hostname:'fixture.invalid'}}});
    await model.loadProfiles(); model.openShare({username:'alice'});
    assert.equal(model.share.profile, 'active'); assert.equal(model.shareProfileDisabled, false);
    model.share.profile = 'disabled'; assert.equal(model.shareProfileDisabled, true);
    assert.match(model.profileLabel(model.profiles[0]), /Disabled/); assert.equal(model.profiles.length, 2);
    assert(html.includes('x-show="shareProfileDisabled"'));
    assert(html.includes('x-show="p.enabled === false"'));
  });
  await check('structured log levels do not come from words inside the JSON message', () => {
    const {model} = component('logs.html','logsPage');
    assert.equal(model.parseLevel('{"level":"INFO","message":"ERROR happened before"}'), 'INFO');
    assert.equal(model.parseLevel('{"message":"WARN"}'), '');
    assert.equal(model.parseLevel('{broken ERROR text'), '');
  });
  await check('every polling page reports failed reads to the shared backoff and still permits manual refresh', async () => {
    for (const [file, factory, read] of [
      ['layout.html','app','fetchStatus'], ['dashboard.html','dashboard','load'],
      ['users.html','usersPage','load'], ['client.html','clientPage','refresh'],
      ['logs.html','logsPage','load'], ['blocked.html','blockedPage','load'],
      ['transport.html','transportHealthPage','refresh'],
    ]) {
      const timers = new Map(); let next = 0, calls = 0;
      const {model} = component(file, factory, {
        URLSearchParams,
        setTimeout(fn, delay) { timers.set(++next,{fn,delay}); return next; },
        clearTimeout(id) { timers.delete(id); }, setInterval() { return null; },
        apiFetch:async () => { calls++; return {ok:false,error:'offline'}; },
      });
      model.scrollBottom = () => {};
      if (factory === 'logsPage') { await model.load(); model.autoRefresh = true; model.handleAutoRefresh(); }
      else await model.init();
      for (let n=0; n<30; n++) await Promise.resolve();
      const first = [...timers.entries()]; assert(first.length > 0, factory);
      for (const [id, timer] of first) { timers.delete(id); await timer.fn(); }
      assert.deepEqual([...timers.values()].map(t => t.delay).sort(), first.map(([,t]) => t.delay*2).sort(), factory);
      const before = calls; await model[read](); assert(calls > before, factory);
      model.destroy(); assert.equal(timers.size, 0, factory);
    }
  });
  await check('user bandwidth displays the effective group cap and ignores legacy burst', async () => {
    const {model, html} = component('users.html', 'usersPage');
    model.groups = [{name:'limited', bandwidth_limit_mbps:3}];
    assert.equal(model.effectiveBandwidth({group:'limited', bandwidth:{limit_mbps:0,burst_mbps:50}}),3);
    assert.equal(model.effectiveBandwidth({group:'limited', bandwidth:{limit_mbps:1,burst_mbps:50}}),1);
    assert.equal(model.effectiveBandwidth({bandwidth:{limit_mbps:0,burst_mbps:50}}),0);
    assert.equal(model.effectiveBandwidth({group:'removed'}),0);
    assert(html.includes(':value="form.bandwidth_burst" disabled'));
    assert(!html.includes('x-model.number="form.bandwidth_burst"'));
  });
  await check('editing a user preserves stored legacy burst in the API request', async () => {
    let sent;
    const {model} = component('users.html','usersPage', {apiFetch: async (url,options) => {sent=JSON.parse(options.body);return {ok:true};}});
    model.openEdit({username:'legacy',bandwidth:{limit_mbps:0,burst_mbps:99}});
    model.form.bandwidth_limit=2;model.load=async () => {};
    await model.save();assert.deepEqual(sent.bandwidth,{limit_mbps:2,burst_mbps:99});
  });
  await check('configuration exposes Form and INI only', async () => {
    const { model, html } = component('config.html', 'configPage');
    assert(!html.includes("switchView('json')"));
    assert(!('onJsonEdit' in model)); assert(!('jsonText' in model));
    await model.switchView('json'); assert.equal(model.view, 'form');
  });
  await check('manual IPv6 preserves NDP across route switches and saves the chosen mode', async () => {
    let sent;
    const { model, html } = component('config.html', 'configPage', {
      apiFetch: async (url, opts) => { sent = JSON.parse(opts.body); return { ok: true, revision: 'r2' }; },
    });
    assert(html.includes('<option value="manual">manual</option>'));
    const routing = { mode: 'route', ndp_proxy: 'required', ndp_proxy_interface: 'ens3' };
    model.cfg = { profiles: [{ tun: { ip_mode: 'dual' }, routing: { ipv6: routing } }] };
    model.loaded = true; model.revision = 'r1';
    model._original = JSON.stringify(model.cfg);
    routing.mode = 'manual'; model.onIpv6RoutingModeChange(0);
    assert.equal(routing.ndp_proxy, 'required'); assert.equal(routing.ndp_proxy_interface, 'ens3');
    await model.save(); assert.equal(sent.config.profiles[0].routing.ipv6.mode, 'manual');
    assert.equal(sent.config.profiles[0].routing.ipv6.ndp_proxy, 'required');
    routing.mode = 'route'; model.onIpv6RoutingModeChange(0); assert.equal(routing.ndp_proxy, 'required');
    for (const mode of ['off', 'nat66']) {
      routing.mode = mode; routing.ndp_proxy = 'required'; routing.ndp_proxy_interface = 'ens3';
      model.onIpv6RoutingModeChange(0);
      assert.equal(routing.ndp_proxy, 'off'); assert.equal(routing.ndp_proxy_interface, '');
    }
    routing.mode = 'manual'; routing.ndp_proxy = 'required';
    model.cfg.profiles[0].tun.ip_mode = 'ipv4'; model.onIpModeChange(0);
    assert.equal(routing.mode, 'off'); assert.equal(routing.ndp_proxy, 'off');
  });
  await check('failed load is visible and blocks writes', async () => {
    let writes = 0;
    const { model, events } = component('config.html', 'configPage', {
      apiFetch: async (url, opts) => { if (opts?.method) writes++; return { ok: false, error: 'fixture read failed' }; },
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
    model.loaded = true; model.dirty = true; model.revision = 'r1'; model.view = raw ? 'raw' : 'form';
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
    model.loaded = true; model.revision = 'r1'; model.view = 'raw'; model.rawOriginal = 'old'; model.rawText = 'new'; model.dirty = true;
    await model.applyRestart(); assert.equal(workers, 0); assert(events.some(e => e[1].type === 'error'));
  });
  await check('failed INI reload remains explicit', async () => {
    const { model } = component('config.html', 'configPage', { apiFetch: async () => ({ ok: false, error: 'unavailable' }) });
    model.loaded = true; await model.loadRaw(); assert(!model.loaded); assert.match(model.loadError, /unavailable/);
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
    model.openUsage('alice', { expire_at: expiry, data_limit_gb: 20 }, 'limit');
    model.usageForm.expire_date = '2026-10-03'; model.syncFromDate(); await model.saveLimit();
    assert.equal(sent.expire_at, Math.floor(new Date('2026-10-03T23:59:59').getTime() / 1000));
    model.openUsage('alice', { expire_at: expiry, data_limit_gb: 20 }, 'limit');
    model.usageForm.expire_date = ''; model.syncFromDate(); await model.saveLimit(); assert.equal(sent.expire_at, null);
  });
  await check('shared Rust INI corpus survives the client editor exactly', () => {
    const cases = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'conformance', 'panel-client-ini.json'), 'utf8'));
    const { model } = component('client.html', 'clientPage');
    for (const test of cases) {
      const form = model.blankForm(); model.parseIni(test.raw, form);
      assert.equal(form.pass, test.password);
      model.form = form;
      const line = text => text.split('\n').find(row => row.startsWith('pass = '));
      assert.equal(line(model.formToIni()), line(test.raw));
    }
  });
  await check('notifications cannot save or send a test until initial load succeeds', async () => {
    let finish, writes = 0;
    const { model } = component('notifications.html', 'notificationsPage', {
      apiFetch: async (url, opts) => {
        if (opts?.method) { writes++; return { ok: true, revision: 'r2', config: { telegram_token_set: true } }; }
        return new Promise(resolve => { finish = resolve; });
      },
    });
    const loading = model.init();
    await model.save(); await model.testChan('telegram'); assert.equal(writes, 0);
    assert(!model.loaded); assert(model.loading);
    finish({ ok: true, revision: 'r1', config: { telegram_enabled: true, telegram_token_set: true, telegram_chat_id: 'fixture' } });
    await loading; assert(model.loaded); assert(!model.loading);
    await model.save(); assert.equal(writes, 1);
  });
  await check('failed notification load blocks writes and a successful save retains newer token edits', async () => {
    let writes = 0;
    const { model, context } = component('notifications.html', 'notificationsPage', {
      apiFetch: async (url, opts) => { if (opts?.method) writes++; return { ok: false, error: 'fixture' }; },
    });
    await model.init(); await model.save(); assert.equal(writes, 0); assert(model.loadFailed);
    model.loaded = true; model.revision = 'r1'; model.loadFailed = false; model.cfg.telegram_token = 'submitted-fixture';
    let finish;
    context.apiFetch = async () => new Promise(resolve => { finish = resolve; });
    const save = model.save(); model.cfg.telegram_token = 'later-fixture';
    finish({ ok: true, revision: 'r2', config: { telegram_token_set: true } }); await save;
    assert.equal(model.cfg.telegram_token, 'later-fixture');
  });
  await check('lockout policy cannot write before load, after failure, or during another save', async () => {
    let finish, writes = 0;
    const { model, context } = component('blocked.html', 'blockedPage', {
      apiFetch: async (url, opts) => {
        if (opts) { writes++; return { ok: true, revision: 'r2' }; }
        return new Promise(resolve => { finish = resolve; });
      },
    });
    await model.savePolicy(); assert.equal(writes, 0);
    const loading = model.loadPolicy(); await model.savePolicy(); assert.equal(writes, 0);
    finish({ ok: false, error: 'fixture read failed' }); await loading;
    await model.savePolicy(); assert.equal(writes, 0); assert(!model.policyLoaded);
    assert.match(model.policyMsg, /fixture read failed/);
    const retry = model.loadPolicy();
    finish({ ok: true, revision: 'r1', settings: { vpn: { max_attempts: 17 }, panel: { enabled: false } } });
    await retry; assert(model.policyLoaded); assert.equal(model.policy.vpn.max_attempts, 17);
    context.apiFetch = async () => { writes++; return new Promise(resolve => { finish = resolve; }); };
    const save = model.savePolicy(); await model.savePolicy(); assert.equal(writes, 1);
    finish({ ok: true, revision: 'r2', panel_applied: true }); await save;
    assert.equal(model.policyRevision, 'r2'); assert(!model.savingPolicy);
  });
  await check('lockout settings without a revision remain read-only', async () => {
    let writes = 0;
    const { model } = component('blocked.html', 'blockedPage', {
      apiFetch: async (url, opts) => {
        if (opts?.method) writes++;
        return { ok: true, settings: { vpn: { max_attempts: 7 } } };
      },
    });
    await model.loadPolicy(); await model.savePolicy(); assert(!model.policyLoaded); assert.equal(writes, 0);
  });
  await check('unavailable canonical defaults never create a fallback profile and recover on reload', async () => {
    let defaults = { ok: false, error: 'fixture defaults failed' };
    const { model, context } = component('config.html', 'configPage', {
      apiFetch: async url => url.endsWith('/defaults') ? defaults : { ok: true, revision: 'r1', config: { profiles: [] } },
      fetch: async () => ({ json: async () => defaults }),
    });
    model.loadIdentity = () => {};
    await model.load(); assert(model.loaded); model.addProfile();
    assert.equal(model.cfg.profiles.length, 0); assert(!model.dirty); assert(model.defaultsError);
    defaults = { ok: true, profile: { bind: {}, tun: { ip_mode: 'ipv4' }, pool: {}, dns: {}, extension: { retained: true } } };
    await model.load(); model.addProfile(); assert.equal(model.cfg.profiles.length, 1);
    assert(model.cfg.profiles[0].extension.retained); assert(!model.defaultsError);
    defaults = { ok: false, error: 'second read failed' }; await model.reloadCurrent();
    assert.equal(model.defaultProfile, null); model.addProfile(); assert.equal(model.cfg.profiles.length, 0);
  });

  for (const [file, factory, method, success, dataKey] of [
    ['logs.html', 'logsPage', 'load', { ok: true, lines: ['INFO fresh'], path: '/fresh' }, 'lines'],
    ['transport.html', 'transportHealthPage', 'refresh', { ok: true, profiles: [{ name: 'fresh' }], worker_ok: true }, 'profiles'],
    ['blocked.html', 'blockedPage', 'load', { ok: true, blocked: { vpn: [{ ip: 'fresh', unblock_in_secs: 8 }], panel: [] } }, 'blocked'],
  ]) {
    await check(factory + ' ignores obsolete responses and bounds background polls', async () => {
      const pending = [];
      const { model } = component(file, factory, {
        URLSearchParams, apiFetch: () => new Promise(resolve => pending.push(resolve)),
      });
      const old = model[method](); const fresh = model[method]();
      const background = model[method](true); assert.equal(pending.length, 2, 'a busy background poll must not start another request'); await background;
      pending[0]({ ok: false, error: 'obsolete failure' }); await old;
      assert(model.loading, 'obsolete completion must not clear current spinner');
      pending[1](success); await fresh; assert(!model.loading);
      assert.equal(model.error, '');
      const snapshot = JSON.stringify(model[dataKey]);
      const older = model[method](); const newer = model[method]();
      pending[3](success); await newer;
      pending[2]({ ok: true, lines: ['INFO obsolete'], profiles: [{ name: 'obsolete' }], blocked: { vpn: [], panel: [] } }); await older;
      assert.equal(JSON.stringify(model[dataKey]), snapshot);
    });
    await check(factory + ' preserves data on failure and suppresses writes after destroy', async () => {
      let finish; const cleared = [];
      const { model, context, html } = component(file, factory, {
        URLSearchParams, clearInterval: id => { if (id != null) cleared.push(id); }, apiFetch: async () => success,
      });
      await model[method](); const snapshot = JSON.stringify(model[dataKey]);
      context.apiFetch = async () => ({ ok: false, error: 'fixture unavailable' });
      await model[method](true); assert.match(model.error, /fixture unavailable/);
      assert.equal(JSON.stringify(model[dataKey]), snapshot);
      assert(html.includes('role="alert"'), 'load errors must be visible independently of filtered data');
      context.apiFetch = () => new Promise(resolve => { finish = resolve; });
      const pending = model[method](); model.destroy();
      finish({ ok: true, lines: ['INFO after destroy'], profiles: [], blocked: { vpn: [], panel: [] } }); await pending;
      assert.equal(JSON.stringify(model[dataKey]), snapshot);
      assert(!model.loading); assert.equal(model.pendingLoads, 0);
    });
  }
  await check('log errors are not log entries and cannot disappear under level/search filters', async () => {
    const { model, context, html } = component('logs.html', 'logsPage', {
      URLSearchParams, apiFetch: async () => ({ ok: true, lines: ['ERROR retained'] }),
    });
    await model.load(); model.selectedLevels = ['ERROR']; model.search = 'retained'; model.applyFilter();
    context.apiFetch = async () => ({ ok: false, error: 'Session expired' });
    await model.load(); assert.equal(model.filtered.length, 1); assert.match(model.error, /Session expired/);
    assert(html.includes('loaded && !loading && !error && filtered.length === 0'));
  });
  await check('blocked countdown cannot turn a stale snapshot into authoritative empty state', async () => {
    const { model, context, html } = component('blocked.html', 'blockedPage', {
      apiFetch: async () => ({ ok: true, blocked: { vpn: [{ ip: 'fixture', unblock_in_secs: 1 }], panel: [] } }),
    });
    await model.load(); model.tick(); model.tick();
    assert.equal(model.blocked.vpn.length, 1); assert.equal(model.blocked.vpn[0].unblock_in_secs, 0);
    context.apiFetch = async () => ({ ok: false, error: 'fixture unavailable' });
    await model.load(true); model.tick(); assert.equal(model.blocked.vpn.length, 1);
    assert(html.includes('loaded && !loading && !error && blocked.vpn.length === 0'));
    context.apiFetch = async () => ({ ok: true, blocked: { vpn: [], panel: [] } });
    await model.load(); assert.equal(model.blocked.vpn.length, 0); assert.equal(model.error, '');
  });
  await check('polling timers are cleared and cannot start work after destroy', async () => {
    for (const [file, factory] of [['logs.html','logsPage'], ['blocked.html','blockedPage'], ['transport.html','transportHealthPage']]) {
      const callbacks = [], cleared = []; let calls = 0;
      const { model } = component(file, factory, {
        URLSearchParams, setInterval: fn => { callbacks.push(fn); return callbacks.length; },
        setTimeout: fn => { callbacks.push(fn); return callbacks.length; },
        clearInterval: id => { if (id != null) cleared.push(id); }, clearTimeout: id => { if (id != null) cleared.push(id); }, apiFetch: async () => { calls++; return { ok: true, lines: [], blocked: {}, profiles: [] }; },
      });
      model.loadPolicy = async () => {}; model.scrollBottom = () => {};
      if (factory === 'logsPage') { model.autoRefresh = true; model.handleAutoRefresh(); } else await model.init();
      assert(callbacks.length > 0);
      model.destroy(); const before = calls;
      for (const fn of callbacks) fn(); await Promise.resolve();
      assert.equal(calls, before); assert.equal(cleared.length, callbacks.length);
    }
  });

  for (const [file, factory, method, errorKey, success, dataKey] of [
    ['dashboard.html','dashboard','load','loadError',url => url.endsWith('status') ? {ok:true,profiles:[],warnings:[]} : {ok:true,clients:[{username:'fresh'}]},'clients'],
    ['client.html','clientPage','refresh','loadError',() => ({ok:true,profiles:[{name:'fresh'}]}),'profiles'],
    ['users.html','usersPage','load','loadError',url => url.endsWith('users') ? {ok:true,users:[{username:'fresh'}]} : {ok:true,usage:[],clients:[],groups:{},config:{profiles:[]}},'users'],
    ['layout.html','app','fetchStatus','statusError',() => ({ok:true,client_count:7,version:'0.8.2'}),'activeInboundSessions'],
  ]) {
    await check(factory + ' displays API refusal, preserves snapshot and recovers', async () => {
      const {model,context,html}=component(file,factory,{apiFetch:async()=>({ok:false,error:'fixture refused'})});
      await model[method](); assert.match(model[errorKey],/fixture refused/);
      assert(html.includes('role="alert"')); context.apiFetch=async url=>success(url);
      await model[method](); assert.equal(model[errorKey],'');
      const snapshot=JSON.stringify(model[dataKey]); context.apiFetch=async()=>({ok:false,error:'fixture later refused'});
      await model[method](true); assert.equal(JSON.stringify(model[dataKey]),snapshot); assert.match(model[errorKey],/fixture later refused/);
    });
    await check(factory + ' ignores obsolete reads, bounds polls and ignores completion after destroy',async()=>{
      const pending=[]; const {model,context}=component(file,factory,{apiFetch:url=>new Promise(resolve=>pending.push({url,resolve}))});
      if(factory==='usersPage'){model.loadGroups=async()=>{};model.loadProfiles=async()=>{};model.loadUsage=async()=>{};}
      const old=model[method](); const split=pending.length; const fresh=model[method](); const count=pending.length;
      const background=model[method](true); assert.equal(pending.length,count); await background;
      for(const req of pending.slice(split)) req.resolve(success(req.url)); await fresh;
      const snapshot=JSON.stringify(model[dataKey]);
      for(const req of pending.slice(0,split)) req.resolve({ok:false,error:'obsolete failure'}); await old;
      assert.equal(model[errorKey],''); assert.equal(JSON.stringify(model[dataKey]),snapshot);
      const after=model[method](); model.destroy(); for(const req of pending.slice(count)) req.resolve(success(req.url)); await after;
      assert.equal(JSON.stringify(model[dataKey]),snapshot);
    });
  }
  await check('dashboard metrics own freshness and do not revive after destroy',async()=>{
    const pending=[];const {model}=component('dashboard.html','dashboard',{apiFetch:url=>new Promise(resolve=>pending.push({url,resolve}))});
    const old=model.loadMetrics(), fresh=model.loadMetrics(); const background=model.loadMetrics(true);assert.equal(pending.length,4);await background;
    for(const req of pending.slice(2))req.resolve(req.url.endsWith('system')?{ok:true,cpu_pct:17}:{ok:true,points:[{down_mbps:7}]});await fresh;
    for(const req of pending.slice(0,2))req.resolve({ok:false});await old;
    assert(!model.metricsErr);assert.equal(model.sys.cpu_pct,17);
    const after=model.loadMetrics();model.destroy();for(const req of pending.slice(4))req.resolve({ok:false});await after;assert(!model.metricsErr);
  });
  for(const ok of [true,false]) await check('dashboard bandwidth '+(ok?'success':'failure')+' owns its original modal',async()=>{
    let finish,writes=0;const {model}=component('dashboard.html','dashboard',{apiFetch:()=>{writes++;return new Promise(r=>finish=r);}});
    model.load=async()=>{}; model.openBw({username:'A',profile:'p',bandwidth_limit_mbps:1});
    const save=model.saveBw();await model.saveBw();assert.equal(writes,1,'Enter/button cannot duplicate a pending write');
    model.openBw({username:'B',profile:'p',bandwidth_limit_mbps:2});const next=model.bwModal;
    finish({ok,error:'old failure',message:'saved A'});await save;assert.equal(model.bwModal,next);assert(model.bwModal.show);assert.equal(model.bwModal.username,'B');
  });
  await check('client save and edit responses cannot close or replace a newer form',async()=>{
    let finish,writes=0;const {model,context}=component('client.html','clientPage',{apiFetch:()=>{writes++;return new Promise(r=>finish=r);}});
    model.refresh=async()=>{}; model.openCreate();model.form.name='A';const save=model.save();await model.save();assert.equal(writes,1);
    model.openCreate();model.form.name='B';finish({ok:true,name:'A'});await save;assert(model.formOpen);assert.equal(model.form.name,'B');
    context.apiFetch=()=>new Promise(r=>finish=r);const edit=model.openEdit('A');model.openCreate();model.form.name='B';
    finish({ok:true,raw:'[qeli]\nserver = fixture\n',revision:'r1'});await edit;assert.equal(model.form.name,'B');
  });
  for(const method of ['create','save','saveGroup','saveLimit','doReset']) for(const ok of [true,false]) await check('users '+method+' '+(ok?'success':'failure')+' preserves a newly opened modal',async()=>{
    let finish,writes=0;const {model}=component('users.html','usersPage',{apiFetch:()=>{writes++;return new Promise(r=>finish=r);}});
    model.load=async()=>{};model.loadGroups=async()=>{};model.loadUsage=async()=>{};
    if(method==='saveGroup')model.openGroup();else if(method==='saveLimit'||method==='doReset')model.openUsage('A',{},method==='doReset'?'reset':'limit');else if(method==='save')model.openEdit({username:'A'});else model.openCreate();
    model.form.username='A';model.form.plainPassword='fixture';model.groupForm.name='A';
    const save=model[method]();await model[method]();assert.equal(writes,1);
    model.openCreate();model.form.username='B';const next=model.form;finish({ok,error:'old failure',message:'saved A'});await save;
    assert.equal(model.modal,'create');assert.equal(model.form,next);assert.equal(model.modalError,'');assert.equal(model.modalSaving,false);
  });
  await check('late generated sharing credentials never enter another user modal',async()=>{
    let finish;const {model}=component('users.html','usersPage',{apiFetch:()=>new Promise(r=>finish=r)});
    model.openShare({username:'A'});model.share.host='fixture';const request=model.generateShare();
    model.openShare({username:'B'});finish({ok:true,uri:'qeli://A',qr_svg:'<svg></svg>',reset:true,new_password:'A-fixture'});await request;
    assert.equal(model.share.user,'B');assert.equal(model.share.uri,'');assert.equal(model.share.newPassword,'');
  });
  await check('remaining panel timers/listeners and delayed client-connect reload have cleanup',async()=>{
    for(const [file,factory] of [['dashboard.html','dashboard'],['users.html','usersPage'],['client.html','clientPage'],['layout.html','app']]){
      const timers=[],cleared=[],listeners=[],removed=[];let calls=0;
      const {model,context}=component(file,factory,{setInterval:fn=>{timers.push(fn);return timers.length;},clearInterval:id=>{if(id!=null)cleared.push(id);},setTimeout:fn=>{timers.push(fn);return timers.length;},clearTimeout:id=>{if(id!=null)cleared.push(id);},document:{readyState:'loading',hidden:false,getElementById:()=>null,addEventListener:(type,fn)=>{if(type==='visibilitychange')listeners.push(fn);},removeEventListener:(type,fn)=>removed.push(fn)},apiFetch:async()=>{calls++;return{ok:false,error:'fixture'};}});
      await model.init();if(factory==='clientPage')await model.connect('fixture');model.destroy();const before=calls;
      for(const fn of timers)fn();for(const fn of listeners)fn();await Promise.resolve();assert.equal(calls,before);assert.equal(cleared.length,timers.length);assert.equal(removed.length,listeners.length);
    }
  });

  await check('pending dashboard/client saves preserve later edits and omit UI flags from API',async()=>{
    for(const kind of ['dashboard','client']){
      let finish,sent;const {model}=component(kind+'.html',kind==='client'?'clientPage':'dashboard',{apiFetch:(url,opts)=>{sent=JSON.parse(opts.body);return new Promise(r=>finish=r);}});
      model.load=async()=>{};model.refresh=async()=>{};
      if(kind==='client'){model.openCreate();model.form.name='A';}else model.openBw({username:'A',profile:'p',bandwidth_limit_mbps:1});
      const pending=kind==='client'?model.save():model.saveBw();
      if(kind==='client')model.form.server='later';else model.bwModal.mbps=2;
      finish({ok:true,name:'A'});await pending;
      assert(kind==='client'?model.formOpen:model.bwModal.show);assert(!('saving' in sent));
    }
  });
  for(const method of ['create','save','saveGroup','saveLimit'])await check('users '+method+' keeps edits made during a successful save',async()=>{
    let finish;const {model}=component('users.html','usersPage',{apiFetch:()=>new Promise(r=>finish=r)});model.load=async()=>{};model.loadUsage=async()=>{};model.loadGroups=async()=>{};
    let owner;if(method==='saveGroup'){model.openGroup();model.groupForm.name='A';owner=model.groupForm;}else if(method==='saveLimit'){model.openUsage('A',{},'limit');owner=model.usageForm;}else{if(method==='save')model.openEdit({username:'A'});else model.openCreate();model.form.username='A';model.form.plainPassword='fixture';owner=model.form;}
    const pending=model[method]();owner.later_edit='retained';finish({ok:true});await pending;assert(model.modal);assert.equal(owner.later_edit,'retained');assert(!model.modalSaving);
  });
  await check('users usage errors are visible and an obsolete failure cannot clear newer addresses',async()=>{
    const pending=[];const {model,context}=component('users.html','usersPage',{apiFetch:url=>new Promise(resolve=>pending.push({url,resolve}))});
    const old=model.loadUsage(),fresh=model.loadUsage();const background=model.loadUsage(true);assert.equal(pending.length,4);await background;
    for(const req of pending.slice(2))req.resolve(req.url.endsWith('usage')?{ok:true,usage:[{username:'A',online:true}]}:{ok:true,clients:[{username:'A',ip:'10.1.2.3'}]});await fresh;
    for(const req of pending.slice(0,2))req.resolve({ok:false,error:'obsolete'});await old;
    assert.equal(model.activeAddressesByUser.A[0],'10.1.2.3');assert.equal(model.readErrors.usage,'');
    context.apiFetch=async()=>({ok:false,error:'current failure'});await model.loadUsage();assert.match(model.readErrors.usage,/current failure/);assert.equal(Object.keys(model.activeAddressesByUser).length,0);assert.equal(model.usage.length,1);
  });
  await check('client import completion and duplicate submits belong to the original import modal',async()=>{
    let finish,writes=0;const {model}=component('client.html','clientPage',{apiFetch:()=>{writes++;return new Promise(r=>finish=r);}});model.refresh=async()=>{};
    model.openImport();model.importLink='A';const pending=model.doImport();await model.doImport();assert.equal(writes,1);
    model.openImport();model.importLink='B';finish({ok:true,name:'A'});await pending;assert(model.importOpen);assert.equal(model.importLink,'B');assert(!model.importSaving);
  });

  for(const kind of ['dashboard','client','users'])await check(kind+' rejects malformed collection replies without corrupting the snapshot',async()=>{
    const factory=kind==='client'?'clientPage':kind==='users'?'usersPage':'dashboard';const {model,context}=component(kind+'.html',factory);
    let healthy=true;context.apiFetch=async url=>url.endsWith('clients')?{ok:true,clients:healthy?[]:'broken'}:url.endsWith('profiles')?{ok:true,profiles:healthy?[]:'broken'}:url.endsWith('users')?{ok:true,users:healthy?[]:'broken'}:url.endsWith('config')?{ok:true,config:{profiles:[]}}:{ok:true,profiles:[],usage:[],groups:{}};
    await model.load();healthy=false;await model.load();assert(model.loadError);assert(Array.isArray(kind==='dashboard'?model.clients:kind==='client'?model.profiles:model.users));
  });

  await check('shared layout exposes translations to CSP Alpine child expressions',async()=>{
    const {model}=component('layout.html','app',{window:{qeliT:s=>'translated '+s,qeliTf:(s,...v)=>s+v.join('/')}});assert.equal(model.qeliT('fixture'),'translated fixture');assert.equal(model.qeliTf('{}',1,2),'{}1/2');
  });
  const quickReply = () => ({ok:true,config:{profiles:[]},revision:'r1'});
  const builtReply = id => ({ok:true,profile:{name:id,bind:{port:8447,transport:'tcp'}}});
  await check('quickstart captures IP mode before reading and confirming, with one build/restart',async()=>{
    let read,confirm,writes=0,restarts=0,sent,prompt;
    const {model}=component('quickstart.html','quickstartPage',{
      apiFetch:(url,opts)=>opts?.method ? (writes++,sent=JSON.parse(opts.body),Promise.resolve(builtReply('plain'))) : new Promise(r=>read=r),
      qeliConfirm:(title,text)=>{prompt=text;return new Promise(r=>confirm=r);},restartServer:async()=>{restarts++;return true;},
    });
    model.ipMode='ipv4';const pending=model.quickStart(model.modes.find(m=>m.id==='plain'));
    model.ipMode='dual';await model.quickStart(model.modes[0]);read(quickReply());
    while(!confirm)await Promise.resolve();assert.match(prompt,/ipv4$/);model.ipMode='ipv6';confirm(true);await pending;
    assert.equal(sent.ip_mode,'ipv4');assert.equal(sent.expected_revision,'r1');assert.equal(writes,1);assert.equal(restarts,1);assert.equal(model.qs.busy,null);
    assert.equal(model.qs.done.ok,true);
  });
  for(const reply of [null,{ok:false,error:'fixture read failed'},{ok:true,config:null,revision:'r1'},{ok:true,config:{profiles:{}},revision:'r1'},{ok:true,config:{profiles:[null]},revision:'r1'},{ok:true,config:{profiles:[]}}])await check('quickstart invalid config/revision releases busy and never builds: '+JSON.stringify(reply),async()=>{
    let writes=0;const {model,events}=component('quickstart.html','quickstartPage',{apiFetch:async(url,opts)=>{if(opts?.method)writes++;return reply;}});
    await model.quickStart(model.modes[0]);assert.equal(model.qs.busy,null);assert.equal(writes,0);assert.equal(events[0][1].type,'error');
  });
  await check('quickstart cancellation, stale revision and malformed build never restart',async()=>{
    for(const variant of ['cancel','conflict','bad build']){
      let writes=0,restarts=0;const {model}=component('quickstart.html','quickstartPage',{
        apiFetch:async(url,opts)=>opts?.method?(writes++,variant==='conflict'?{ok:false,kind:'config_conflict',error:'stale'}:{ok:true,profile:null}):quickReply(),
        qeliConfirm:async()=>variant!=='cancel',restartServer:async()=>{restarts++;return true;},
      });
      await model.quickStart(model.modes[0]);assert.equal(writes,variant==='cancel'?0:1);assert.equal(restarts,0);assert.equal(model.qs.busy,null);
    }
  });
  await check('quickstart checks existing manual bind and permits opposite transport',async()=>{
    let writes=0;const {model,context}=component('quickstart.html','quickstartPage');
    const profiles=[{name:'plain',bind:{port:9443,transport:'udp'}},{name:'other',bind:{port:9443,transport:'udp'}}];
    context.apiFetch=async(url,opts)=>opts?.method?(writes++,builtReply('plain')):{ok:true,revision:'r1',config:{profiles}};
    context.restartServer=async()=>true;await model.quickStart(model.modes.find(m=>m.id==='plain'));assert.equal(model.portClash.port,9443);assert.equal(writes,0);
    profiles[1].bind.transport='tcp';await model.quickStart(model.modes.find(m=>m.id==='plain'));assert.equal(writes,1);assert.equal(model.portClash,null);
    assert(model.modes.every(m=>Object.keys(m).every(k=>['id','name','transport','port','tag','flag','desc'].includes(k))));
  });
  await check('quickstart restart failure retains saved/unconfirmed result and clipboard failures are visible',async()=>{
    for(const failure of [false,'throw']){
      const {model,context,events}=component('quickstart.html','quickstartPage',{apiFetch:async(url,opts)=>opts?.method?builtReply('plain'):quickReply(),restartServer:async()=>{if(failure==='throw')throw Error('rejected');return false;},navigator:{}});
      await model.quickStart(model.modes.find(m=>m.id==='plain'));assert.equal(model.qs.done.ok,false);assert.equal(events.at(-1)[1].type,'warn');
      await model.copy('fixture');assert.equal(events.at(-1)[1].msg,'Copy failed');
      context.navigator.clipboard={writeText:async()=>{throw Error('permission');}};await model.copy('fixture');assert.equal(events.at(-1)[1].msg,'Copy failed');
      context.navigator.clipboard={writeText:async()=>{}};await model.copy('fixture');assert.equal(events.at(-1)[1].msg,'Copied');
    }
  });
  await check('destroyed quickstart stops after read, confirmation or build without restart',async()=>{
    for(const stop of ['read','confirm','build']){
      let finish,writes=0,restarts=0;const {model}=component('quickstart.html','quickstartPage',{
        apiFetch:async(url,opts)=>opts?.method?(writes++,stop==='build'?new Promise(r=>finish=()=>r(builtReply('plain'))):builtReply('plain')):stop==='read'?new Promise(r=>finish=()=>r(quickReply())):quickReply(),
        qeliConfirm:async()=>stop==='confirm'?new Promise(r=>finish=()=>r(true)):true,restartServer:async()=>{restarts++;return true;},
      });
      const pending=model.quickStart(model.modes.find(m=>m.id==='plain'));for(let n=0;n<100&&!finish;n++)await Promise.resolve();assert(finish,'fixture request did not start');model.destroy();finish();await pending;
      assert.equal(restarts,0);assert.equal(writes,stop==='build'?1:0);assert.equal(model.qs.done,null);assert.equal(model.qs.busy,null);
    }
  });
  const notifyReply = revision => ({ok:true,revision,config:{server_name:'fixture',telegram_enabled:true,telegram_token_set:true,telegram_token_hint:'…last',telegram_chat_id:'123',webhook_enabled:true,webhook_url:'https://fixture.invalid'}});
  await check('notification missing revision/malformed config blocks edits, writes and tests; retry is atomic',async()=>{
    const {model,context}=component('notifications.html','notificationsPage');let writes=0;
    for(const reply of [{ok:true,config:{}}, {ok:true,config:[],revision:'r1'}, {ok:true,config:null,revision:'r1'}, {ok:false,error:'fixture read failed'}]){
      context.apiFetch=async(url,opts)=>{if(opts?.method)writes++;return reply;};await model.init();model.toggle('telegram_enabled');await model.save();await model.testChan('telegram');assert(model.loadFailed);assert(!model.canEdit());assert.equal(writes,0);assert.equal(model.cfg.server_name,'');
    }
    context.apiFetch=async()=>notifyReply('r1');await model.init();assert(model.canEdit());assert.equal(model.cfg.telegram_token,'');assert.equal(model.tokenHint,'…last');
  });
  await check('notification duplicate load and reload while saving are suppressed; pending drafts survive',async()=>{
    let finish,reads=0;const {model,context}=component('notifications.html','notificationsPage',{apiFetch:()=>{reads++;return new Promise(r=>finish=r);}});
    const pending=model.init();await model.init();model.cfg.telegram_token='new draft';finish(notifyReply('r1'));await pending;assert.equal(reads,1);assert(model.loadFailed);assert.equal(model.cfg.telegram_token,'new draft');
    context.apiFetch=async()=>notifyReply('r1');await model.init();assert(model.canEdit());assert.equal(model.cfg.telegram_token,'new draft');
    let writes=0;context.apiFetch=()=>{writes++;return new Promise(r=>finish=r);};const save=model.save();await model.init();await model.save();await model.testChan('telegram');assert.equal(writes,1);model.cfg.telegram_token='newer';finish(notifyReply('r2'));await save;assert.equal(model.cfg.telegram_token,'newer');assert.equal(model.revision,'r2');
  });
  await check('notification stale or missing save revision preserves draft and requires reload',async()=>{
    for(const reply of [{ok:false,kind:'config_conflict',error:'stale fixture'},{ok:true,config:{telegram_token_set:true}}]){
      const {model,context}=component('notifications.html','notificationsPage',{apiFetch:async()=>notifyReply('r1')});await model.init();model.cfg.telegram_token='draft';let writes=0;context.apiFetch=async()=>{writes++;return reply;};await model.save();await model.save();assert.equal(writes,1);assert(model.loadFailed);assert.equal(model.cfg.telegram_token,'draft');assert.equal(model.revision,'r1');
    }
  });
  await check('notification tests remain independent, reject duplicates and hide results for edited credentials',async()=>{
    const {model,context,events}=component('notifications.html','notificationsPage',{apiFetch:async()=>notifyReply('r1')});await model.init();events.length=0;
    const pending=[];context.apiFetch=(url,opts)=>new Promise(resolve=>pending.push({body:JSON.parse(opts.body),resolve}));
    const tg=model.testChan('telegram'),wh=model.testChan('webhook');await model.testChan('telegram');await model.save();await model.init();assert.equal(pending.length,2);
    model.cfg.telegram_chat_id='456';pending[0].resolve({ok:true,result:{ok:true,status:200}});pending[1].resolve({ok:true,result:{ok:false,error:'fixture delivery refused'}});await Promise.all([tg,wh]);
    assert.equal(model.resultFor('telegram'),null);assert.equal(model.resultFor('webhook').ok,false);assert.equal(events.length,1);assert.equal(events[0][1].type,'error');assert(!model.testingTg&&!model.testingWh);
    context.apiFetch=async()=>{throw Error('network fixture');};await model.testChan('telegram');assert.equal(model.resultFor('telegram').ok,false);assert.equal(events.at(-1)[1].type,'error');
    context.apiFetch=async()=>({ok:true});await model.testChan('webhook');assert.equal(model.resultFor('webhook').ok,false);
  });
  await check('notification destroyed during load/save/test never mutates returned UI state',async()=>{
    for(const op of ['init','save','testChan']){
      const {model,context,events}=component('notifications.html','notificationsPage',{apiFetch:async()=>notifyReply('r1')});await model.init();events.length=0;let finish;context.apiFetch=()=>new Promise(r=>finish=r);
      const pending=model[op]('telegram');model.destroy();finish(op==='testChan'?{ok:true,result:{ok:true}}:notifyReply('r2'));await pending;
      assert.equal(events.length,0);assert.equal(model.revision,'r1');assert.equal(model.resultTg,null);
    }
  });
  function loginFixture(fetch) {
    const els={};let handler;for(const id of ['loginForm','err','btn','btnText','btnSpin','username','password'])els[id]={value:'',style:{},disabled:false,classList:{add(){},remove(){}}};
    els.loginForm.addEventListener=(event,fn)=>handler=fn;const context={document:{getElementById:id=>els[id]},window:{location:{href:'login'}},fetch};vm.createContext(context);
    const html=fs.readFileSync(path.join(templates,'login.html'),'utf8');for(const m of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g))vm.runInContext(m[1],context);
    return {els,context,submit:()=>handler({preventDefault(){}})};
  }
  await check('login Enter/repeated submit sends once, preserves exact password and retries after failure',async()=>{
    let finish,writes=0,sent;const f=loginFixture((url,opts)=>{writes++;sent=JSON.parse(opts.body);return new Promise(r=>finish=r);});f.els.username.value=' admin ';f.els.password.value='  exact#;pass  ';
    const pending=f.submit();await f.submit();assert.equal(writes,1);assert.equal(sent.username,'admin');assert.equal(sent.password,'  exact#;pass  ');assert(f.els.btn.disabled);
    finish({ok:false,json:async()=>({ok:false,error:'fixture refused'})});await pending;assert.equal(f.els.err.textContent,'fixture refused');assert(!f.els.btn.disabled);
    const retry=f.submit();finish({ok:true,json:async()=>({ok:true})});await retry;await f.submit();assert.equal(writes,2);assert.equal(f.context.window.location.href,'.');assert(f.els.btn.disabled);
  });
  await check('login malformed responses and network failures never redirect or leave busy',async()=>{
    for(const response of [null,{}, {ok:'true'}]){
      const f=loginFixture(async()=>({ok:true,json:async()=>response}));f.els.username.value='a';f.els.password.value='b';await f.submit();assert.equal(f.els.err.textContent,'Sign in failed');assert(!f.els.btn.disabled);assert.equal(f.context.window.location.href,'login');
    }
    for(const broken of ['json','network']){
      const f=loginFixture(async()=>{if(broken==='network')throw Error('fixture offline');return{ok:true,json:async()=>{throw Error('fixture invalid JSON');}};});f.els.username.value='a';f.els.password.value='b';await f.submit();assert(!f.els.btn.disabled);assert.equal(f.context.window.location.href,'login');
    }
    let writes=0;const f=loginFixture(async()=>{writes++;});await f.submit();assert.equal(writes,0);assert.equal(f.els.err.textContent,'Enter a username and password');
  });


  function readyEditor(raw=false, overrides={}) {
    const result=component('config.html','configPage',overrides),m=result.model;
    m.loaded=true;m.revision='r1';m.view=raw?'raw':'form';m.cfg={profiles:[],auth:{brute_force:{}},web:{brute_force:{}},logging:{level:'info'}};
    m._original=JSON.stringify(m.cfg);m.rawOriginal='original';m.rawText='original';result.identityRead=m.loadIdentity;m.loadIdentity=()=>{};return result;
  }
  const configRead=(revision='r1',level='info')=>({ok:true,revision,config:{profiles:[],logging:{level}}});
  await check('config serializes form/raw reads and rejects unconfirmed dirty reloads',async()=>{
    const pending=[];const {model,context}=readyEditor(false,{apiFetch:url=>new Promise(resolve=>pending.push({url,resolve}))});
    const read=model.load();await model.loadRaw();await model.load();assert.equal(pending.length,2);
    pending.find(r=>r.url.endsWith('defaults')).resolve({ok:false,error:'fixture defaults'});pending.find(r=>r.url.endsWith('config')).resolve(configRead());await read;
    assert(model.loaded);assert(!model.loading);assert(model.defaultsError);const cfg=JSON.stringify(model.cfg);model.cfg.logging.level='debug';model.dirty=true;
    await model.load();await model.loadRaw();assert.equal(pending.length,2);assert.notEqual(JSON.stringify(model.cfg),cfg);
    context.qeliConfirm=async()=>false;await model.reloadCurrent();assert.equal(pending.length,2);assert(model.dirty);
  });
  for(const kind of ['form','raw'])await check('config '+kind+' load preserves pending edits and rejects malformed/revisionless replies',async()=>{
    const {model,context}=readyEditor(kind==='raw');let finish;context.apiFetch=url=>url.endsWith('defaults')?Promise.resolve({ok:false}):new Promise(r=>finish=r);
    const p=kind==='raw'?model.loadRaw():model.load();if(kind==='raw')model.rawText='later draft';else model.cfg.logging.level='later';model.dirty=true;
    finish(kind==='raw'?{ok:true,revision:'r2',raw:'disk'}:configRead('r2','disk'));await p;assert(!model.loaded);assert(model.loadError);assert(model.dirty);assert.equal(kind==='raw'?model.rawText:model.cfg.logging.level,kind==='raw'?'later draft':'later');
    model.dirty=false;
    for(const reply of [null,{ok:true,config:null,raw:null,revision:'r1'},{ok:true,config:{profiles:[null]},raw:1,revision:'r1'},{ok:true,config:{profiles:[]},raw:'disk'}]){
      context.apiFetch=async url=>url.endsWith('defaults')?{ok:false}:reply;await(kind==='raw'?model.loadRaw():model.load());assert(!model.loaded);assert(model.loadError);assert.equal(model.revision,'r1');
    }
  });
  await check('default endpoint rejection remains independent of successful config read',async()=>{
    const {model}=readyEditor(false,{apiFetch:async url=>{if(url.endsWith('defaults'))throw Error('fixture defaults offline');return configRead();}});
    await model.load();assert(model.loaded);assert.equal(model.defaultProfile,null);assert(model.defaultsError);
  });
  for(const operation of ['switch','reload'])await check('config '+operation+' confirmation retains newer drafts and excludes competing actions',async()=>{
    let confirm,reads=0;const {model}=readyEditor(false,{qeliConfirm:()=>new Promise(r=>confirm=r),apiFetch:async()=>{reads++;return configRead();}});model.cfg.logging.level='debug';model.dirty=true;
    const p=operation==='switch'?model.switchView('raw'):model.reloadCurrent();await model.switchView('raw');await model.save();await model.applyRestart();assert.equal(reads,0);assert.equal(model.action,'view');
    model.cfg.logging.level='later';confirm(true);await p;assert.equal(model.view,'form');assert.equal(model.cfg.logging.level,'later');assert.equal(reads,0);assert(model.dirty);assert.equal(model.action,null);
  });
  for(const raw of [false,true])await check('config '+(raw?'INI':'form')+' save reserves review and writes captured revision/draft once',async()=>{
    let confirm,reply,writes=0,sent;const {model}=readyEditor(raw,{qeliConfirm:()=>new Promise(r=>confirm=r),apiFetch:(url,opts)=>{writes++;sent=JSON.parse(opts.body);return new Promise(r=>reply=r);}});
    if(raw)model.rawText='reviewed';else model.cfg.logging.level='reviewed';model.dirty=true;
    const p=raw?model.saveRaw():model.save();await(raw?model.saveRaw():model.save());await model.applyRestart();await model.reloadCurrent();assert.equal(writes,0);assert.equal(model.action,'save');
    if(raw)model.rawText='newer';else model.cfg.logging.level='newer';confirm(true);for(let n=0;n<100&&!reply;n++)await Promise.resolve();assert(reply,'fixture request did not start');assert.equal(writes,1);assert.equal(sent.expected_revision,'r1');assert.equal(raw?sent.raw:sent.config.logging.level,'reviewed');
    reply({ok:true,revision:'r2'});await p;assert(model.dirty);assert.equal(model.revision,'r2');assert.equal(raw?model.rawOriginal:JSON.parse(model._original).logging.level,'reviewed');assert.equal(model.action,null);
  });
  for(const raw of [false,true])await check('config '+(raw?'INI':'form')+' save aborts a changed review owner and fails closed on missing returned revision',async()=>{
    let confirm,writes=0;const {model,context}=readyEditor(raw,{qeliConfirm:()=>new Promise(r=>confirm=r),apiFetch:async()=>{writes++;return{ok:true,revision:'r3'};}});
    if(raw)model.rawText='draft';else model.cfg.logging.level='draft';model.dirty=true;const p=raw?model.saveRaw():model.save();model.revision='r2';confirm(true);await p;assert.equal(writes,0);assert.equal(model.revision,'r2');assert(model.dirty);
    context.qeliConfirm=async()=>true;context.apiFetch=async()=>{writes++;return{ok:true};};await(raw?model.saveRaw():model.save());assert(!model.loaded);assert(model.loadError);assert(model.dirty);assert.equal(model.revision,'r2');
  });
  await check('apply restart cancellation/failure/new draft never starts restart and uncertainty retains socket requirement',async()=>{
    for(const mode of ['cancel','fail','new draft']){
      let restarts=0;const {model}=readyEditor(false,{qeliConfirm:async()=>mode!=='cancel',apiFetch:async()=>{if(mode==='new draft')model.cfg.logging.level='later';return mode==='fail'?{ok:false,error:'fixture refused'}:{ok:true,revision:'r2'};},fullRestartServer:async()=>{restarts++;return{ok:true,cameBack:true};}});
      model.cfg.logging.level='draft';model.dirty=true;await model.applyRestart();assert.equal(restarts,0);assert.equal(model.action,null);assert(!model.restarting);
    }
    let finish,calls=0;const {model}=readyEditor(false,{fullRestartServer:()=>{calls++;return new Promise(r=>finish=r);}});model.needsFullRestart=true;const p=model.applyRestart();await model.applyRestart();assert.equal(calls,1);finish({ok:true,cameBack:false});await p;assert(model.needsFullRestart);
  });
  await check('identity read failures retain keys, newest response wins and only public fields are retained',async()=>{
    const {model,context}=component('config.html','configPage');const pending=[];context.apiFetch=()=>new Promise(r=>pending.push(r));
    const old=model.loadIdentity(),fresh=model.loadIdentity();pending[1]({ok:true,profiles:[{name:'fresh',public_key:'a'.repeat(64),private_key:'must not be retained'}]});await fresh;pending[0]({ok:false,error:'obsolete'});await old;
    assert.equal(model.identity[0].name,'fresh');assert(!('private_key'in model.identity[0]));assert.equal(model.identityError,'');assert(!model.identityLoading);
    context.apiFetch=async()=>({ok:false,error:'current failure'});await model.loadIdentity();assert.match(model.identityError,/current failure/);assert.equal(model.identity[0].name,'fresh');
    context.apiFetch=async()=>({ok:true,profiles:[null]});await model.loadIdentity();assert(model.identityError);assert.equal(model.identity[0].name,'fresh');
    context.apiFetch=async()=>({ok:true,profiles:[]});await model.loadIdentity();assert(model.identityLoaded);assert.equal(model.identityError,'');assert.equal(model.identity.length,0);
  });
  await check('identity rotation reserves confirmation, prevents duplicates and aborts replaced key owner',async()=>{
    let confirm,writes=0;const {model,context}=readyEditor(false,{qeliConfirm:()=>new Promise(r=>confirm=r),apiFetch:async(url,opts)=>{if(opts?.method)writes++;return{ok:true,profiles:[]};}});model.identity=[{name:'A',public_key:'a'.repeat(64)}];
    const p=model.rotateIdentity('A');await model.rotateIdentity('A');await model.save();model.identity=[{name:'A',public_key:'b'.repeat(64)}];confirm(true);await p;assert.equal(writes,0);assert.equal(model.action,null);
    model.loadIdentity=async()=>true;context.qeliConfirm=async()=>true;let finish;context.apiFetch=()=>{writes++;return new Promise(r=>finish=r);};const rotate=model.rotateIdentity('A');for(let n=0;n<100&&!finish;n++)await Promise.resolve();assert(finish,'fixture request did not start');await model.rotateIdentity('A');assert.equal(writes,1);finish({ok:true});await rotate;assert.equal(model.identityRotating,null);
  });
  await check('password hash preserves newer plaintext and config ownership, and suppresses duplicate requests',async()=>{
    let finish,writes=0,sent;const {model,context}=readyEditor(false,{apiFetch:(url,opts)=>{writes++;sent=JSON.parse(opts.body);return new Promise(r=>finish=r);}});model.adminPw='  original#;  ';
    const p=model.hashAdminPw();await model.hashAdminPw();await model.save();assert.equal(writes,1);assert.equal(sent.password,'  original#;  ');model.adminPw='newer';finish({ok:true,hash:'old hash'});await p;
    assert.equal(model.adminPw,'newer');assert.equal(model.cfg.web.password_hash,undefined);assert.equal(model.adminPwStatus,'err');assert(!model.adminPwHashing);
    context.apiFetch=async()=>({ok:true,hash:'new hash'});await model.hashAdminPw();assert.equal(model.cfg.web.password_hash,'new hash');assert.equal(model.adminPw,'');assert(model.dirty);
  });
  await check('history late replies cannot replace a newly opened modal; failures preserve snapshot and block restore',async()=>{
    const pending=[];const {model,context}=readyEditor(false,{apiFetch:()=>new Promise(r=>pending.push(r))});
    const old=model.openHistory();model.closeHistory();const fresh=model.openHistory();pending[1]({ok:true,entries:[{id:'new',revision:'r0',created:1,bytes:1}]});await fresh;pending[0]({ok:true,entries:[{id:'old',revision:'r0'}]});await old;
    assert.equal(model.history[0].id,'new');assert(model.historyLoaded);assert(!model.historyLoading);context.apiFetch=async()=>({ok:false,error:'history offline'});await model.openHistory();assert(model.historyError);assert.equal(model.history[0].id,'new');assert.equal(await model.restoreHistory(model.history[0]),false);
  });
  await check('history restore captures revision, serializes review, retains later edits and never restarts',async()=>{
    for(const when of ['review','POST']){
      let confirm,reply,writes=0,sent;const {model}=readyEditor(false,{qeliConfirm:()=>new Promise(r=>confirm=r),apiFetch:(url,opts)=>{writes++;sent=JSON.parse(opts.body);return new Promise(r=>reply=r);}});const entry={id:'snapshot',revision:'r0',created:1};model.history=[entry];model.historyOpen=true;
      const p=model.restoreHistory(entry);await model.restoreHistory(entry);model.closeHistory();assert(model.historyOpen);assert.equal(model.action,'restore');
      if(when==='review'){model.cfg.logging.level='later';model.dirty=true;}confirm(true);if(when==='POST'){for(let n=0;n<100&&!reply;n++)await Promise.resolve();assert(reply,'fixture request did not start');model.cfg.logging.level='later';model.dirty=true;reply({ok:true,revision:'r2'});}await p;
      assert.equal(writes,when==='review'?0:1);if(sent)assert.equal(sent.expected_revision,'r1');assert.equal(model.cfg.logging.level,'later');assert(model.dirty);assert.equal(model.action,null);assert.equal(model.historyRestoring,null);
      if(when==='POST')assert(!model.loaded);
    }
  });
  await check('history clean restore refreshes canonical config and preserves restart requirement',async()=>{
    const {model,context}=readyEditor(false);const entry={id:'snapshot',revision:'r0',created:1};model.history=[entry];model.historyOpen=true;
    context.apiFetch=async(url,opts)=>opts?.method?{ok:true,revision:'r2'}:url.endsWith('defaults')?{ok:false}:{...configRead('r2','restored'),needs_full_restart:true};
    assert.equal(await model.restoreHistory(entry),true);assert.equal(model.cfg.logging.level,'restored');assert.equal(model.revision,'r2');assert(model.needsFullRestart);assert(!model.historyOpen);
  });
  await check('remove confirmation retains profile identity after index shifts and aborts changed contents',async()=>{
    for(const changed of [false,true]){
      let confirm;const {model}=readyEditor(false,{qeliConfirm:()=>new Promise(r=>confirm=r)});const target={name:'A'},other={name:'B'};model.cfg.profiles=[target,other];const p=model.removeProfile(0);
      model.cfg.profiles.unshift({name:'inserted'});if(changed)target.name='edited';confirm(true);await p;assert.equal(model.cfg.profiles.includes(target),changed);assert(model.cfg.profiles.includes(other));assert.equal(model.action,null);
    }
  });
  for(const operation of ['read','identity','history','save','hash','restart'])await check('config destroy suppresses late '+operation+' effects',async()=>{
    let finish;const {model,context,events,identityRead}=readyEditor(false,{window:{removeEventListener(){}}});
    if(operation==='identity')model.loadIdentity=identityRead;
    context.apiFetch=url=>url.endsWith('defaults')?Promise.resolve({ok:false}):new Promise(r=>finish=r);context.fullRestartServer=()=>new Promise(r=>finish=r);
    let p;if(operation==='read')p=model.load();else if(operation==='identity')p=model.loadIdentity();else if(operation==='history')p=model.openHistory();else if(operation==='save'){model.cfg.logging.level='draft';model.dirty=true;p=model.save();}else if(operation==='hash'){model.adminPw='fixture';p=model.hashAdminPw();}else p=model.applyRestart();
    for(let n=0;n<100&&!finish;n++)await Promise.resolve();assert(finish,'fixture request did not start');model.destroy();finish(operation==='restart'?{ok:true,cameBack:true}:operation==='identity'?{ok:true,profiles:[{name:'late'}]}:operation==='history'?{ok:true,entries:[]}:{...configRead('r2','late'),hash:'late'});await p;
    assert.equal(model.revision,'r1');assert.equal(events.length,0);assert.equal(model.cfg.web.password_hash,undefined);assert.equal(model.identity.length,0);assert.equal(model.history.length,0);
  });
  await check('config beforeunload protects only dirty drafts and unregisters the exact handler',async()=>{
    let added,removed;const {model}=readyEditor(false,{window:{addEventListener:(e,f)=>added=f,removeEventListener:(e,f)=>removed=f}});model.load=()=>{};model.init();let prevented=0;const event={preventDefault(){prevented++;}};
    added(event);assert.equal(prevented,0);model.dirty=true;added(event);assert.equal(prevented,1);assert.equal(event.returnValue,'');model.destroy();assert.equal(removed,added);assert.equal(model._beforeUnload,null);
  });
  await check('shared confirmation focuses cancel, traps both tab directions and restores original focus once',async()=>{
    const frames=[],nodes={};let active;const make=id=>nodes[id]={id,disabled:false,isConnected:true,getClientRects:()=>[1],getAttribute:()=>null,focus(){active=this;}};const origin=make('origin'),close=make('close'),cancel=make('qeli-confirm-cancel'),apply=make('apply');active=origin;
    const dialog=make('qeli-confirm-dialog');dialog.querySelectorAll=()=>[close,cancel,apply];dialog.contains=el=>[dialog,close,cancel,apply].includes(el);const document={readyState:'loading',addEventListener(){},getElementById:id=>nodes[id],get activeElement(){return active;}};
    const {model}=component('layout.html','app',{document,requestAnimationFrame:f=>frames.push(f)});model.$nextTick=f=>f();let answer;
    model.onConfirmRequest({title:'fixture',message:'fixture',resolve:v=>answer=v});assert.equal(active,cancel);let prevented=0;model.confirmTab({shiftKey:true,preventDefault(){prevented++;}});assert.equal(active,close);model.confirmTab({shiftKey:true,preventDefault(){}});assert.equal(active,apply);model.confirmTab({shiftKey:false,preventDefault(){}});assert.equal(active,close);assert.equal(prevented,1);
    origin.focus();model.confirmFocusIn({target:origin});assert.equal(active,cancel);model.confirmResolve(false);assert.equal(answer,false);frames.splice(0).forEach(f=>f());assert.equal(active,origin);
    const answers=[];model.onConfirmRequest({resolve:v=>answers.push(['old',v])});model.onConfirmRequest({resolve:v=>answers.push(['new',v])});model.confirmResolve(true);frames.splice(0).forEach(f=>f());assert.deepEqual(answers,[['old',false],['new',true]]);assert.equal(active,origin);
  });

  console.log(`Panel editor regressions: ${passed} passed`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
