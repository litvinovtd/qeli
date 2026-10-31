/* Run: node scripts/test_ndp_panel.js. Pure panel model, no server/network dependencies. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../qeli/src/web/templates/config.html'), 'utf8');
const script = html.match(/<script>\s*(function configPage\(\)[\s\S]*?)<\/script>/)[1];
const context = {document: {addEventListener() {}}, window: {}};
vm.createContext(context);
vm.runInContext(script, context);
const page = context.configPage();
page.cfg.profiles = [{}];
page.normalizeProfiles();
const policy = page.cfg.profiles[0].routing.ipv6;
assert.equal(policy.ndp_proxy, 'off');
assert.equal(policy.ndp_proxy_source, '');
assert.equal(policy.ndp_proxy_router, false);
assert.equal(policy.ndp_proxy_override, false);
assert.equal(policy.ndp_proxy_announce_interval_secs, 0);
for (const value of [0, 10, 60, 86400]) {
  policy.ndp_proxy_announce_interval_secs = value;
  assert.equal(page.ndpRefreshValid(0), true, `valid ${value}`);
}
for (const value of ['', null, undefined, NaN, Infinity, '60', -1, 1, 9, 10.5, 86401]) {
  policy.ndp_proxy_announce_interval_secs = value;
  assert.equal(page.ndpRefreshValid(0), false, `invalid ${value}`);
}
Object.assign(policy, {ndp_proxy:'required', ndp_proxy_source:'2001:db8::1', ndp_proxy_router:true,
  ndp_proxy_override:true, ndp_proxy_announce_interval_secs:60});
page.normalizeProfiles();
assert.equal(policy.ndp_proxy_source, '2001:db8::1');
assert.equal(policy.ndp_proxy_router, true);
assert.equal(policy.ndp_proxy_override, true);
assert.equal(policy.ndp_proxy_announce_interval_secs, 60);
for (const key of ['source','router','override','announce_interval_secs'])
  assert.ok(html.includes(`cfg.profiles[activeTab].routing.ipv6.ndp_proxy_${key}`));
assert.ok(html.includes('aria-describedby="ndp-refresh-help ndp-refresh-error"'));
assert.ok(html.includes('x-show="!ndpRefreshValid(activeTab)"'));
console.log('NDP panel defaults, preservation, inputs and interval validation: PASS');
