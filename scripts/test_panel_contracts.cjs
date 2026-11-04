/* Audit regressions: run real panel components against non-mutating API fixtures. */
const assert = require('node:assert/strict');
const {component} = require('./test_panel_editors.cjs');
let passed = 0;
async function check(name, run) { await run(); passed++; console.log('PASS ' + name); }
async function main() {
  await check('import is split by default; full tunnel is an explicit independent choice', async () => {
    const bodies = [];
    const {model} = component('client.html','clientPage', {apiFetch:async (u,o)=>{bodies.push(JSON.parse(o.body));return {ok:true};}});
    model.refresh = async()=>{};
    model.openImport(); await model.doImport(); assert.equal(bodies[0].gateway,false);
    model.openImport(); model.importGateway=true; await model.doImport(); assert.equal(bodies[1].gateway,true);
    model.openImport(); assert.equal(model.importGateway,false);
  });
  await check('missing limit record cannot produce an unlimited expiry edit', async () => {
    let writes=0; const {model}=component('users.html','usersPage',{apiFetch:async()=>{writes++;return {ok:true};}});
    model.openUsage('missing',{},'limit'); await model.saveLimit(); assert.equal(writes,0); assert.notEqual(model.modal,'usage');
  });
  await check('limits use the user record even with unavailable or stale accounting', async () => {
    const bodies=[];const {model}=component('users.html','usersPage',{apiFetch:async(u,o)=>{bodies.push(JSON.parse(o.body));return {ok:true};}});
    model.loadUsage=()=>{}; model.users=[{username:'alice',data_limit_gb:50,expire_at:1800000000}];model.readErrors.usage='unavailable';
    model.openUsage('alice',{},'limit'); assert.equal(model.usageForm.data_limit_gb,50);
    model.usageForm.data_limit_gb=60; await model.saveLimit(); assert.deepEqual(bodies[0],{data_limit_gb:60});
    model.openUsage('alice',{},'limit'); model.usageForm.expire_date='';model.syncFromDate();await model.saveLimit();assert.deepEqual(bodies[1],{expire_at:null});
  });
  await check('days mean 24 hours; calendar input means local end of day; latest input wins', async () => {
    let body;const {model,context}=component('users.html','usersPage',{apiFetch:async(u,o)=>{body=JSON.parse(o.body);return {ok:true};}});
    model.loadUsage=()=>{};context.Date=class extends Date {static now(){return 1793790900000;}};
    const open=()=>model.openUsage('alice',{data_limit_gb:10,expire_at:1800000000},'limit');
    open();model.usageForm.expire_days=1;model.syncFromDays();await model.saveLimit();assert.deepEqual(body,{expire_at:1793790900+86400});
    open();model.usageForm.expire_days=2;model.syncFromDays();model.usageForm.expire_date='2026-12-01';model.syncFromDate();await model.saveLimit();
    assert.deepEqual(body,{expire_at:Math.floor(new Date('2026-12-01T23:59:59').getTime()/1000)});
    open();model.usageForm.expire_days=-1;model.syncFromDays();const previous=body;await model.saveLimit();assert.equal(body,previous);assert(model.modalError);
  });
  await check('preview and form save share payload; dormant values are not erased', async () => {
    const bodies=[];const {model}=component('client.html','clientPage',{apiFetch:async(u,o)=>{bodies.push([u,JSON.parse(o.body)]);return {ok:true,raw:'[qeli]\nserver=fixture.invalid:443\ngateway=false\n'};}});
    model.refresh=async()=>{};model.openCreate();model.form.server='fixture.invalid:443';
    Object.assign(model.form,{awg:false,jc:7,jmin:0,jmax:333,front:'none',proto:'tcp',quic:true});
    model.onClientTransportChange();assert.equal(model.form.quic,false);
    const before=JSON.stringify(model.form);
    await model.formToIni();await model.save();
    for(const key of ['jc','jmin','jmax','front','awg','quic'])assert.equal(bodies[0][1][key],bodies[1][1][key]);
    assert.equal(bodies[0][1].jmin,0);assert.equal(bodies[0][1].jc,7);assert.equal(JSON.stringify(model.form),before);
  });
  await check('late or failed preview cannot replace edited or reopened forms', async () => {
    let finish;const {model,context}=component('client.html','clientPage',{apiFetch:()=>new Promise(r=>finish=r)});
    model.openCreate();model.form.server='before';const pending=model.toggleRaw();model.form.server='after';
    finish({ok:true,raw:'old'});await pending;assert(!model.form.rawMode);assert.equal(model.form.server,'after');
    const another=model.toggleRaw();model.openCreate();finish({ok:true,raw:'old'});await another;assert(!model.form.rawMode);
    context.apiFetch=async()=>({ok:false,error:'preview rejected'});await model.toggleRaw();assert(!model.form.rawMode);assert(!model.formConverting);
  });
  await check('NDP and address-family round trips preserve draft choices without sending unsupported combinations', () => {
    const {model}=component('config.html','configPage');
    model.cfg={profiles:[{tun:{ip_mode:'dual'},routing:{ipv6:{mode:'route',ndp_proxy:'required',ndp_proxy_interface:'ens3',ndp_proxy_source:'fe80::1'},nat:{enabled:true}},dhcp:{enabled:true}}]};
    const p=model.cfg.profiles[0],original=JSON.stringify(p.routing.ipv6);
    p.routing.ipv6.mode='nat66';model.onIpv6RoutingModeChange(0);assert.equal(p.routing.ipv6.ndp_proxy,'off');
    p.routing.ipv6.mode='route';model.onIpv6RoutingModeChange(0);assert.equal(JSON.stringify(p.routing.ipv6),original);
    p.tun.ip_mode='ipv4';model.onIpModeChange(0);assert.equal(p.routing.ipv6.mode,'off');
    p.tun.ip_mode='dual';model.onIpModeChange(0);assert.equal(JSON.stringify(p.routing.ipv6),original);
    p.tun.ip_mode='ipv6';model.onIpModeChange(0);assert.equal(p.routing.nat.enabled,false);assert.equal(p.dhcp.enabled,false);
    p.tun.ip_mode='dual';model.onIpModeChange(0);assert(p.routing.nat.enabled);assert(p.dhcp.enabled);
    assert(!JSON.stringify(model.cfg).includes('networkDraft'));
  });
  console.log('Panel contract regressions: '+passed+' passed');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
