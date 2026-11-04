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
  console.log('Panel contract regressions: '+passed+' passed');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
