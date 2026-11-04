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
  await check('Quick Start accepts a server-approved same-port bind and rejects unavailable preview', async () => {
    let writes=0,previews=0;const {model,context}=component('quickstart.html','quickstartPage',{restartServer:async()=>true,
      apiFetch:async(u,o)=>{
        if(o?.method){writes++;return {ok:true,profile:{name:'plain',bind:{address:'192.0.2.10',port:8447,transport:'tcp'}}};}
        if(u.startsWith('api/config/quickstart/')){previews++;return {ok:true,profile:{name:'plain'}};}
        return {ok:true,revision:'r1',config:{profiles:[{name:'plain',bind:{address:'192.0.2.10',port:8447,transport:'tcp'}},{name:'other',bind:{address:'192.0.2.11',port:8447,transport:'tcp'}}]}};
      }});
    await model.quickStart(model.modes.find(m=>m.id==='plain'));assert.equal(previews,1);assert.equal(writes,1);
    context.apiFetch=async(u,o)=>u.startsWith('api/config/quickstart/')?{ok:false,error:'wildcard conflict'}:{ok:true,revision:'r1',config:{profiles:[]}};
    await model.quickStart(model.modes[0]);assert.equal(writes,1);assert.equal(model.qs.done,null);
  });
  await check('partial VPN block-list failure retains VPN snapshot while panel journal updates', async () => {
    const {model}=component('blocked.html','blockedPage',{apiFetch:async()=>({ok:true,vpn_available:false,vpn_error:'worker unavailable',blocked:{vpn:null,panel:[{ip:'192.0.2.1'}]}})});
    model.blocked.vpn=[{ip:'192.0.2.2',unblock_in_secs:90}];await model.load();
    assert.equal(model.blocked.vpn[0].ip,'192.0.2.2');assert.equal(model.blocked.panel[0].ip,'192.0.2.1');assert.match(model.error,/unavailable/);
  });
  await check('saving an explicit network mode releases rollback-only drafts', async () => {
    const {model}=component('config.html','configPage',{apiFetch:async()=>({ok:true,revision:'r2'})});
    model.loaded=true;model.revision='r1';model.view='form';
    model.cfg={profiles:[{routing:{ipv6:{mode:'route',ndp_proxy:'auto',ndp_proxy_interface:'ens3'}}}]};
    model._original=JSON.stringify(model.cfg);const p=model.cfg.profiles[0];p.routing.ipv6.mode='nat66';model.onIpv6RoutingModeChange(0);
    assert(model.suspendedNdp(0));await model.save();assert(!model.suspendedNdp(0));
    p.routing.ipv6.mode='route';model.onIpv6RoutingModeChange(0);assert.equal(p.routing.ipv6.ndp_proxy,'off');
  });
  await check('client distinguishes active, outdated, missing and stopped diagnostics without inventing zeroes', () => {
    const {model,context}=component('client.html','clientPage');const now=1793790900000;
    context.Date=class extends Date{static now(){return now;}};
    const profile={name:'fixture',connected:true,state:'up',diagnostics:{state:'running',updated_at_ms:now,stats:{tx_bytes:0},plan:{full_tunnel:false,mtu:1400}}};
    model.diagProfile=profile;assert.equal(model.displayState(profile),'up');assert.equal(model.diagBoolean('plan.full_tunnel'),'Disabled');
    assert.equal(model.diagBytes('stats.tx_bytes'),'0');assert.equal(model.diagBytes('stats.rx_bytes'),'—');assert.equal(model.diagBoolean('plan.kill_switch'),'—');
    profile.diagnostics.updated_at_ms-=16000;assert.equal(model.displayState(profile),'unknown');
    profile.connected=false;assert.equal(model.displayState(profile),'down');assert.match(model.snapshotLabel(profile),/Last session/);
    assert.equal(model.displayState({connected:true,state:'up'}),'connecting');
  });
  await check('outbound table has localized mobile labels and scoped stacked layout', () => {
    const {html}=component('client.html','clientPage');
    for(const label of ['Profile','Server','Mode','Status','Traffic and network','Actions'])assert(html.includes(':data-label="qeliT(\''+label+'\')"'));
    const css=require('node:fs').readFileSync(require('node:path').join(__dirname,'../qeli/web-assets/input.css'),'utf8');
    assert(css.includes('.client-profile-table tbody tr{display:block;'));
    assert(css.includes('.card>table.client-profile-table{min-width:0}'));
    assert(css.includes('.client-summary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))'));
  });
  await check('client diagnostics follow polls and late log responses cannot cross profiles', async () => {
    let finish;const finishes=[];const {model,context}=component('client.html','clientPage',{apiFetch:()=>new Promise(r=>{finish=r;finishes.push(r);})});
    const old=model.openDiagnostics({name:'old'}), latest=model.openDiagnostics({name:'new'});
    finishes[1]({ok:true,raw:'new log'});await latest;finishes[0]({ok:true,raw:'old log'});await old;
    assert.equal(model.logText,'new log');assert.equal(model.diagProfile.name,'new');
    context.apiFetch=async()=>({ok:true,profiles:[{name:'new',connected:true,diagnostics:{state:'retrying',reconnects:3}}]});
    await model.refresh();assert.equal(model.diagValue('reconnects'),3);
    context.apiFetch=()=>new Promise(r=>finish=r);const pending=model.loadClientLog();model.closeDiagnostics();finish({ok:true,raw:'obsolete'});await pending;assert.equal(model.logText,'new log');
    model.diagOpen=true;context.apiFetch=async()=>({ok:true,profiles:[]});await model.refresh();assert(!model.diagOpen);
  });
  await check('copy writes exactly the displayed fragment and handles denied clipboard access', async () => {
    let copied;const {model,context}=component('client.html','clientPage',{navigator:{clipboard:{writeText:async text=>{copied=text;}}}});
    model.diagOpen=true;model.diagProfile={name:'fixture'};model.logText='first\nsecond';
    await model.copyClientLog();assert.equal(copied,'first\nsecond');assert(!model.logCopying);assert.equal(model.logActionError,'');
    context.navigator.clipboard.writeText=async()=>{throw Error('denied');};
    await model.copyClientLog();assert.match(model.logActionError,/Could not copy/);assert.equal(model.logText,'first\nsecond');
    copied=null;model.logError='unavailable';await model.copyClientLog();assert.equal(copied,null);
  });
  await check('HTTP clipboard fallback restores focus and removes its temporary textarea on success or failure', async () => {
    let input,removed=0,focused=0,selected=0,works=true;
    const {model}=component('client.html','clientPage',{navigator:{},document:{
      readyState:'loading',addEventListener(){},activeElement:{focus(){focused++;}},
      body:{appendChild(value){input=value;}},createElement(){return {style:{},focus(){},select(){selected++;},remove(){removed++;}};},
      execCommand(command){assert.equal(command,'copy');return works;},
    }});
    model.diagOpen=true;model.diagProfile={name:'fixture'};model.logText='shown fragment';
    await model.copyClientLog();assert.equal(input.value,'shown fragment');assert.equal(selected,1);assert.equal(removed,1);assert.equal(focused,1);
    works=false;await model.copyClientLog();assert.equal(removed,2);assert.equal(focused,2);assert(model.logActionError);
  });
  await check('download saves the complete response, validates headers, and refuses HTTP errors and login pages', async () => {
    const full='line\n'.repeat(20000),saved=[];let response;
    const ok=()=>({ok:true,status:200,headers:{get:key=>key==='Content-Type'?'text/plain; charset=utf-8':'attachment; filename="fixture.log"'},blob:async()=>full});
    const {model,context}=component('client.html','clientPage',{AbortController,fetch:async()=>response});
    model.diagOpen=true;model.diagProfile={name:'fixture'};model.logText='only preview';
    model.saveLogBlob=(blob,name)=>saved.push([blob,name]);response=ok();await model.downloadFullLog();
    assert.deepEqual(saved,[[full,'fixture']]);assert(!model.logDownloading);
    for(const bad of [
      {ok:false,status:404,json:async()=>({error:'Client log not found'})},
      {ok:false,status:401},
      {ok:true,status:200,headers:{get:()=> 'text/html'},blob:async()=>'<html>login</html>'},
    ]){response=bad;await model.downloadFullLog();assert.equal(saved.length,1);assert(model.logActionError);assert(!model.logDownloading);}
    context.fetch=async()=>{throw Error('network unavailable');};await model.downloadFullLog();assert.equal(saved.length,1);assert.match(model.logActionError,/network/);
  });
  await check('closing diagnostics aborts a download and a late response cannot save another profile log', async () => {
    let finish,signal,saved=0;
    const {model,context}=component('client.html','clientPage',{AbortController,fetch:async(u,o)=>{signal=o.signal;return new Promise(r=>finish=r);}});
    model.saveLogBlob=()=>{saved++;};model.diagOpen=true;model.diagProfile={name:'old'};
    const pending=model.downloadFullLog();await model.downloadFullLog();model.closeDiagnostics();assert(signal.aborted);
    model.diagOpen=true;model.diagProfile={name:'new'};
    finish({ok:true});await pending;assert.equal(saved,0);assert(!model.logDownloading);assert.equal(model.logActionError,'');
  });
  await check('download links have a safe filename and object URLs are released after click and on failure', () => {
    let link,released=[],cleanup,fail=false;
    const {model}=component('client.html','clientPage',{URL:{createObjectURL:()=> 'blob:fixture',revokeObjectURL:url=>released.push(url)},
      setTimeout:fn=>{cleanup=fn;},document:{readyState:'loading',addEventListener(){},body:{appendChild(){}},
      createElement:()=>link={click(){if(fail)throw Error('click failed');},remove(){}}}});
    model.saveLogBlob('fixture','name/unsafe');assert.equal(link.download,'qeli-client-name_unsafe.log');assert.equal(released.length,0);
    cleanup();assert.deepEqual(released,['blob:fixture']);
    fail=true;assert.throws(()=>model.saveLogBlob('fixture','name'),/click failed/);assert.deepEqual(released,['blob:fixture','blob:fixture']);
  });
  console.log('Panel contract regressions: '+passed+' passed');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
