import test from 'node:test';
import assert from 'node:assert/strict';
import {createBattleMetricsClient, publicIp, captureConnectionEvidence} from '../battleMetrics.js';
import {projectReportPayloadForAdmin} from '../reportPayloadProjection.js';
const steam='76561198763925016', other='76561198000000001';
const player=(id,identifiers=[])=>({type:'player',id,attributes:{name:'Example'},relationships:{identifiers:{data:identifiers.map(id=>({type:'identifier',id}))}}});
const identifier=(id,type,value)=>({type:'identifier',id,attributes:{type,identifier:value}});
const json=data=>new Response(JSON.stringify(data),{headers:{'content-type':'application/json'}});
const report={steamAccounts:[{steamId64:steam}],connectionEvidence:{publicIp:'8.8.8.8'}};

test('disabled provider makes no network calls',async()=>{
 const client=createBattleMetricsClient({fetchImpl:()=>{throw new Error('unexpected network');}});
 assert.equal((await client.analyze(report,steam)).status,'not_configured');
});
test('public IP comes from socket unless the exact proxy topology is configured',()=>{
 assert.equal(publicIp('::ffff:8.8.8.8'),'8.8.8.8');
 for(const ip of ['127.0.0.1','10.0.0.2','172.16.1.2','192.168.0.5','100.64.0.1','::1','fc00::1','fe80::1','not-ip'])assert.equal(publicIp(ip),null);
 const req={socket:{remoteAddress:'::ffff:8.8.8.8'},headers:{'x-forwarded-for':'1.1.1.1'}};
 assert.equal(captureConnectionEvidence(req).publicIp,'8.8.8.8');
 assert.equal(captureConnectionEvidence(req,1).publicIp,'1.1.1.1');
 assert.equal(captureConnectionEvidence(req,2).publicIp,'8.8.8.8');
});
test('correlates exact attached identifiers and verifies bans belong to that player',async()=>{
 let calls=0;
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async url=>{
  calls++; const u=new URL(url);
  if(u.pathname==='/players')return json({data:[player('1',['s']),player('2',['s2','ip'])],included:[identifier('s','steamID',steam),identifier('s2','steamID',other),identifier('ip','ip','8.8.8.8')]});
  return json({data:[{type:'ban',id:'b1',attributes:{reason:'Reported reason',timestamp:'2026-01-01',expires:'2026-02-01'},relationships:{player:{data:{id:u.searchParams.get('filter[player]')}},server:{data:{id:'10'}}}},{type:'ban',id:'foreign',attributes:{reason:'Wrong player'},relationships:{player:{data:{id:'999'}}}}],included:[{type:'server',id:'10',attributes:{name:'Example server'}}]});
 }});
 const result=await client.analyze(report,steam);
 assert.equal(result.accounts.length,2);
 assert.equal(result.accounts.find(x=>x.playerId==='1').foundOnPc,true);
 const remote=result.accounts.find(x=>x.playerId==='2');
 assert.equal(remote.foundOnPc,false);assert.deepEqual(remote.steamIds,[other]);
 assert.equal(remote.bans.length,1);assert.equal(remote.bans[0].status,'expired');
 assert.equal(remote.bans[0].server,'Example server');
 const before=calls;assert.equal((await client.analyze(report,steam)).cached,true);assert.equal(calls,before);
 const projected=projectReportPayloadForAdmin({battleMetrics:result});
 assert.equal(projected.battleMetrics.accounts[1].bans[0].reason,'Reported reason');
});
test('unrelated included identifiers cannot establish an association',async()=>{
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async()=>json({data:[player('1')],included:[identifier('unattached','steamID',steam)]})});
 const result=await client.analyze({steamAccounts:[{steamId64:steam}]},steam);
 assert.equal(result.accounts.length,0);assert.equal(result.status,'identifiers_unavailable');
});
test('403 is inaccessible, never a clean result',async()=>{
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async()=>new Response('',{status:403})});
 assert.equal((await client.analyze(report,steam)).status,'forbidden');
});
test('429 stops further calls and honors cooldown across analyses',async()=>{
 let calls=0;
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async()=>{calls++;return new Response('',{status:429,headers:{'retry-after':'90'}});}});
 assert.equal((await client.analyze(report,steam)).status,'rate_limited');
 assert.equal((await client.analyze(report,other)).status,'rate_limited');assert.equal(calls,1);
});
test('saved player query keeps hidden identities separate from local accounts',async()=>{
 const client=createBattleMetricsClient({token:'test',queryId:'saved-query',minIntervalMs:0,fetchImpl:async url=>{
  const u=new URL(url);
  if(u.pathname==='/players')return json({data:[player('1',['s'])],included:[identifier('s','steamID',steam)]});
  if(u.pathname.includes('player-query'))return json({data:[{type:'playerQueryResult',attributes:{score:42},relationships:{player:{data:{type:'player',id:'2'}}}}]});
  return json({data:[]});
 }});
 const result=await client.analyze({steamAccounts:[{steamId64:steam}]},steam);
 const hidden=result.accounts.find(x=>x.playerId==='2');assert(hidden);assert.equal(hidden.foundOnPc,false);assert.deepEqual(hidden.steamIds,[]);assert.equal(hidden.associations[0].score,42);
});
test('request budget produces a partial result instead of unlimited enumeration',async()=>{
 const client=createBattleMetricsClient({token:'test',maxRequests:1,minIntervalMs:0,fetchImpl:async()=>json({data:[player('1',['s'])],included:[identifier('s','steamID',steam)]})});
 const result=await client.analyze(report,steam);assert.equal(result.status,'partial');assert.equal(result.truncated,true);
});

test('admin renderer escapes external content and rejects foreign source URLs',async()=>{
 const {readFile}=await import('node:fs/promises');const vm=await import('node:vm');
 const target={innerHTML:'',textContent:''};
 const context={window:{},document:{getElementById:()=>target},URL,Date};
 vm.runInNewContext(await readFile(new URL('../public/battle-metrics-ui.js',import.meta.url),'utf8'),context);
 context.window.renderBattleMetrics({status:'forbidden',accounts:[{name:'<img src=x onerror=alert(1)>',profileUrl:'https://evil.test/',steamIds:[],associations:[],bans:[{reason:'<script>bad</script>',url:'javascript:alert(1)'}]}]});
 assert(!target.innerHTML.includes('<script>'));assert(!target.innerHTML.includes('<img'));assert(!target.innerHTML.includes('href="https://evil.test'));
 assert(target.innerHTML.includes('Acesso negado'));assert(target.innerHTML.includes('&lt;script&gt;'));
});

test('official reverse identifier relationships and offset search pagination are supported',async()=>{
 const offsets=[];
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async url=>{
  const u=new URL(url);
  if(u.pathname==='/players'){
   const offset=u.searchParams.get('page[offset]');offsets.push(offset);
   const id=offset?'2':'1';
   const ident=identifier('s'+id,'steamID',steam);ident.relationships={player:{data:{type:'player',id}}};
   return json({data:[{type:'player',id,attributes:{name:'Example'}}],included:[ident],links:offset?{}:{next:'https://api.battlemetrics.com/players?page[offset]=50'}});
  }
  assert.equal(u.searchParams.get('filter[expired]'),'true');
  return json({data:[]});
 }});
 const result=await client.analyze({steamAccounts:[{steamId64:steam}]},steam);
 assert.deepEqual(offsets,[null,'50']);assert.equal(result.accounts.length,2);assert.equal(result.status,'ok');
});

test('reverse identifiers belonging to another player cannot establish a match',async()=>{
 const ident=identifier('s','steamID',steam);ident.relationships={player:{data:{type:'player',id:'999'}}};
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async()=>json({data:[{type:'player',id:'1',attributes:{}}],included:[ident]})});
 const result=await client.analyze({steamAccounts:[{steamId64:steam}]},steam);
 assert.equal(result.accounts.length,0);assert.equal(result.status,'identifiers_unavailable');
});

test('cache isolates local account evidence even when lookup seeds match',async()=>{
 const client=createBattleMetricsClient({token:'test',minIntervalMs:0,fetchImpl:async url=>
  new URL(url).pathname==='/players'
   ? json({data:[player('1',['s'])],included:[identifier('s','steamID',steam)]})
   : json({data:[]})});
 for(const foundOnPc of [false,true,false]){
  const result=await client.analyze({steamAccounts:foundOnPc?[{steamId64:steam}]:[]},steam);
  assert.equal(result.accounts[0].foundOnPc,foundOnPc);
 }
});
