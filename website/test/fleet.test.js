import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {PGlite} from '@electric-sql/pglite';
import {initFleetDb, installFleet, normalizePolicy, associationMembers, clientReportVisibility} from '../serverFleet.js';

test('association policy validates integers and only follows the directly shared team', () => {
  const player='76561198000000001', teammate='76561198000000002', unrelated='76561198000000003';
  assert.deepEqual(associationMembers(player,[[player,teammate],[teammate,unrelated],[player,teammate,'bad']]),[teammate]);
  assert.deepEqual(normalizePolicy({associationEnabled:true,associationDays:14,notifyChat:false}),{associationEnabled:true,associationDays:14,notifyChat:false});
  for(const value of [0,366,1.5,'',true,null]) assert.throws(()=>normalizePolicy({associationEnabled:true,associationDays:value,notifyChat:true}));
});

test('fleet end-to-end: quotas, tenant isolation, evidence, retries, association, expiry and unban', async t => {
  const db = new PGlite();
  await db.exec(`CREATE TABLE analyses(id BIGSERIAL PRIMARY KEY,status TEXT); CREATE TABLE scan_findings(id BIGSERIAL PRIMARY KEY,analysis_id BIGINT REFERENCES analyses(id),title TEXT,severity TEXT,artifact_type TEXT,artifact_value TEXT); INSERT INTO analyses(status) VALUES('completed'),('pending'); INSERT INTO scan_findings(analysis_id,title) VALUES(1,'Prova selecionada'),(2,'Outra análise'),(1,'Não selecionada');`);
  let lock=Promise.resolve();
  const pool={
    query:async(sql,params)=>!params&&sql.includes(';')?(await db.exec(sql)).at(-1):db.query(sql,params),
    connect:async()=>{const previous=lock;let release;lock=new Promise(resolve=>release=resolve);await previous;return{query:(sql,params)=>db.query(sql,params),release};}
  };
  await initFleetDb(pool);
  await initFleetDb(pool); // Repeated startup must preserve existing tables.
  const app=express();app.use(express.json());
  installFleet(app,{pool,requireAdmin:(req,res,next)=>req.headers['x-test-owner']==='yes'?next():res.status(401).json({message:'Unauthorized'})});
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));await db.close();});
  const base=`http://127.0.0.1:${server.address().port}`;
  async function api(url,body,method='POST',token){
    const res=await fetch(base+url,{method:body===undefined?'GET':method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{'x-test-owner':'yes'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
    return {status:res.status,data:await res.json()};
  }
  const unauthorized=await fetch(base+'/api/admin/fleet');assert.equal(unauthorized.status,401);
  const a=(await api('/api/admin/fleet/clients',{name:'Cliente A',serverLimit:2})).data.client;
  const b=(await api('/api/admin/fleet/clients',{name:'Cliente B',serverLimit:1})).data.client;
  const s1=(await api('/api/admin/fleet/servers',{clientId:a.id,name:'Rust A1'})).data;
  const s2=(await api('/api/admin/fleet/servers',{clientId:a.id,name:'Rust A2'})).data;
  const other=(await api('/api/admin/fleet/servers',{clientId:b.id,name:'Rust B'})).data;
  assert.equal((await api('/api/admin/fleet/servers',{clientId:a.id,name:'Rust A3'})).status,409);
  assert.equal((await api('/api/admin/fleet/clients/'+a.id,{serverLimit:1},'PATCH')).status,409);
  assert.equal((await api('/api/admin/fleet/clients/'+a.id,{serverLimit:3},'PATCH')).status,200);
  const s3=(await api('/api/admin/fleet/servers',{clientId:a.id,name:'Rust A3'})).data;
  const completed={status:'completed',client_report_released:false,fleet_server_id:s1.server.id};
  assert.deepEqual(await clientReportVisibility(pool,completed),{released:false,automatic:false});
  assert.equal((await api('/api/admin/fleet/servers/'+s1.server.id,{reportVisibility:'automatic'},'PATCH')).status,200);
  assert.deepEqual(await clientReportVisibility(pool,completed),{released:true,automatic:true});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,fleet_server_id:s2.server.id}),{released:false,automatic:false});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,fleet_server_id:other.server.id}),{released:false,automatic:false});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,status:'processing'}),{released:false,automatic:false});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,fleet_server_id:null}),{released:false,automatic:false});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,fleet_server_id:null,client_report_released:true}),{released:true,automatic:false});
  assert.equal((await api('/api/admin/fleet/servers/'+s1.server.id,{reportVisibility:'invalid'},'PATCH')).status,400);
  assert.equal((await api('/api/admin/fleet/servers/99999',{reportVisibility:'automatic'},'PATCH')).status,404);
  const unauthorizedPolicy=await fetch(base+'/api/admin/fleet/servers/'+s1.server.id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reportVisibility:'manual'})});
  assert.equal(unauthorizedPolicy.status,401);
  const configured=(await api('/api/admin/fleet')).data.servers;
  assert.equal(configured.find(s=>s.id===s1.server.id).report_visibility,'automatic');
  assert.equal((await api('/api/admin/fleet/servers/'+s1.server.id,{reportVisibility:'manual'},'PATCH')).status,200);
  assert.deepEqual(await clientReportVisibility(pool,completed),{released:false,automatic:false});
  assert.deepEqual(await clientReportVisibility(pool,{...completed,client_report_released:true}),{released:true,automatic:false});
  const stored=(await db.query('SELECT token_hash FROM fleet_servers WHERE id=$1',[s1.server.id])).rows[0];
  assert.notEqual(stored.token_hash,s1.token);
  const player='76561198000000001',mate='76561198000000002',third='76561198000000003';
  const sync=(token,body={})=>api('/api/fleet/sync',{teams:[[player,mate],[mate,third]],events:[],notificationCursor:0,appliedRevision:0,...body},'POST',token);
  assert.equal((await sync('a'.repeat(64))).status,401);
  await sync(s1.token);
  const ban={clientId:a.id,serverId:s1.server.id,analysisId:1,evidenceIds:[1],steamId:player,reason:'Teste de moderação'};
  assert.equal((await api('/api/admin/fleet/bans',{...ban,evidenceIds:[2]})).status,400);
  assert.equal((await api('/api/admin/fleet/bans',{...ban,serverId:other.server.id})).status,400);
  assert.equal((await api('/api/admin/fleet/bans',{...ban,serverId:s2.server.id})).status,409);
  const created=await api('/api/admin/fleet/bans',ban);assert.equal(created.status,201);assert.equal(created.data.created,2);
  const banId=(await db.query("SELECT id FROM fleet_bans WHERE kind='direct' LIMIT 1")).rows[0].id;
  const audit=await api('/api/admin/fleet/bans/'+banId+'/evidence');
  assert.deepEqual(audit.data.evidence.map(f=>Number(f.id)),[1]);
  assert.equal(JSON.stringify(audit.data).includes('Não selecionada'),false);
  assert.equal((await api('/api/admin/fleet/bans',ban)).data.created,0);
  const one=(await sync(s1.token)).data,two=(await sync(s2.token)).data,three=(await sync(s3.token)).data;
  for(const result of [one,two,three]){
    assert.deepEqual(result.bans.map(x=>x.steam_id).sort(),[player,mate].sort());
    assert.equal(result.bans.find(x=>x.steam_id===player).expires_at,null);
    const expiry=new Date(result.bans.find(x=>x.steam_id===mate).expires_at).getTime();
    assert.ok(Math.abs(expiry-Date.now()-7*86400000)<10000);
    assert.equal(result.notifications.length,2);
  }
  assert.equal((await sync(other.token)).data.bans.length,0);
  const acknowledged=await sync(s1.token,{appliedRevision:one.revision,notificationCursor:Number(one.notifications.at(-1).id)});
  assert.equal(acknowledged.data.notifications.length,0);
  let fleet=(await api('/api/admin/fleet')).data;
  assert.equal(Number(fleet.servers.find(s=>s.id===s1.server.id).applied_revision),one.revision);
  const event={id:'test-native-event-0001',type:'ban',steamId:third,reason:'Ban local',team:[third,mate],expiry:-1};
  await sync(s2.token,{events:[event]});await sync(s2.token,{events:[event]});
  assert.equal((await db.query('SELECT COUNT(*)::integer AS n FROM fleet_bans WHERE steam_id=$1 AND kind=$2',[third,'direct'])).rows[0].n,1);
  const policy=await api('/api/admin/fleet/clients/'+a.id,{associationEnabled:true,associationDays:14,notifyChat:false},'PATCH');assert.equal(policy.status,200);
  const fourth='76561198000000004',fifth='76561198000000005';
  const afterPolicy=(await sync(s1.token,{events:[{id:'test-native-event-0002',type:'ban',steamId:fourth,reason:'Novo prazo',team:[fourth,fifth]}]})).data;
  assert.ok(Math.abs(new Date(afterPolicy.bans.find(x=>x.steam_id===fifth).expires_at).getTime()-Date.now()-14*86400000)<10000);
  assert.equal(afterPolicy.notifications.some(n=>n.message.includes(fifth)),false);
  await db.query("UPDATE fleet_bans SET expires_at=NOW()-INTERVAL '1 second' WHERE kind='association'");
  const expired=(await sync(s3.token)).data;
  assert.equal(expired.bans.some(x=>x.steam_id===mate||x.steam_id===fifth),false);
  assert.equal(expired.bans.some(x=>x.steam_id===player),true);
  await api('/api/admin/fleet/unban',{clientId:a.id,steamId:player});
  for(const s of [s1,s2,s3])assert.equal((await sync(s.token)).data.bans.some(x=>x.steam_id===player),false);
  await sync(s2.token,{events:[{id:'test-native-unban-0003',type:'unban',steamId:third}]});
  assert.equal((await sync(s1.token)).data.bans.some(x=>x.steam_id===third),false);
  fleet=(await api('/api/admin/fleet')).data;
  assert.equal(JSON.stringify(fleet).includes(s1.token),false);
  const listed=(await api('/api/admin/fleet/bans?clientId='+b.id)).data;assert.equal(listed.bans.length,0);
});
