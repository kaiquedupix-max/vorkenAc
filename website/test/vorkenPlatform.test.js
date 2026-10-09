import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import cookieParser from 'cookie-parser';
import { PGlite } from '@electric-sql/pglite';
import { installVorkenPlatform,initVorkenPlatform,backfillLegacyVorkenBans,importLegacyVerificationBans } from '../vorkenPlatform.js';
import { hash,seal,addMonths,licensed,managesGuild,validDiscordInvite,serverSlug } from '../vorkenDomain.js';
import { canPublish,publicNotice,verificationEmbed,verificationSettings } from '../vorkenSettings.js';

test('verification instructions show tenant name, configurable rules and actual timeout policy',()=>{
  const embed=verificationEmbed({name:'Xtreme',verification_settings:{timeoutSeconds:600,rules:'Regra exclusiva Xtreme',banOnTimeout:false,banOnRefusal:false,banOnDisconnect:false}});
  assert(embed.title.includes('Xtreme'));assert(embed.description.includes('10 minutos'));assert(embed.description.includes('Regra exclusiva Xtreme'));
  assert(!embed.description.includes('Guerra Fria'));assert(!embed.description.includes('youtu'));assert(!embed.description.includes('banimento permanente'));
  assert(!verificationEmbed({name:'Other',verification_settings:{showRules:false}}).description.includes('PC estopado'));
});

test('Discord channel permissions respect member denies and public feeds omit private evidence',()=>{
  const guild='123456789012345678',member={user:{id:'999456789012345678'},roles:['staff']};
  const roles=[{id:guild,permissions:String(1024|2048|16384|65536)},{id:'staff',permissions:'0'}];
  assert(canPublish({type:0},guild,member,roles));
  assert(!canPublish({type:0,permission_overwrites:[{id:member.user.id,type:1,deny:'2048',allow:'0'}]},guild,member,roles));
  assert(!canPublish({type:2},guild,member,roles));
  const embed=publicNotice('public_ban',{playerName:'<@everyone>',steamId:'76561198000000001',serverName:'Xtreme',reason:'Prova revisada',evidence:'PRIVATE',code:'1234'});
  assert(!JSON.stringify(embed).includes('PRIVATE'));assert(!JSON.stringify(embed).includes('1234'));
});

test('calendar billing clamps month ends and preserves UTC time',()=>{
  assert.equal(addMonths('2026-01-31T12:00:00Z',1).toISOString(),'2026-02-28T12:00:00.000Z');
  assert.equal(addMonths('2024-02-29T12:00:00Z',12).toISOString(),'2025-02-28T12:00:00.000Z');
});
test('expired, suspended and revoked licenses cannot authorize a server',()=>{
  const e={status:'active',license_status:'active',license_until:'2026-11-01'};
  assert(licensed(e,new Date('2026-10-04')));assert(!licensed(e,new Date('2026-11-01')));
  assert(!licensed({...e,license_status:'revoked'},new Date('2026-10-04')));
  assert(!licensed({...e,status:'suspended'},new Date('2026-10-04')));
});
test('Discord guild ownership, invites and subdomain names are validated',()=>{
  assert(managesGuild({permissions:'32'}));assert(!managesGuild({permissions:'4'}));
  assert(validDiscordInvite('https://discord.gg/xtreme'));assert(!validDiscordInvite('https://discord.gg.evil.test/x'));
  assert.equal(serverSlug('Guerra Fria'),'guerrafria');assert.equal(serverSlug('ADMIN'),'servidor');
});

test('platform routes isolate customers, confirm decisions and activate payments idempotently',async t=>{
  const db=new PGlite();
  // PGlite supplies a real Postgres engine; advisory locks are no-ops in this single-connection harness.
  const pool={query:async(sql,args)=>{
    if(sql.includes('pg_advisory_'))return {rows:[]};
    if(!args&&sql.includes('CREATE TABLE')){await db.exec(sql);return {rows:[]};}
    return db.query(sql,args);
  },connect:async()=>({...pool,release(){}})};
  await db.exec(`CREATE TABLE analyses(id BIGSERIAL PRIMARY KEY,public_token TEXT,label TEXT,status TEXT DEFAULT 'waiting',
    expires_at TIMESTAMPTZ,processing_stage TEXT DEFAULT 'waiting',external_source TEXT,external_player_id TEXT,external_discord_user_id TEXT,
    external_verification_code TEXT,external_ticket_channel_id TEXT,external_decision TEXT,external_decision_at TIMESTAMPTZ,external_decision_result TEXT);
    CREATE TABLE scan_findings(id BIGSERIAL PRIMARY KEY,analysis_id BIGINT,title TEXT,severity TEXT,artifact_type TEXT,artifact_value TEXT,evidence JSONB);
    CREATE TABLE guerra_fria_verifications(id BIGSERIAL PRIMARY KEY,analysis_id BIGINT,player_name TEXT,administrator_id TEXT);`);
  await initVorkenPlatform(pool);
  const secret='test-session-secret-that-is-at-least-32-bytes';
  const oldEnv={SESSION_SECRET:process.env.SESSION_SECRET,MERCADO_PAGO_ACCESS_TOKEN:process.env.MERCADO_PAGO_ACCESS_TOKEN,MERCADO_PAGO_WEBHOOK_SECRET:process.env.MERCADO_PAGO_WEBHOOK_SECRET,VORKEN_DISCORD_BOT_TOKEN:process.env.VORKEN_DISCORD_BOT_TOKEN,VORKEN_DISCORD_CLIENT_ID:process.env.VORKEN_DISCORD_CLIENT_ID};
  process.env.VORKEN_DISCORD_BOT_TOKEN='test-only-bot';process.env.VORKEN_DISCORD_CLIENT_ID='999456789012345678';
  process.env.SESSION_SECRET=secret;process.env.MERCADO_PAGO_ACCESS_TOKEN='test-only';process.env.MERCADO_PAGO_WEBHOOK_SECRET='test-webhook-secret';
  const nativeFetch=globalThis.fetch;
  let payment;
  globalThis.fetch=async(url,options)=>{
    if(String(url).endsWith('/channels'))return Response.json([{id:'888456789012345678',name:'ban-feed',type:0},{id:'777456789012345678',name:'verificados',type:0}]);
    if(String(url).endsWith('/roles'))return Response.json([{id:'123456789012345678',permissions:'8'}]);
    if(String(url).includes('/members/'))return Response.json({user:{id:'999456789012345678'},roles:[]});
    if(String(url).startsWith('https://discord.com/api/'))return Response.json([{id:'123456789012345678',name:'Discord de teste',owner:true}]);
    if(String(url).includes('api.mercadopago.com/v1/payments/'))return Response.json(payment);
    if(String(url).includes('api.mercadopago.com/checkout/preferences'))return Response.json({id:'pref-test',init_point:'https://www.mercadopago.com.br/checkout/test'});
    return nativeFetch(url,options);
  };
  const learned=[],revoked=[],reportScopes=[];
  const sharedReport={analysis:{id:1,status:'completed'},report:{payload:{files:[{name:'inventory'}],browserHistorySignals:[{url:'history'}],uiCounts:{files:484}}},findings:[{id:1,severity:'critical',title:'Critical preserved'}],commonApps:[],relatedAnalyses:[]};
  const app=express();app.use(express.json());app.use(cookieParser());
  const platform=installVorkenPlatform(app,{pool,publicUrl:'https://vorken.xyz',
    loadRawAnalysisReport:async()=>sharedReport.report.payload,
    loadAnalysisReport:async(id,serverId)=>{reportScopes.push({id,serverId});return {...sharedReport,analysis:{...sharedReport.analysis,id}};},
    requireAdmin:(req,res,next)=>req.get('x-test-owner')==='yes'?next():res.sendStatus(401),
    learnAnalysisArtifacts:async(...args)=>learned.push(args),revokeLearnedTrustForFindings:async(...args)=>revoked.push(args)});
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  const url='http://127.0.0.1:'+server.address().port;
  t.after(async()=>{await new Promise(r=>server.close(r));await db.close();globalThis.fetch=nativeFetch;for(const[k,v]of Object.entries(oldEnv)){if(v===undefined)delete process.env[k];else process.env[k]=v;}});
  const c1=crypto.randomUUID(),c2=crypto.randomUUID(),s1=crypto.randomUUID(),s2=crypto.randomUUID();
  const token1=crypto.randomBytes(32).toString('base64url'),token2=crypto.randomBytes(32).toString('base64url');
  for(const[id,discordId]of[[c1,'123456789012345678'],[c2,'223456789012345678']]){
    await pool.query('INSERT INTO vorken_customers(id,discord_id,name) VALUES($1,$2,$3)',[id,discordId,'Cliente '+id]);
    await pool.query("INSERT INTO vorken_licenses(customer_id,plan_id,status,expires_at) VALUES($1,'mensal','active',NOW()+interval '1 month')",[id]);
    await pool.query("INSERT INTO vorken_logins(token_hash,customer_id,access_token,expires_at) VALUES($1,$2,$3,NOW()+interval '1 hour')",[hash(id),id,seal('test-access',secret)]);
    await pool.query('INSERT INTO vorken_guilds(id,customer_id,name) VALUES($1,$2,$3)',[discordId,id,'Guild '+id]);
  }
  for(const[id,c,g,token]of[[s1,c1,'123456789012345678',token1],[s2,c2,'223456789012345678',token2]])
    await pool.query('INSERT INTO vorken_servers(id,customer_id,guild_id,name,discord_invite,token_hash,slug) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,c,g,'Servidor '+id,'https://discord.gg/test',hash(token),'server-'+id]);
  const request=async(path,{customerId=c1,owner=false,body,token,origin='https://vorken.xyz',method,fetchSite}={})=>{
    const r=await nativeFetch(url+'/api/vorken'+path,{method:method||(body?'POST':'GET'),headers:{'Content-Type':'application/json','X-Vorken-Request':'portal',
      ...(origin?{Origin:origin}:{}),...(fetchSite?{'Sec-Fetch-Site':fetchSite}:{}),Cookie:'vorken_customer='+customerId,...(token?{Authorization:'Bearer '+token}:{}),...(owner?{'X-Test-Owner':'yes'}:{})},
      body:body?JSON.stringify(body):undefined});
    const text=await r.text();let data;try{data=JSON.parse(text);}catch{data=text;}return {status:r.status,data};
  };
  await t.test('customer cannot download another customer plugin; mutations require same origin',async()=>{
    assert.equal((await request('/servers/'+s2+'/plugin',{body:{}})).status,404);
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body:{name:'New',discordInvite:'https://discord.gg/test'},origin:'https://evil.test'})).status,403);
    assert.equal((await request('/admin')).status,401);
    const body={name:'New',discordInvite:'https://discord.gg/test'};
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body,origin:'https://www.vorken.xyz'})).status,200);
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body,origin:null,fetchSite:'same-origin'})).status,200);
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body,origin:null})).status,403);
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body,origin:'https://evil.test',fetchSite:'same-origin'})).status,403);
  });
  await t.test('personal invites bind Discord identity, scope roster/reports and revoke immediately',async()=>{
    const invited=await request('/servers/'+s1+'/team/invites',{body:{discordId:'223456789012345678'}});
    assert.equal(invited.status,201);const token=invited.data.url.split('convite=')[1];
    assert.equal((await request('/team/accept',{body:{token}})).status,403);
    assert.equal((await request('/team/accept',{customerId:c2,body:{token}})).status,200);
    assert.equal((await request('/team/accept',{customerId:c2,body:{token}})).status,403);
    assert.equal((await request('/operations/'+s1,{customerId:c2})).status,200);
    assert.equal((await request('/servers/'+s1+'/plugin',{customerId:c2,body:{}})).status,404);
    assert.equal((await request('/servers/'+s1+'/team',{customerId:c2})).status,404);
    const me=await request('/me',{customerId:c2});assert.equal(me.data.servers.find(s=>s.id===s1).owned,false);
    await request('/servers/'+s1+'/team/'+c2,{method:'DELETE'});
    assert.equal((await request('/operations/'+s1,{customerId:c2})).status,404);
    const revoked=await request('/servers/'+s1+'/team/invites',{body:{discordId:'223456789012345678'}});
    await request('/servers/'+s1+'/invites/'+revoked.data.id,{method:'DELETE'});
    assert.equal((await request('/team/accept',{customerId:c2,body:{token:revoked.data.url.split('convite=')[1]}})).status,403);
    const expired=await request('/servers/'+s1+'/team/invites',{body:{discordId:'223456789012345678'}});
    await pool.query("UPDATE vorken_invites SET expires_at=NOW()-interval '1 hour' WHERE id=$1",[expired.data.id]);
    assert.equal((await request('/team/accept',{customerId:c2,body:{token:expired.data.url.split('convite=')[1]}})).status,403);
  });
  await t.test('notification channels allow one shared channel, reject foreign IDs and sync Rust switches',async()=>{
    const settings={banChannelId:'888456789012345678',verifiedChannelId:'888456789012345678',discordBans:true,discordVerified:true,rustStarted:false,rustVerified:false,rustBans:true};
    assert.equal((await request('/servers/'+s1+'/settings',{method:'PATCH',body:{settings}})).status,200);
    assert.equal((await request('/servers/'+s1+'/settings',{customerId:c2})).status,404);
    assert.equal((await request('/servers/'+s1+'/settings',{method:'PATCH',body:{settings:{...settings,banChannelId:'666456789012345678'}}})).status,400);
    const sync=await request('/plugin/sync',{token:token1,body:{}});assert.equal(sync.data.notifications.rustStarted,false);assert.equal(sync.data.notifications.rustVerified,false);
    const verification={...verificationSettings(),rules:'Política personalizada Xtreme',timeoutSeconds:600,banOnRefusal:false,banOnDisconnect:false};
    assert.equal((await request('/servers/'+s1+'/settings',{method:'PATCH',body:{settings,verification}})).status,200);
    assert.equal((await request('/servers/'+s1+'/settings',{method:'PATCH',body:{settings,verification:{...verification,timeoutSeconds:65}}})).status,400);
    assert.equal((await request('/servers/'+s1+'/settings',{method:'PATCH',body:{settings,verification:{...verification,rules:'x'.repeat(2001)}}})).status,400);
    const policy=await request('/plugin/sync',{token:token1,body:{}});assert.equal(policy.data.verification.timeoutSeconds,600);assert.equal(policy.data.verification.banOnRefusal,false);
  });
  await t.test('online roster and panel telagem are scoped, deduplicated and reject stale data',async()=>{
    const steamId='76561198000000999';
    await request('/plugin/sync',{token:token1,body:{players:[{steamId,name:'Online player'},{steamId,name:'Online player'},{steamId:'invalid',name:'Invalid'}]}});
    const roster=await request('/operations/'+s1);
    assert.equal(roster.data.players.length,1);assert.equal(roster.data.players[0].name,'Online player');
    assert.equal((await request('/operations/'+s1,{customerId:c2})).status,404);
    assert.equal((await request('/admin/operations/'+s1)).status,401);
    assert.equal((await request('/admin/operations/'+s1,{owner:true})).data.players.length,1);
    const start=await request('/operations/'+s1+'/telagem',{body:{steamId}});assert.equal(start.status,200);
    assert.equal((await request('/operations/'+s1+'/telagem',{body:{steamId}})).status,409);
    await pool.query("UPDATE vorken_commands SET status='applied' WHERE id=$1",[start.data.commandId]);
    await pool.query("UPDATE vorken_servers SET players_updated_at=NOW()-interval '1 minute' WHERE id=$1",[s1]);
    assert.equal((await request('/operations/'+s1)).data.players.length,0);
    assert.equal((await request('/operations/'+s1+'/telagem',{body:{steamId}})).status,409);
    await request('/plugin/sync',{token:token1,body:{players:[]}});
    assert.equal((await request('/operations/'+s1)).data.players.length,0);
  });
  const sessionId=crypto.randomUUID(),analysisId=(await pool.query("INSERT INTO analyses(public_token,label,status,processing_stage,expires_at) VALUES('test-public','Test','completed','completed',NOW()+interval '8 hours') RETURNING id")).rows[0].id;
  await pool.query("INSERT INTO scan_findings(analysis_id,title,severity,artifact_type,artifact_value,evidence) VALUES($1,'Test evidence','review','file','test.exe','{}')",[analysisId]);
  const findingId=(await pool.query('SELECT id FROM scan_findings LIMIT 1')).rows[0].id;
  const event={id:crypto.randomUUID(),sessionId,eventType:'session_started',steamId:'76561198000000000',playerName:'Player',code:'1234',expiresAt:new Date(Date.now()+300000).toISOString()};
  await t.test('installation scopes events and accepts retries without duplicate sessions',async()=>{
    assert.equal((await request('/plugin/sync',{token:token1,body:{events:[event]}})).status,200);
    assert.equal((await request('/plugin/sync',{token:token1,body:{events:[event]}})).status,200);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_sessions')).rows[0].n,1);
    const foreign=await request('/plugin/sync',{token:token2,body:{events:[event]}});
    assert.equal(foreign.data.accepted.length,0);
    assert.equal((await request('/sessions/'+sessionId+'/report',{customerId:c2})).status,404);
  });
  await pool.query("UPDATE vorken_sessions SET status='redeemed',analysis_id=$2 WHERE id=$1",[sessionId,analysisId]);
  await t.test('customer and operations reuse the complete report only after server authorization',async()=>{
    const customer=await request('/sessions/'+sessionId+'/report');
    const operations=await request('/operations/'+s1+'/sessions/'+sessionId+'/report');
    const owner=await request('/admin/operations/'+s1+'/sessions/'+sessionId+'/report',{owner:true});
    assert.equal(customer.status,200);assert.equal(operations.status,200);assert.equal(owner.status,200);
    assert.deepEqual(customer.data.report,sharedReport.report);assert.deepEqual(customer.data.findings,sharedReport.findings);
    assert.deepEqual(operations.data,customer.data);assert.deepEqual(owner.data,customer.data);
    assert(reportScopes.every(scope=>scope.serverId===s1));
    const raw=await request('/sessions/'+sessionId+'/raw');
    assert.deepEqual(raw.data,sharedReport.report.payload);
    assert.deepEqual((await request('/operations/'+s1+'/sessions/'+sessionId+'/raw')).data,raw.data);
    assert.deepEqual((await request('/admin/operations/'+s1+'/sessions/'+sessionId+'/raw',{owner:true})).data,raw.data);
    assert.equal((await request('/sessions/'+sessionId+'/raw',{customerId:c2})).status,404);
    assert.equal((await request('/operations/'+s2+'/sessions/'+sessionId+'/raw',{customerId:c2})).status,404);
    const calls=reportScopes.length;
    assert.equal((await request('/sessions/'+sessionId+'/report',{customerId:c2})).status,404);
    assert.equal((await request('/operations/'+s2+'/sessions/'+sessionId+'/report',{customerId:c2})).status,404);
    assert.equal(reportScopes.length,calls);
  });
  let commandId;
  await t.test('ended report requires an updated plugin and preserves ended state on failure',async()=>{
    await pool.query("UPDATE vorken_sessions SET status='ended' WHERE id=$1",[sessionId]);
    const old=await request('/sessions/'+sessionId+'/decision',{body:{decision:'approve'}});
    assert.equal(old.status,409);assert.match(old.data.message,/2.0.7/);
    await pool.query("UPDATE vorken_servers SET plugin_version='2.0.7' WHERE id=$1",[s1]);
    const newer=crypto.randomUUID();
    await pool.query("INSERT INTO vorken_sessions(id,server_id,steam_id,player_name,code,status,expires_at) SELECT $1,server_id,steam_id,player_name,'9876','pending',NOW()+interval '5 minutes' FROM vorken_sessions WHERE id=$2",[newer,sessionId]);
    assert.equal((await request('/sessions/'+sessionId+'/decision',{body:{decision:'approve'}})).status,409);
    await pool.query("DELETE FROM vorken_sessions WHERE id=$1",[newer]);
    assert.equal((await request('/sessions/'+sessionId+'/decision',{customerId:c2,body:{decision:'approve'}})).status,404);
    const result=await request('/sessions/'+sessionId+'/decision',{body:{decision:'approve'}});
    assert.equal(result.status,200);
    const sync=await request('/plugin/sync',{token:token1,body:{version:'2.0.7'}});
    assert.equal(sync.data.commands.find(c=>c.id===result.data.commandId).detachedSession,true);
    await request('/plugin/sync',{token:token1,body:{version:'2.0.7',receipts:[{id:result.data.commandId,ok:false,result:'New session on Rust'}]}});
    assert.equal((await pool.query('SELECT status FROM vorken_sessions WHERE id=$1',[sessionId])).rows[0].status,'ended');
    assert.equal((await pool.query('SELECT external_decision FROM analyses WHERE id=$1',[analysisId])).rows[0].external_decision,null);
  });
  await t.test('ban needs real selected proof and is not applied before plugin acknowledgement',async()=>{
    assert.equal((await request('/sessions/'+sessionId+'/decision',{body:{decision:'deny',reason:'Cheat',evidenceIds:[]}})).status,400);
    assert.equal((await request('/sessions/'+sessionId+'/decision',{body:{decision:'deny',reason:'Cheat',evidenceIds:[999999]}})).status,400);
    const r=await request('/sessions/'+sessionId+'/decision',{body:{decision:'deny',reason:'Proof checked',evidenceIds:[Number(findingId)]}});
    assert.equal(r.status,200);commandId=r.data.commandId;
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_bans')).rows[0].n,0);
    assert.equal((await request('/sessions/'+sessionId+'/decision',{body:{decision:'approve'}})).status,409);
  });
  await t.test('wrong installation cannot acknowledge commands; confirmed bans create a shared proof record',async()=>{
    await request('/plugin/sync',{token:token2,body:{receipts:[{id:commandId,ok:true,result:'Forged'}]}});
    assert.equal((await pool.query('SELECT status FROM vorken_commands WHERE id=$1',[commandId])).rows[0].status,'pending');
    const r=await request('/plugin/sync',{token:token1,body:{receipts:[{id:commandId,ok:true,result:'Ban confirmed'}]}});
    assert.equal(r.status,200);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_bans')).rows[0].n,1);
    await request('/plugin/sync',{token:token1,body:{receipts:[{id:commandId,ok:true,result:'Retry'}]}});
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_bans')).rows[0].n,1);assert.equal(revoked.length,1);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM vorken_notices WHERE kind='public_ban'")).rows[0].n,1);
    const invited=await request('/servers/'+s1+'/team/invites',{body:{discordId:'223456789012345678'}});
    await request('/team/accept',{customerId:c2,body:{token:invited.data.url.split('convite=')[1]}});
    const report=await request('/sessions/'+event.sessionId+'/report',{customerId:c2});assert.equal(report.status,200);assert.equal(report.data.findings.length,1);
    assert.equal((await request('/operations/'+s1+'/sessions/'+event.sessionId+'/report',{customerId:c2})).status,200);
    await request('/servers/'+s1+'/team/'+c2,{method:'DELETE'});
    assert.equal((await request('/sessions/'+event.sessionId+'/report',{customerId:c2})).status,404);
    assert.equal((await request('/operations/'+s1+'/sessions/'+event.sessionId+'/report',{customerId:c2})).status,404);
  });
  await t.test('public ban page renders confirmed bans without private proofs or administrator data',async()=>{
    const r=await nativeFetch(url+'/banimentos');assert.equal(r.status,200);const html=await r.text();
    assert.match(html,/Proof checked/);assert.match(html,/steamcommunity.com\/profiles/);
    assert(!html.includes('Critical preserved'));assert(!html.includes('trusted_ids'));assert(!html.includes(c1));
  });
  await t.test('join on a different server queues alert with reason and selected evidence, no ban command',async()=>{
    const r=await request('/plugin/sync',{token:token2,body:{events:[{id:crypto.randomUUID(),eventType:'player_join',steamId:event.steamId,playerName:'Player'}]}});
    assert.equal(r.status,200);
    const notice=(await pool.query("SELECT payload FROM vorken_notices WHERE kind='prior_ban'")).rows[0].payload;
    assert.equal(notice.bans[0].reason,'Proof checked');assert.equal(notice.bans[0].evidence.length,1);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_commands WHERE server_id=$1',[s2])).rows[0].n,0);
  });
  await t.test('prior ban proofs belong to the destination team; general audit is owner only',async()=>{
    const n=(await pool.query("SELECT id FROM vorken_notices WHERE kind='prior_ban' LIMIT 1")).rows[0];
    assert.equal((await request('/alerts/'+n.id)).status,404);
    const allowed=await request('/alerts/'+n.id,{customerId:c2});assert.equal(allowed.status,200);assert.equal(allowed.data.serverId,s2);
    assert.equal((await request('/admin/bans')).status,401);
    const audit=await request('/admin/bans',{owner:true});assert.equal(audit.status,200);assert.equal(audit.data.bans[0].reason,'Proof checked');
    assert.equal((await request('/admin/bans?q=no-such-player',{owner:true})).data.bans.length,0);
  });
  await t.test('local prior-ban action enters the audit only after Rust acknowledgement and cannot duplicate',async()=>{
    const n=(await pool.query("SELECT * FROM vorken_notices WHERE kind='prior_ban' LIMIT 1")).rows[0];
    const commandId=await platform.queue(pool,s2,'ban_prior',event.steamId,'223456789012345678|Administrador Xtreme',null,'Provas do servidor de origem revisadas');
    await pool.query('UPDATE vorken_notices SET payload=$2 WHERE id=$1',[n.id,JSON.stringify({...n.payload,commandId})]);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_bans WHERE command_id=$1',[commandId])).rows[0].n,0);
    for(let i=0;i<2;i++)assert.equal((await request('/plugin/sync',{token:token2,body:{receipts:[{id:commandId,ok:true,result:'Banimento aplicado'}]}})).status,200);
    const audit=await request('/admin/bans',{owner:true});assert.equal(audit.status,200);
    const ban=audit.data.bans.find(b=>b.command_id===commandId);assert.equal(ban.administrator,'Administrador Xtreme');assert.equal(ban.evidence[0].reason,'Proof checked');
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_bans WHERE command_id=$1',[commandId])).rows[0].n,1);
  });
  await t.test('historical confirmed Vorken bans import once and exclude unconfirmed analyses',async()=>{
    await db.exec("ALTER TABLE analyses ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW(); CREATE TABLE evidence_packages(id BIGSERIAL,analysis_id BIGINT,reason TEXT,findings JSONB);");
    await pool.query('UPDATE vorken_servers SET guild_id=$1 WHERE id=$2',['1499084540356853912',s1]).catch(async()=>{
      await pool.query('INSERT INTO vorken_guilds(id,customer_id,name) VALUES($1,$2,$3)',['1499084540356853912',c1,'Guerra Fria']);
      await pool.query('UPDATE vorken_servers SET guild_id=$1 WHERE id=$2',['1499084540356853912',s1]);
    });
    const legacy=(await pool.query("INSERT INTO analyses(external_source,external_player_id,external_decision) VALUES('guerra_fria','76561198000000009','deny') RETURNING id")).rows[0];
    await pool.query('INSERT INTO evidence_packages(analysis_id,reason,findings) VALUES($1,$2,$3)',[legacy.id,'Motivo histórico',JSON.stringify([{title:'Prova histórica'}])]);
    await pool.query("INSERT INTO analyses(external_source,external_player_id) VALUES('guerra_fria','76561198000000008')");
    assert.equal(await backfillLegacyVorkenBans(pool),1);assert.equal(await backfillLegacyVorkenBans(pool),0);
    const imported=(await pool.query('SELECT * FROM vorken_bans WHERE legacy_analysis_id=$1',[legacy.id])).rows[0];
    assert.equal(imported.reason,'Motivo histórico');assert.equal(imported.evidence[0].title,'Prova histórica');
  });
  await t.test('legacy policy bans preserve disconnect reasons and subsequent unbans idempotently',async()=>{
    const record={id:692,action:'BAN',steam_id:'76561198000000020',player_name:'Policy player',reason:'Desconectou durante a verificacao administrativa.',admin_id:'SYSTEM',admin_name:'Sistema de Verificação',created_at:'2026-09-30T12:00:00Z',latest_action:'BAN'};
    const released={...record,id:708,steam_id:'76561198000000021',latest_action:'DESBANIR'};
    assert.equal(await importLegacyVerificationBans(pool,[record,released,{...record,id:709,admin_name:'Moderator',admin_id:'123'}]),2);
    assert.equal(await importLegacyVerificationBans(pool,[record,released]),0);
    const rows=(await pool.query("SELECT * FROM vorken_bans WHERE legacy_source='guerra_fria_verification_policy' ORDER BY legacy_record_id")).rows;
    assert.equal(rows[0].reason,record.reason);assert.equal(rows[0].administrator_name,record.admin_name);assert.equal(rows[0].active,true);assert.equal(rows[1].active,false);
    assert.equal(rows[0].evidence[0].evidence.legacyRecordId,692);
  });
  await t.test('license revocation stops commands and new sessions without disabling cleanup',async()=>{
    await request('/admin/customers/'+c1+'/license',{owner:true,body:{action:'revoke'}});
    const r=await request('/plugin/sync',{token:token1,body:{events:[{...event,id:crypto.randomUUID(),sessionId:crypto.randomUUID(),code:'5555'}]}});
    assert.equal(r.data.active,false);assert.equal(r.data.commands.length,0);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_sessions')).rows[0].n,1);
    assert.equal((await request('/servers/'+s1+'/plugin',{body:{}})).status,403);
  });
  await t.test('signed Mercado Pago payment validates price and cannot grant twice',async()=>{
    const checkout=await request('/checkout',{body:{planId:'trimestral'}});assert.equal(checkout.status,200);
    const order=(await pool.query('SELECT * FROM vorken_orders LIMIT 1')).rows[0];
    assert.equal(order.price_cents,13500);
    payment={id:991,external_reference:order.id,status:'approved',transaction_amount:135,currency_id:'BRL',live_mode:true};
    const signature=crypto.createHmac('sha256','test-webhook-secret').update('id:991;request-id:test-request;ts:1704908010;').digest('hex');
    const send=async(sig)=>nativeFetch(url+'/api/vorken/payments/webhook?data.id=991',{method:'POST',headers:{'Content-Type':'application/json','x-request-id':'test-request','x-signature':'ts=1704908010,v1='+sig},body:JSON.stringify({type:'payment'})});
    assert.equal((await send('bad')).status,401);
    payment.transaction_amount=1;assert.equal((await send(signature)).status,400);
    payment.transaction_amount=135;assert.equal((await send(signature)).status,200);
    const before=(await platform.entitlement(c1)).license_until;
    assert.equal((await send(signature)).status,200);
    assert.equal(new Date((await platform.entitlement(c1)).license_until).getTime(),new Date(before).getTime());
    payment.status='refunded';assert.equal((await send(signature)).status,200);
    assert.equal((await platform.entitlement(c1)).license_status,'suspended');
  });
});
