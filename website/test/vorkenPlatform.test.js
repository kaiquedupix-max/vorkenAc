import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import cookieParser from 'cookie-parser';
import { PGlite } from '@electric-sql/pglite';
import { installVorkenPlatform,initVorkenPlatform } from '../vorkenPlatform.js';
import { hash,seal,addMonths,licensed,managesGuild,validDiscordInvite,serverSlug } from '../vorkenDomain.js';

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
    CREATE TABLE scan_findings(id BIGSERIAL PRIMARY KEY,analysis_id BIGINT,title TEXT,severity TEXT,artifact_type TEXT,artifact_value TEXT,evidence JSONB);`);
  await initVorkenPlatform(pool);
  const secret='test-session-secret-that-is-at-least-32-bytes';
  const oldEnv={SESSION_SECRET:process.env.SESSION_SECRET,MERCADO_PAGO_ACCESS_TOKEN:process.env.MERCADO_PAGO_ACCESS_TOKEN,MERCADO_PAGO_WEBHOOK_SECRET:process.env.MERCADO_PAGO_WEBHOOK_SECRET};
  process.env.SESSION_SECRET=secret;process.env.MERCADO_PAGO_ACCESS_TOKEN='test-only';process.env.MERCADO_PAGO_WEBHOOK_SECRET='test-webhook-secret';
  const nativeFetch=globalThis.fetch;
  let payment;
  globalThis.fetch=async(url,options)=>{
    if(String(url).startsWith('https://discord.com/api/'))return Response.json([{id:'123456789012345678',name:'Discord de teste',owner:true}]);
    if(String(url).includes('api.mercadopago.com/v1/payments/'))return Response.json(payment);
    if(String(url).includes('api.mercadopago.com/checkout/preferences'))return Response.json({id:'pref-test',init_point:'https://www.mercadopago.com.br/checkout/test'});
    return nativeFetch(url,options);
  };
  const learned=[],revoked=[];
  const app=express();app.use(express.json());app.use(cookieParser());
  const platform=installVorkenPlatform(app,{pool,publicUrl:'https://vorken.xyz',
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
  const request=async(path,{customerId=c1,owner=false,body,token,origin='https://vorken.xyz',method}={})=>{
    const r=await nativeFetch(url+'/api/vorken'+path,{method:method||(body?'POST':'GET'),headers:{'Content-Type':'application/json','X-Vorken-Request':'portal',
      Origin:origin,Cookie:'vorken_customer='+customerId,...(token?{Authorization:'Bearer '+token}:{}),...(owner?{'X-Test-Owner':'yes'}:{})},
      body:body?JSON.stringify(body):undefined});
    const text=await r.text();let data;try{data=JSON.parse(text);}catch{data=text;}return {status:r.status,data};
  };
  await t.test('customer cannot download another customer plugin; mutations require same origin',async()=>{
    assert.equal((await request('/servers/'+s2+'/plugin',{body:{}})).status,404);
    assert.equal((await request('/servers/'+s1,{method:'PATCH',body:{name:'New',discordInvite:'https://discord.gg/test'},origin:'https://evil.test'})).status,403);
    assert.equal((await request('/admin')).status,401);
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
  let commandId;
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
  });
  await t.test('join on a different server queues alert with reason and selected evidence, no ban command',async()=>{
    const r=await request('/plugin/sync',{token:token2,body:{events:[{id:crypto.randomUUID(),eventType:'player_join',steamId:event.steamId,playerName:'Player'}]}});
    assert.equal(r.status,200);
    const notice=(await pool.query("SELECT payload FROM vorken_notices WHERE kind='prior_ban'")).rows[0].payload;
    assert.equal(notice.bans[0].reason,'Proof checked');assert.equal(notice.bans[0].evidence.length,1);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM vorken_commands WHERE server_id=$1',[s2])).rows[0].n,0);
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
