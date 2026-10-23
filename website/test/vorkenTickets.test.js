import test from 'node:test';
import assert from 'node:assert/strict';
import {createTicketQueue,ensureTicketIntro} from '../vorkenTickets.js';
const botId='bot',sessionId='session-1';
const intro=(id,owner=botId,prefix='vorken_ticket_lang',session=sessionId)=>({id,author:{id:owner},components:[{components:[{customId:prefix+':pt:'+session}]}]});
function fixture(initial=[],failSave=false){
 const records=new Map(initial.map(m=>[m.id,m]));let sent=0,saved=null;
 for(const m of records.values())m.delete=async()=>records.delete(m.id);
 const ticket={messages:{fetch:async query=>{await Promise.resolve();if(typeof query==='string'){const m=records.get(query);if(!m)throw Object.assign(Error('missing'),{code:10008});return m;}return new Map(records);}},send:async payload=>{assert.equal(payload.enforceNonce,true);assert.equal(payload.nonce.length,24);sent++;const m=intro(String(100+sent));m.delete=async()=>records.delete(m.id);records.set(m.id,m);return m;}};
 const run=()=>ensureTicketIntro({ticket,session:{id:sessionId,ticket_message_id:saved},botId,payload:{embeds:[]},save:async id=>{if(failSave){failSave=false;throw Error('database failed');}saved=id;}});
 return {run,records,get sent(){return sent;},get saved(){return saved;}};
}
function lockingPool(){
 const locks=new Map();let releases=0;
 return {get releases(){return releases;},connect:async()=>{let unlock;return {query:async(sql,[key])=>{if(sql.includes('pg_advisory_lock(')){const previous=locks.get(key)||Promise.resolve();const held=new Promise(resolve=>{unlock=resolve;});locks.set(key,held);await previous;}else unlock?.();return {rows:[]};},release(){releases++;}};}};
}

test('simultaneous message handler and worker share one ticket operation and one intro',async()=>{
 const pool=lockingPool(),f=fixture();let operations=0;
 const ensure=createTicketQueue(pool,async()=>{operations++;return f.run();});
 const results=await Promise.all(Array.from({length:20},()=>ensure(sessionId)));
 assert.equal(operations,1);assert.equal(f.sent,1);assert(results.every(r=>r.id===results[0].id));assert.equal(pool.releases,1);
});

test('different bot instances serialize by Postgres lock and reuse the intro on retries',async()=>{
 const pool=lockingPool(),f=fixture(),one=createTicketQueue(pool,f.run),two=createTicketQueue(pool,f.run);
 const results=await Promise.all([one(sessionId),two(sessionId)]);assert.equal(f.sent,1);assert.equal(results[0].id,results[1].id);
 await one(sessionId);assert.equal(f.sent,1);assert.equal(pool.releases,3);
});

test('existing duplicate introductions consolidate without deleting progress, another session or another bot',async()=>{
 const f=fixture([intro('12'),intro('11'),intro('13',botId,'vorken_status_lang'),intro('14','other'),intro('15',botId,'vorken_ticket_lang','another-session')]);
 await f.run();assert.equal(f.saved,'11');assert.equal(f.sent,0);assert.deepEqual([...f.records.keys()],['11','13','14','15']);
});

test('failed database save after Discord send recovers the same message instead of sending twice',async()=>{
 const f=fixture([],true),pool=lockingPool(),ensure=createTicketQueue(pool,f.run);
 await assert.rejects(ensure(sessionId),/database failed/);assert.equal(f.saved,null);
 await ensure(sessionId);assert.equal(f.sent,1);assert.equal(f.saved,'101');assert.equal(pool.releases,2);
});
