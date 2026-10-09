import crypto from 'node:crypto';

export function createTicketQueue(pool,work){
 const pending=new Map();
 return function ensure(sessionId){
  if(pending.has(sessionId))return pending.get(sessionId);
  const job=(async()=>{const db=await pool.connect();let locked=false;try{
   await db.query('SELECT pg_advisory_lock(hashtextextended($1,0))',['vorken-ticket:'+sessionId]);locked=true;
   return await work(sessionId,db);
  }finally{if(locked)await db.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',['vorken-ticket:'+sessionId]).catch(()=>{});db.release();}})();
  pending.set(sessionId,job);job.finally(()=>pending.delete(sessionId)).catch(()=>{});return job;
 };
}

export function isTicketIntro(message,botId,sessionId){
 return message?.author?.id===botId&&message.components?.some(row=>row.components?.some(button=>{
  const id=button.customId||button.custom_id||'';return ['pt','en','es'].some(lang=>id==='vorken_ticket_lang:'+lang+':'+sessionId);
 }));
}

export async function ensureTicketIntro({ticket,session,botId,payload,save}){
 let current=session.ticket_message_id?await ticket.messages.fetch(session.ticket_message_id).catch(error=>{if(error.code===10008)return null;throw error;}):null;
 if(!isTicketIntro(current,botId,session.id))current=null;
 const recent=await ticket.messages.fetch({limit:100});
 const intros=[...recent.values()].filter(message=>isTicketIntro(message,botId,session.id));
 if(!current)current=intros.sort((a,b)=>BigInt(a.id)<BigInt(b.id)?-1:BigInt(a.id)>BigInt(b.id)?1:0)[0];
 if(!current){if(!payload)return null;current=await ticket.send({...payload,nonce:crypto.createHash('sha256').update('ticket-intro:'+session.id).digest('hex').slice(0,24),enforceNonce:true});}
 for(const message of intros)if(message.id!==current.id)await message.delete().catch(error=>{if(error.code!==10008)throw error;});
 await save(current.id);
 return current;
}
