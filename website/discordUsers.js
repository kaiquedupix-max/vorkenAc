// Server-side lookup; never expose the bot token to the browser.
export function createDiscordUserLookup({fetchImpl=fetch,token=()=>process.env.VORKEN_DISCORD_BOT_TOKEN,now=Date.now,ttl=300000}={}) {
  const cache=new Map(),pending=new Map();
  let blockedUntil=0;
  return async function lookup(value) {
    const id=String(value||'');
    if(!/^\d{16,20}$/.test(id))return null;
    const saved=cache.get(id);
    if(saved&&saved.until>now())return saved.user;
    if(pending.has(id))return pending.get(id);
    const secret=token();
    if(!secret||blockedUntil>now())return null;
    const work=(async()=>{
      let user=null,cacheMs=30000;
      try {
        const response=await fetchImpl('https://discord.com/api/v10/users/'+id,{
          headers:{Authorization:'Bot '+secret},signal:AbortSignal.timeout(5000)
        });
        if(response.status===429){
          const body=await response.json().catch(()=>({}));
          blockedUntil=now()+Math.max(1000,Number(body.retry_after||1)*1000);
        } else if(response.ok) {
          const profile=await response.json();
          if(profile.id===id&&typeof profile.username==='string'){
            user={id,username:profile.username,displayName:profile.global_name||profile.username,profileUrl:'https://discord.com/users/'+id};
            cacheMs=ttl;
          }
        }
      } catch { /* Preserve report access when Discord is unavailable. */ }
      if(cache.size>=2000)cache.delete(cache.keys().next().value);
      cache.set(id,{user,until:now()+cacheMs});
      return user;
    })();
    pending.set(id,work);
    try{return await work;}finally{pending.delete(id);}
  };
}
export const lookupDiscordUser=createDiscordUserLookup();
