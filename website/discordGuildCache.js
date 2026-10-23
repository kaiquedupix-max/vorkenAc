// Cache each login independently and coalesce concurrent reads; never reuse another account's guilds.
export function createDiscordGuildCache(load,{ttl=60000,now=Date.now}={}){
  const entries=new Map();
  return async function get(key){
    const current=entries.get(key),time=now();
    if(current?.pending)return current.pending;
    if(current?.until>time){if(current.error)throw current.error;return current.value;}
    if(entries.size>1000)for(const[k,v]of entries)if(!v.pending&&v.until<=time)entries.delete(k);
    const entry={until:0};entries.set(key,entry);
    entry.pending=Promise.resolve().then(()=>load(key)).then(value=>{
      entry.value=value;entry.until=now()+ttl;return value;
    },error=>{
      if(error.status===429&&Number.isFinite(error.retryAfter)&&error.retryAfter>0){entry.error=error;entry.until=now()+error.retryAfter*1000;}
      else entries.delete(key);
      throw error;
    }).finally(()=>{delete entry.pending;});
    return entry.pending;
  };
}
