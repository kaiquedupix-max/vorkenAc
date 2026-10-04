export const notificationDefaults={banChannelId:null,verifiedChannelId:null,discordBans:true,discordVerified:true,rustStarted:true,rustVerified:true,rustBans:true};
export function notificationSettings(value={}){return {...notificationDefaults,...value};}
// Discord permissions: base roles, everyone overwrite, aggregated role overwrites, member overwrite.
export function canPublish(channel,guildId,member,roles){
  if(![0,5].includes(channel.type))return false;
  const ids=new Set([guildId,...member.roles]);
  let bits=roles.filter(r=>ids.has(r.id)).reduce((b,r)=>b|BigInt(r.permissions),0n);
  if(bits&8n)return true;
  const overwrites=channel.permission_overwrites||[];
  const apply=o=>{if(o)bits=(bits&~BigInt(o.deny))|BigInt(o.allow);};
  apply(overwrites.find(o=>o.id===guildId));
  let allow=0n,deny=0n;
  for(const o of overwrites.filter(o=>o.type===0&&o.id!==guildId&&ids.has(o.id))){allow|=BigInt(o.allow);deny|=BigInt(o.deny);}
  bits=(bits&~deny)|allow;apply(overwrites.find(o=>o.type===1&&o.id===member.user.id));
  const required=1024n|2048n|16384n|65536n;return (bits&required)===required;
}
export function publicNotice(kind,p){
  const safe=v=>String(v||'').replace(/([\\`*_{}\[\]()<>~|])/g,'\\$1').slice(0,300);
  const ban=kind==='public_ban';
  return {color:ban?0xff2222:0x2bf0c9,title:ban?'🚫 Banimento confirmado':'✅ Jogador verificado',
    description:ban?`**${safe(p.playerName)}** foi banido pelo Vorken Scanner.`:`**${safe(p.playerName)}** foi verificado no Rust e no Discord.`,
    fields:[{name:'Jogador',value:safe(p.steamId),inline:true},{name:'Servidor',value:safe(p.serverName),inline:true},...(ban?[{name:'Motivo',value:safe(p.reason)||'Decisão administrativa.'}]:[])],
    footer:{text:'Vorken Scanner · Verificação administrativa'}};
}
