import { verificationEmbed } from './vorkenSettings.js';

export function communityVerificationEmbed(servers,guildName,language='pt'){
  if(servers.length===1)return verificationEmbed(servers[0],language);
  const lang=['pt','en','es'].includes(language)?language:'pt';
  const base=verificationEmbed({...servers[0],name:guildName,verification_settings:{showRules:false}},lang);
  const text={pt:'Envie seu código de 4 dígitos neste canal. O código identifica automaticamente o servidor Rust. Selecione seu servidor abaixo para consultar as regras e o prazo específicos.',en:'Send your 4-digit code in this channel. The code automatically identifies the Rust server. Select your server below to see its rules and deadline.',es:'Envía tu código de 4 dígitos en este canal. El código identifica automáticamente el servidor Rust. Selecciona tu servidor para consultar sus reglas y plazo.'};
  return {...base,description:base.description.split('⏱️')[0].trim()+'\n\n'+text[lang],fields:[{name:lang==='en'?'Rust servers':lang==='es'?'Servidores Rust':'Servidores Rust',value:servers.map(s=>String(s.name).replace(/([\\`*_{}\[\]()<>~|])/g,'\\$1')).join('\n').slice(0,1024)}]};
}

// Only messages owned by this bot and known as verification instructions can be consolidated.
export function instructionMessagesToRemove(messages,botId,keepId,knownIds){
  const known=new Set(knownIds.filter(Boolean));
  return [...messages].filter(m=>m.id!==keepId&&m.author?.id===botId&&(known.has(m.id)||m.components?.some(row=>row.components?.some(c=>/^vorken_(?:lang|guild_lang|rules):/.test(c.customId||c.custom_id||'')))));
}
