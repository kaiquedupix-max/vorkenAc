export const notificationDefaults={banChannelId:null,verifiedChannelId:null,discordBans:true,discordVerified:true,rustStarted:true,rustVerified:true,rustBans:true};
export function notificationSettings(value={}){return {...notificationDefaults,...value};}
export const defaultRules='**1. PC com ambiente de verificação comprometido ("PC estopado")**\n\nWindows otimizado, limpo ou modificado a ponto de apagar, esvaziar ou impedir o acesso a registros relevantes, como Prefetch, Recent e Temp, será tratado como um ambiente comprometido. Dependendo dos indícios restantes, das inconsistências encontradas e do grau de anormalidade do caso, a situação poderá resultar em banimento.\n\n**2. VAC relacionado ao Rust com menos de 120 dias**\n\nResulta em banimento direto, mesmo que nenhuma outra evidência de trapaça seja encontrada durante a verificação.\n\n**3. Conta confirmada em sites de scripts, hacks ou cheats relacionados ao Rust**\n\nSe for confirmado que o usuário possui uma conta cadastrada em qualquer site voltado à venda, distribuição ou uso de scripts, hacks ou qualquer tipo de cheat para Rust, o resultado será banimento direto.';
export const verificationDefaults={rules:defaultRules,introduction:'A verificação é obrigatória quando solicitada pela administração.',color:'#2bf0c9',timeoutSeconds:300,banOnTimeout:false,banOnRefusal:true,banOnDisconnect:true,showRules:true};
export const verificationSettings=value=>({...verificationDefaults,...value});
export function verificationEmbed(server){
  const p=verificationSettings(server.verification_settings),minutes=p.timeoutSeconds/60;
  const penalties=[];
  if(p.banOnRefusal)penalties.push('recusar');if(p.banOnDisconnect)penalties.push('desconectar do servidor');if(p.banOnTimeout)penalties.push('deixar o prazo expirar');
  const description='**'+p.introduction+'**\n\n'+
    '1. Veja o **código de 4 dígitos** exibido na tela do Rust.\n'+
    '2. Você tem **'+minutes+' minutos** para enviar o código pelo botão **Enviar código** abaixo ou pelo comando **/codigo**.\n'+
    '3. O bot criará uma **sala privada** para sua verificação.\n'+
    '4. Dentro da sala você receberá o **link exclusivo do Vorken**.\n'+
    '5. Baixe, execute como administrador e aguarde a análise terminar.\n'+
    '6. Quando finalizar, **aguarde a decisão da administração** dentro do ticket.\n\n'+
    (penalties.length?'🚫 **'+penalties.join(', ').replace(/^./,c=>c.toUpperCase())+' resulta em banimento permanente.**\n':'')+
    '⚠️ Não compartilhe seu código com outra pessoa.'+(p.showRules&&p.rules?'\n\n📋 **Regras da verificação**\n\n'+p.rules:'');
  return {title:'🛡️ Verificação Vorken · '+server.name,color:parseInt(p.color.slice(1),16),description,footer:{text:'Vorken Scanner · '+server.name}};
}
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
