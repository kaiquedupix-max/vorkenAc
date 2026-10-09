export const notificationDefaults={banChannelId:null,verifiedChannelId:null,discordBans:true,discordVerified:true,rustStarted:true,rustVerified:true,rustBans:true};
export function notificationSettings(value={}){return {...notificationDefaults,...value};}

export const defaultRules='**1. PC com ambiente de verificação comprometido ("PC estopado")**\n\nWindows otimizado, limpo ou modificado a ponto de apagar, esvaziar ou impedir o acesso a registros relevantes, como Prefetch, Recent e Temp, será tratado como um ambiente comprometido. Dependendo dos indícios restantes, das inconsistências encontradas e do grau de anormalidade do caso, a situação poderá resultar em banimento.\n\n**2. VAC relacionado ao Rust com menos de 120 dias**\n\nResulta em banimento direto, mesmo que nenhuma outra evidência de trapaça seja encontrada durante a verificação.\n\n**3. Conta confirmada em sites de scripts, hacks ou cheats relacionados ao Rust**\n\nSe for confirmado que o usuário possui uma conta cadastrada em qualquer site voltado à venda, distribuição ou uso de scripts, hacks ou qualquer tipo de cheat para Rust, o resultado será banimento direto.';

const localizedRules={
  pt:defaultRules,
  en:'**1. Compromised verification environment ("wiped/stripped PC")**\n\nA Windows installation that was optimized, cleaned or modified in a way that deletes, empties or prevents access to relevant records such as Prefetch, Recent and Temp is treated as a compromised verification environment. Depending on the remaining evidence, inconsistencies and overall context, this may result in a ban.\n\n**2. Rust-related VAC ban under 120 days**\n\nResults in a direct ban even when no additional cheating evidence is found during verification.\n\n**3. Confirmed account on Rust script, hack or cheat websites**\n\nA confirmed registered account on a website focused on selling, distributing or using Rust scripts, hacks or cheats results in a direct ban.',
  es:'**1. Entorno de verificación comprometido ("PC limpiado")**\n\nUna instalación de Windows optimizada, limpiada o modificada de forma que elimine, vacíe o impida el acceso a registros relevantes como Prefetch, Recent y Temp se considera un entorno de verificación comprometido. Según las evidencias restantes, las inconsistencias y el contexto general, la situación puede resultar en un baneo.\n\n**2. VAC relacionado con Rust de menos de 120 días**\n\nResulta en baneo directo aunque no se encuentre ninguna otra evidencia de trampa durante la verificación.\n\n**3. Cuenta confirmada en sitios de scripts, hacks o cheats de Rust**\n\nUna cuenta registrada y confirmada en un sitio dedicado a vender, distribuir o usar scripts, hacks o cheats para Rust resulta en baneo directo.'
};

export const verificationDefaults={rules:defaultRules,introduction:'A verificação é obrigatória quando solicitada pela administração.',color:'#2bf0c9',timeoutSeconds:300,banOnTimeout:false,banOnRefusal:true,banOnDisconnect:true,showRules:true};
export const verificationSettings=value=>({...verificationDefaults,...value});

const verificationCopy={
  pt:{title:'🛡️ Verificação Vorken',intro:'A verificação é obrigatória quando solicitada pela administração.',steps:['Entre no Discord e abra este canal **Verificação Vorken**.','Veja o **código de 4 dígitos** exibido na tela do Rust.','Envie **somente os 4 dígitos diretamente neste chat**. Não há botão para enviar código.','O Vorken criará automaticamente uma **sala privada** para você.','Dentro da sala, use o botão **Baixar Vorken**, execute como administrador e aguarde a coleta terminar.','Após o envio do relatório, aguarde a **decisão da administração** no ticket.'],rules:'📋 Regras da verificação',warning:'⚠️ Não compartilhe seu código com outra pessoa.',penalty:'🚫 Recusar, desconectar durante a verificação ou deixar o prazo aplicável expirar pode resultar em banimento.',footer:'Envie os 4 dígitos no chat · PT / EN / ES'},
  en:{title:'🛡️ Vorken Verification',intro:'Verification is mandatory when requested by the administration.',steps:['Join Discord and open this **Vorken Verification** channel.','Check the **4-digit code** displayed on your Rust screen.','Send **only the 4 digits directly in this chat**. There is no submit-code button.','Vorken will automatically create a **private room** for you.','Inside the room, use the **Download Vorken** button, run it as administrator and wait for collection to finish.','After the report is sent, wait for the **administration decision** in the ticket.'],rules:'📋 Verification rules',warning:'⚠️ Do not share your code with anyone.',penalty:'🚫 Refusing, disconnecting during verification or allowing an applicable deadline to expire may result in a ban.',footer:'Send the 4 digits in chat · PT / EN / ES'},
  es:{title:'🛡️ Verificación Vorken',intro:'La verificación es obligatoria cuando la solicita la administración.',steps:['Entra en Discord y abre este canal de **Verificación Vorken**.','Mira el **código de 4 dígitos** mostrado en la pantalla de Rust.','Envía **solamente los 4 dígitos directamente en este chat**. No hay botón para enviar el código.','Vorken creará automáticamente una **sala privada** para ti.','Dentro de la sala, usa el botón **Descargar Vorken**, ejecútalo como administrador y espera a que termine la recopilación.','Después de enviar el informe, espera la **decisión de la administración** en el ticket.'],rules:'📋 Reglas de verificación',warning:'⚠️ No compartas tu código con nadie.',penalty:'🚫 Rechazar, desconectarse durante la verificación o dejar que expire un plazo aplicable puede resultar en baneo.',footer:'Envía los 4 dígitos en el chat · PT / EN / ES'}
};

export function verificationEmbed(server,language='pt'){
  const lang=verificationCopy[language]?language:'pt',copy=verificationCopy[lang],p=verificationSettings(server.verification_settings);
  const minutes=Math.max(1,Math.round(p.timeoutSeconds/60));
  const intro=(lang==='pt'&&p.introduction)?p.introduction:copy.intro;
  const steps=copy.steps.map((text,index)=>`${index+1}. ${text}`).join('\n');
  const configuredRules=String(p.rules||'').trim();
  const rules=configuredRules===defaultRules?localizedRules[lang]:configuredRules;
  const deadline=lang==='pt'?`⏱️ Você possui **${minutes} minutos** para validar o código quando a contagem estiver ativa.`:lang==='en'?`⏱️ You have **${minutes} minutes** to validate the code while the countdown is active.`:`⏱️ Tienes **${minutes} minutos** para validar el código mientras el contador esté activo.`;
  const description=`**${intro}**\n\n${steps}\n\n${deadline}\n${copy.penalty}\n${copy.warning}`+(p.showRules&&rules?`\n\n${copy.rules}\n\n${rules}`:'');
  return {title:`${copy.title} · ${server.name}`,color:parseInt(p.color.slice(1),16),description,footer:{text:`Vorken Scanner · ${server.name} · ${copy.footer}`}};
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
  const safe=(value,max=500)=>String(value||'').replace(/([\\`*_{}\[\]()<>~|])/g,'\\$1').slice(0,max)||'—';
  const ban=kind==='public_ban';
  const steamId=safe(p.steamId,32),profile=`https://steamcommunity.com/profiles/${steamId}`;
  if(ban){
    return {
      color:0xe53935,
      title:'🔨 Banimento aplicado',
      description:p.discordUserId?`O jogador <@${p.discordUserId}> foi banido após a verificação Vorken.`:'O jogador foi banido após a verificação Vorken.',
      fields:[
        {name:'Jogador',value:safe(p.playerName,100),inline:true},
        {name:'SteamID',value:steamId,inline:true},
        {name:'Duração',value:safe(p.duration||'Permanente',40),inline:true},
        {name:'Motivo',value:safe(p.reason||'Decisão administrativa.',500),inline:false},
        {name:'Responsável',value:safe(p.administratorName||'Administração Vorken',100),inline:true},
        {name:'Perfil Steam',value:`[Abrir perfil](${profile})`,inline:true},
      ],
      ...(p.avatarUrl?{thumbnail:{url:p.avatarUrl}}:{}),
      footer:{text:`Vorken Scanner · ${safe(p.serverName,100)}`},
      timestamp:new Date().toISOString()
    };
  }
  return {
    color:0x2bf0c9,
    title:'✅ Verificação concluída',
    description:p.discordUserId?`<@${p.discordUserId}> foi verificado e liberado.`:`**${safe(p.playerName,100)}** foi verificado e liberado.`,
    fields:[
      {name:'Jogador',value:safe(p.playerName,100),inline:true},
      {name:'SteamID',value:steamId,inline:true},
      {name:'Responsável',value:safe(p.administratorName||'Administração Vorken',100),inline:true},
      {name:'Perfil Steam',value:`[Abrir perfil](${profile})`,inline:true}
    ],
    ...(p.avatarUrl?{thumbnail:{url:p.avatarUrl}}:{}),
    footer:{text:`Vorken Scanner · ${safe(p.serverName,100)}`},
    timestamp:new Date().toISOString()
  };
}
