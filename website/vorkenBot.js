import crypto from 'node:crypto';
import { notificationSettings, publicNotice, verificationEmbed } from './vorkenSettings.js';
import {
  Client, GatewayIntentBits, PermissionFlagsBits as P, ChannelType,
  SlashCommandBuilder, MessageFlags, ActivityType, EmbedBuilder,
  ActionRowBuilder, ButtonBuilder, ButtonStyle
} from 'discord.js';

const STEAM=/^7656119\d{10}$/;
const SNOWFLAKE=/^\d{16,20}$/;
const staff=member=>!!member?.permissions&&(member.permissions.has(P.Administrator)||member.permissions.has(P.BanMembers));
const noMentions={parse:[]};
const clean=(value,max=100)=>String(value||'').replace(/[\r\n\t|]/g,' ').replace(/\s+/g,' ').trim().slice(0,max);
const steamProfile=id=>'https://steamcommunity.com/profiles/'+encodeURIComponent(String(id||''));

const ticketCopy={
  pt:{title:'🛡️ Verificação Vorken',description:'Sua sala privada de verificação está pronta. Use o botão abaixo para baixar o Vorken e mantenha o Rust aberto até a coleta terminar.',player:'Jogador',steam:'Steam',admin:'Administração responsável',status:'Status',statusValue:'Aguardando execução do Vorken',download:'Baixar Vorken',footer:'Vorken Scanner · Sala privada'},
  en:{title:'🛡️ Vorken Verification',description:'Your private verification room is ready. Use the button below to download Vorken and keep Rust open until collection finishes.',player:'Player',steam:'Steam',admin:'Responsible administrator',status:'Status',statusValue:'Waiting for Vorken to run',download:'Download Vorken',footer:'Vorken Scanner · Private room'},
  es:{title:'🛡️ Verificación Vorken',description:'Tu sala privada de verificación está lista. Usa el botón de abajo para descargar Vorken y mantén Rust abierto hasta que termine la recopilación.',player:'Jugador',steam:'Steam',admin:'Administración responsable',status:'Estado',statusValue:'Esperando la ejecución de Vorken',download:'Descargar Vorken',footer:'Vorken Scanner · Sala privada'}
};

const statusCopy={
  pt:{waiting:['⏳ Aguardando execução','O link já está liberado. Baixe o Vorken e execute como administrador.'],collecting:['🧪 Coleta iniciada','O Vorken foi iniciado e a coleta técnica está em andamento. Não feche o Rust nem o Vorken.'],processing:['🔎 Coleta enviada','A coleta terminou e o relatório foi enviado para análise. Aguarde a administração.'],completed:['✅ Análise pronta','O relatório foi processado. Aguarde a decisão da administração neste ticket.']},
  en:{waiting:['⏳ Waiting for execution','The link is ready. Download Vorken and run it as administrator.'],collecting:['🧪 Collection started','Vorken is running and technical collection is in progress. Do not close Rust or Vorken.'],processing:['🔎 Collection submitted','Collection is finished and the report was submitted for analysis. Wait for the administration.'],completed:['✅ Analysis ready','The report has been processed. Wait for the administration decision in this ticket.']},
  es:{waiting:['⏳ Esperando ejecución','El enlace ya está disponible. Descarga Vorken y ejecútalo como administrador.'],collecting:['🧪 Recopilación iniciada','Vorken está ejecutándose y la recopilación técnica está en curso. No cierres Rust ni Vorken.'],processing:['🔎 Recopilación enviada','La recopilación terminó y el informe fue enviado para análisis. Espera a la administración.'],completed:['✅ Análisis listo','El informe fue procesado. Espera la decisión de la administración en este ticket.']}
};

const decisionCopy={
  pt:{approve:['✅ Verificação concluída','Você foi verificado e liberado pela administração.'],deny:['🔨 Banimento confirmado','A administração concluiu a verificação e aplicou o banimento.'],cancel:['⚠️ Verificação encerrada','A sessão de verificação foi encerrada.']},
  en:{approve:['✅ Verification completed','You were verified and released by the administration.'],deny:['🔨 Ban confirmed','The administration completed the verification and applied the ban.'],cancel:['⚠️ Verification closed','The verification session was closed.']},
  es:{approve:['✅ Verificación finalizada','Fuiste verificado y liberado por la administración.'],deny:['🔨 Baneo confirmado','La administración finalizó la verificación y aplicó el baneo.'],cancel:['⚠️ Verificación cerrada','La sesión de verificación fue cerrada.']}
};

const langName={pt:'Português',en:'English',es:'Español'};
const language=value=>['pt','en','es'].includes(value)?value:'pt';

function instructionLanguageRow(serverId){
  return new ActionRowBuilder().addComponents(...['pt','en','es'].map(lang=>
    new ButtonBuilder().setCustomId(`vorken_lang:${lang}:${serverId}`).setLabel(langName[lang]).setStyle(ButtonStyle.Secondary)));
}

function ticketLanguageButtons(sessionId,prefix,extra=''){
  return ['pt','en','es'].map(lang=>new ButtonBuilder()
    .setCustomId(`${prefix}:${lang}:${sessionId}${extra?':'+extra:''}`)
    .setLabel(lang.toUpperCase()).setStyle(ButtonStyle.Secondary));
}

function statusEmbed(stage,lang='pt'){
  lang=language(lang);
  const pair=statusCopy[lang][stage]||statusCopy[lang].processing;
  const color=stage==='completed'?0x35de91:stage==='collecting'?0x2bf0c9:stage==='processing'?0x49b5bd:0xf0b429;
  return new EmbedBuilder().setColor(color).setTitle(pair[0]).setDescription(pair[1]).setFooter({text:'Vorken Scanner · '+(lang==='pt'?'Status da verificação':lang==='en'?'Verification status':'Estado de la verificación')}).setTimestamp();
}

function decisionEmbed(action,reason,lang='pt'){
  lang=language(lang);
  const pair=decisionCopy[lang][action]||decisionCopy[lang].cancel;
  const color=action==='approve'?0x35de91:action==='deny'?0xe53935:0xf0b429;
  const suffix=reason?`\n\n**${lang==='pt'?'Motivo':lang==='en'?'Reason':'Motivo'}:** ${clean(reason,500)}`:'';
  return new EmbedBuilder().setColor(color).setTitle(pair[0]).setDescription(pair[1]+suffix).setFooter({text:'Vorken Scanner'}).setTimestamp();
}

export async function startVorkenBot(platform){
  const token=process.env.VORKEN_DISCORD_BOT_TOKEN;
  if(!token){console.log('Vorken bot: aguardando configuração.');return null;}
  const {pool,tx,queue,decision,serverActive,publicUrl}=platform;
  const client=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages,GatewayIntentBits.MessageContent]});
  const plansUrl=publicUrl+'/servidor#planos';
  let banCount=null,playerCount=null,machineCount=null,statsUpdatedAt=0,presenceIndex=0,presenceUpdating=false;

  async function refreshBanCount(){
    if(Date.now()-statsUpdatedAt<300000)return;
    const result=await pool.query(`SELECT
      (SELECT COUNT(DISTINCT steam_id)::text FROM vorken_bans WHERE active) AS count,
      COUNT(DISTINCT NULLIF(a.external_player_id,''))::text AS players,
      COUNT(DISTINCT NULLIF(a.machine_fingerprint,''))::text AS machines
      FROM analyses a WHERE a.status='completed' AND a.processing_stage='completed'`);
    banCount=BigInt(result.rows[0].count).toLocaleString('pt-BR');
    playerCount=BigInt(result.rows[0].players).toLocaleString('pt-BR');
    machineCount=BigInt(result.rows[0].machines).toLocaleString('pt-BR');
    statsUpdatedAt=Date.now();
  }

  async function updatePresence(){
    if(!client.isReady()||presenceUpdating)return;
    presenceUpdating=true;
    try{
      await refreshBanCount().catch(e=>console.error('Vorken statistics:',e.code||e.name));
      const messages=[...(playerCount===null?[]:[`🔍 ${playerCount} jogadores · ${machineCount} máquinas verificadas`]),
        banCount===null?'🛡️ Vorken Scanner · Proteção para Rust':`🛡️ ${banCount} jogadores banidos pelo Vorken Scanner`,
        '🚀 Quer usar no seu servidor? '+plansUrl.replace(/^https?:\/\//,'')];
      client.user.setPresence({status:'online',activities:[{name:'Custom Status',type:ActivityType.Custom,state:messages[presenceIndex++%messages.length]}]});
    }finally{presenceUpdating=false;}
  }

  const commands=[
    new SlashCommandBuilder().setName('telagem').setDescription('Iniciar verificação de um jogador no Rust')
      .setDefaultMemberPermissions(P.BanMembers)
      .addStringOption(o=>o.setName('steamid').setDescription('SteamID64 do jogador').setRequired(true))
      .addStringOption(o=>o.setName('servidor').setDescription('Servidor Rust').setRequired(true).setAutocomplete(true)),
    new SlashCommandBuilder().setName('verificar').setDescription('Liberar uma sessão Vorken após revisar o relatório')
      .setDefaultMemberPermissions(P.BanMembers)
      .addStringOption(o=>o.setName('sessao').setDescription('ID da sessão no painel administrativo').setRequired(true)),
    new SlashCommandBuilder().setName('vorken').setDescription('Abrir o painel e as instruções do seu servidor'),
  ].map(c=>c.toJSON());

  const pendingSetups=new Map();

  async function publishInstructions(server,config){
    const channel=client.channels.cache.get(config.verification_channel_id)||await client.channels.fetch(config.verification_channel_id).catch(()=>null);
    if(!channel?.isSendable()||channel.guildId!==server.guild_id)return;
    const embed=verificationEmbed(server,'pt');
    const row=instructionLanguageRow(server.id);
    const signature=crypto.createHash('sha256').update(JSON.stringify({embed,components:row.toJSON()})).digest('hex');
    if(server.instructions_signature===signature&&server.instructions_message_id){
      const existing=await channel.messages.fetch(server.instructions_message_id).catch(()=>null);
      if(existing?.author.id===client.user.id)return;
    }
    const payload={embeds:[embed],components:[row],allowedMentions:noMentions};
    const existing=server.instructions_message_id?await channel.messages.fetch(server.instructions_message_id).catch(()=>null):null;
    const message=existing?.author.id===client.user.id?await existing.edit(payload):await channel.send(payload);
    await pool.query('UPDATE vorken_servers SET instructions_message_id=$2,instructions_signature=$3 WHERE id=$1',[server.id,message.id,signature]);
  }

  async function setup(guild){
    if(pendingSetups.has(guild.id))return pendingSetups.get(guild.id);
    const promise=(async()=>{
      const stored=(await pool.query('SELECT * FROM vorken_guilds WHERE id=$1',[guild.id])).rows[0];
      if(!stored)return null;
      await guild.roles.fetch();await guild.channels.fetch();
      const role=async(id,name,legacyName,color,emoji)=>{
        const existing=guild.roles.cache.get(id)||guild.roles.cache.find(r=>!r.managed&&(r.name===name||r.name===legacyName));
        const appearance={name,color,...(guild.features.includes('ROLE_ICONS')?{unicodeEmoji:emoji}:{}),reason:'Identidade visual dos cargos Vorken'};
        if(!existing)return guild.roles.create({...appearance,permissions:[],mentionable:false});
        if(existing.name!==name||existing.color!==color||(guild.features.includes('ROLE_ICONS')&&existing.unicodeEmoji!==emoji))await existing.edit(appearance);
        return existing;
      };
      const verified=await role(stored.verified_role_id,'✅ Verificado','Verificado',0x2ecc71,'✅');
      const screening=await role(stored.screening_role_id,'🔎 Em telagem','Em telagem',0xf39c12,'🔎');
      const staffRoles=guild.roles.cache.filter(r=>r.id!==guild.id&&!r.managed&&(r.permissions.has(P.Administrator)||r.permissions.has(P.BanMembers)));
      const botId=client.user.id;
      const privateOverwrites=[{id:guild.id,deny:[P.ViewChannel]},
        {id:botId,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.ManageChannels,P.ManageMessages,P.AttachFiles,P.EmbedLinks]},
        ...staffRoles.map(r=>({id:r.id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory]}))];
      const normalize=name=>name.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
      const channel=async(id,name,type,overwrites)=>guild.channels.cache.get(id)||
        (type===ChannelType.GuildCategory?guild.channels.cache.find(c=>c.type===type&&normalize(c.name)===normalize(name)):null)||
        await guild.channels.create({name,type,permissionOverwrites:overwrites});
      const category=await channel(stored.category_id,'Verificação Vorken',ChannelType.GuildCategory,privateOverwrites);
      if(category.name!=='Verificação Vorken')await category.setName('Verificação Vorken');
      const previousInstructions=stored.verification_channel_id||guild.channels.cache.find(c=>c.type===ChannelType.GuildText&&c.parentId===category.id&&normalize(c.name)==='verificacao')?.id;
      const instructions=await channel(previousInstructions,'verificacao',ChannelType.GuildText,[
        {id:guild.id,allow:[P.ViewChannel,P.ReadMessageHistory,P.SendMessages],deny:[P.AttachFiles,P.EmbedLinks]},
        {id:botId,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.EmbedLinks,P.ManageMessages]}]);
      const alerts=await channel(stored.alerts_channel_id,'vorken-alertas',ChannelType.GuildText,privateOverwrites);
      await alerts.permissionOverwrites.set(privateOverwrites);
      if(instructions.parentId!==category.id)await instructions.setParent(category.id,{lockPermissions:false});
      await instructions.permissionOverwrites.edit(guild.id,{ViewChannel:true,ReadMessageHistory:true,SendMessages:true,AttachFiles:false,EmbedLinks:false});
      await instructions.permissionOverwrites.edit(botId,{ViewChannel:true,SendMessages:true,ReadMessageHistory:true,EmbedLinks:true,ManageMessages:true});
      const previousMessages=await instructions.messages.fetch({limit:50});
      for(const message of previousMessages.values()){
        const oldFeedback=message.author.id===botId&&/^<@!?\d+> /.test(message.content)&&/código (inválido|validado)|Não foi possível validar o código/.test(message.content);
        if(!message.author.bot&&/^\d{4}$/.test(message.content.trim())||oldFeedback)await message.delete().catch(error=>console.error('Vorken limpeza de código:',error.code||error.name));
      }
      await pool.query(`UPDATE vorken_guilds SET verified_role_id=$2,screening_role_id=$3,category_id=$4,verification_channel_id=$5,alerts_channel_id=$6 WHERE id=$1`,
        [guild.id,verified.id,screening.id,category.id,instructions.id,alerts.id]);
      await guild.commands.set(commands);
      const config={...stored,verification_channel_id:instructions.id};
      for(const server of (await pool.query('SELECT * FROM vorken_servers WHERE guild_id=$1 AND enabled',[guild.id])).rows)await publishInstructions(server,config);
      return {...stored,verified_role_id:verified.id,screening_role_id:screening.id,category_id:category.id,verification_channel_id:instructions.id,alerts_channel_id:alerts.id};
    })();
    pendingSetups.set(guild.id,promise);
    try{return await promise;}finally{pendingSetups.delete(guild.id);}
  }

  async function licensedServer(guildId,id){
    const s=(await pool.query('SELECT * FROM vorken_servers WHERE guild_id=$1 AND id::text=$2 AND enabled',[guildId,id])).rows[0];
    if(!s)throw new Error('Servidor não encontrado neste Discord.');
    if(!await serverActive(s))throw new Error('Licença inativa ou limite de servidores excedido. Peça ao responsável para acessar o painel.');
    if(!s.last_seen||Date.now()-new Date(s.last_seen)>90000)throw new Error('Plugin desconectado. Aguarde a conexão antes de iniciar.');
    return s;
  }

  const attempts=new Map();
  async function redeem(server,code,userId){
    const key=server.guild_id+':'+userId,now=Date.now(),bucket=attempts.get(key);
    if(bucket&&bucket.until>now&&bucket.n>=5)throw new Error('Aguarde um minuto antes de tentar outro código.');
    attempts.set(key,bucket&&bucket.until>now?{n:bucket.n+1,until:bucket.until}:{n:1,until:now+60000});
    if(attempts.size>10000)for(const[k,v]of attempts)if(v.until<now)attempts.delete(k);
    if(!/^\d{4}$/.test(code))throw new Error('Código inválido.');
    return tx(async db=>{
      const r=await db.query(`SELECT * FROM vorken_sessions WHERE server_id=$1 AND code=$2 AND status IN ('pending','redeemed') ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,[server.id,code]);
      const s=r.rows[0];
      if(!s||(new Date(s.expires_at)<=new Date()&&s.status==='pending'))throw new Error('Código inválido ou expirado.');
      if(s.discord_user_id&&s.discord_user_id!==userId)throw new Error('Esse código já foi utilizado.');
      if(s.status==='redeemed')return s;
      const token=crypto.randomBytes(24).toString('base64url');
      const analysis=await db.query(`INSERT INTO analyses(public_token,label,expires_at,external_source,external_player_id,external_discord_user_id,external_verification_code)
        VALUES($1,$2,NOW()+interval '8 hours','vorken',$3,$4,$5) RETURNING id`,[token,'Vorken · '+server.name+' · '+s.player_name+' · '+s.steam_id,s.steam_id,userId,code]);
      await db.query("UPDATE vorken_sessions SET status='redeemed',discord_user_id=$2,analysis_id=$3 WHERE id=$1",[s.id,userId,analysis.rows[0].id]);
      await queue(db,server.id,'attend',s.steam_id,userId,s.id);
      return {...s,status:'redeemed',discord_user_id:userId,analysis_id:analysis.rows[0].id};
    });
  }

  async function administratorIdentity(guild,raw){
    let value=String(raw||'').trim().replace(/^discord:/i,'');
    let fallback='Administração Vorken';
    if(value.includes('|')){
      const index=value.indexOf('|');
      const id=value.slice(0,index).trim(),name=clean(value.slice(index+1),100);
      if(name)fallback=name;
      value=id;
    }
    if(value.startsWith('customer:')){
      const customerId=value.slice('customer:'.length);
      const row=(await pool.query('SELECT discord_id,name FROM vorken_customers WHERE id::text=$1',[customerId])).rows[0];
      if(row){value=String(row.discord_id||'');fallback=clean(row.name,100)||fallback;}
    }
    if(SNOWFLAKE.test(value)){
      const member=await guild.members.fetch(value).catch(()=>null);
      return {id:value,name:member?.displayName||member?.user?.globalName||member?.user?.username||fallback};
    }
    return {id:null,name:fallback};
  }

  async function sessionContext(sessionId){
    const row=(await pool.query(`SELECT v.*,s.name AS server_name,s.guild_id,a.public_token
      FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id
      LEFT JOIN analyses a ON a.id=v.analysis_id WHERE v.id=$1`,[sessionId])).rows[0];
    if(!row)return null;
    const guild=await client.guilds.fetch(row.guild_id).catch(()=>null);
    if(!guild)return null;
    const admin=await administratorIdentity(guild,row.administrator_id);
    const member=row.discord_user_id?await guild.members.fetch(row.discord_user_id).catch(()=>null):null;
    return {row,guild,admin,member};
  }

  async function initialTicketPayload(sessionId,lang='pt'){
    lang=language(lang);
    const context=await sessionContext(sessionId);
    if(!context)return null;
    const {row,admin,member}=context,copy=ticketCopy[lang];
    const embed=new EmbedBuilder().setColor(0x2bf0c9).setTitle(copy.title).setDescription(copy.description)
      .addFields(
        {name:copy.player,value:clean(row.player_name,100)||'—',inline:true},
        {name:copy.steam,value:`[${row.steam_id}](${steamProfile(row.steam_id)})`,inline:true},
        {name:copy.admin,value:admin.name,inline:true},
        {name:copy.status,value:copy.statusValue,inline:false})
      .setFooter({text:copy.footer}).setTimestamp();
    if(member?.user)embed.setThumbnail(member.user.displayAvatarURL({size:256}));
    const download=publicUrl+'/a/'+row.public_token;
    const rowButtons=new ActionRowBuilder().addComponents(
      new ButtonBuilder().setLabel(copy.download).setStyle(ButtonStyle.Link).setURL(download),
      ...ticketLanguageButtons(row.id,'vorken_ticket_lang'));
    return {embeds:[embed],components:[rowButtons],allowedMentions:noMentions};
  }

  async function ensureTicket(session){
    const server=(await pool.query('SELECT * FROM vorken_servers WHERE id=$1',[session.server_id])).rows[0];
    const guild=await client.guilds.fetch(server.guild_id);
    const config=(await pool.query('SELECT * FROM vorken_guilds WHERE id=$1',[guild.id])).rows[0];
    if(!config?.category_id)return null;
    await guild.channels.fetch();
    let ticket=guild.channels.cache.get(session.ticket_channel_id)||guild.channels.cache.find(c=>c.topic==='VORKEN_SESSION:'+session.id);
    if(!ticket){
      const overwrites=[{id:guild.id,deny:[P.ViewChannel]},
        {id:client.user.id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.ManageChannels,P.AttachFiles,P.EmbedLinks]},
        ...guild.roles.cache.filter(r=>r.id!==guild.id&&!r.managed&&(r.permissions.has(P.Administrator)||r.permissions.has(P.BanMembers))).map(r=>({id:r.id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory]}))];
      if(session.discord_user_id)overwrites.push({id:session.discord_user_id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory],deny:[]});
      const admin=await administratorIdentity(guild,session.administrator_id);
      if(admin.id&&admin.id!==session.discord_user_id)overwrites.push({id:admin.id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory],deny:[]});
      ticket=await guild.channels.create({name:'vorken-'+session.steam_id.slice(-6),type:ChannelType.GuildText,parent:config.category_id,topic:'VORKEN_SESSION:'+session.id,permissionOverwrites:overwrites});
    }
    const member=session.discord_user_id?await guild.members.fetch(session.discord_user_id).catch(()=>null):null;
    if(member){await member.roles.remove(config.verified_role_id).catch(()=>{});await member.roles.add(config.screening_role_id).catch(()=>{});}
    const recent=await ticket.messages.fetch({limit:20});
    const already=recent.some(m=>m.author.id===client.user.id&&m.embeds.some(e=>e.title?.includes('Vorken')&&e.fields?.some(f=>f.value?.includes(session.steam_id))));
    if(!already){const payload=await initialTicketPayload(session.id,'pt');if(payload)await ticket.send(payload);}
    await pool.query('UPDATE vorken_sessions SET ticket_channel_id=$2 WHERE id=$1',[session.id,ticket.id]);
    await pool.query('UPDATE analyses SET external_ticket_channel_id=$2 WHERE id=$1',[session.analysis_id,ticket.id]);
    return ticket;
  }

  async function privateCodeFeedback(user,content){
    await user.send({content,allowedMentions:noMentions}).catch(error=>{
      console.error('Vorken retorno privado do código:',error.code||error.name);
    });
  }

  client.on('messageCreate',async message=>{
    if(message.author.bot||!message.guildId)return;
    const config=(await pool.query('SELECT * FROM vorken_guilds WHERE id=$1 AND verification_channel_id=$2',[message.guildId,message.channelId])).rows[0];
    if(!config)return;
    const code=message.content.trim();
    try{await message.delete();}catch(error){
      console.error('Vorken remoção de mensagem no canal de verificação:',error.code||error.name);
      await privateCodeFeedback(message.author,'Não foi possível apagar sua mensagem. Avise a administração para conceder ao Vorken a permissão Gerenciar mensagens neste canal.');
      return;
    }
    if(!/^\d{4}$/.test(code)){
      await privateCodeFeedback(message.author,'Envie somente os 4 dígitos exibidos no Rust no canal de verificação.');
      return;
    }
    try{
      const matches=(await pool.query(`SELECT v.id,v.server_id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id
        WHERE s.guild_id=$1 AND s.enabled AND v.code=$2 AND v.status IN ('pending','redeemed') ORDER BY v.created_at DESC LIMIT 3`,[message.guildId,code])).rows;
      if(!matches.length)throw new Error('Código inválido ou expirado. Confira os 4 dígitos exibidos no Rust.');
      if(matches.length>1)throw new Error('Este código coincide com mais de uma verificação ativa. Peça à administração para reiniciar uma das sessões.');
      const server=await licensedServer(message.guildId,matches[0].server_id);
      const session=await redeem(server,code,message.author.id);
      const ticket=await ensureTicket(session);
      if(ticket)await privateCodeFeedback(message.author,'✅ Código validado. Sua sala privada está pronta: https://discord.com/channels/'+message.guildId+'/'+ticket.id);
      else await privateCodeFeedback(message.author,'✅ Código validado. Sua sala privada está sendo criada.');
    }catch(error){await privateCodeFeedback(message.author,error.message||'Não foi possível validar o código.');}
  });

  client.on('interactionCreate',async i=>{
    if(!i.guildId)return;
    if(i.isAutocomplete()){
      const rows=await pool.query('SELECT id,name FROM vorken_servers WHERE guild_id=$1 AND enabled ORDER BY name',[i.guildId]);
      const query=String(i.options.getFocused()).toLowerCase();
      await i.respond(rows.rows.filter(s=>s.name.toLowerCase().includes(query)).slice(0,25).map(s=>({name:s.name.slice(0,100),value:s.id}))).catch(()=>{});return;
    }
    if(i.isButton()){
      try{
        if(i.customId.startsWith('vorken_prior:')){
          await i.deferReply({flags:MessageFlags.Ephemeral});
          const member=await i.guild.members.fetch(i.user.id);
          if(!staff(member))throw new Error('Somente a administração pode revisar este alerta.');
          const [,action,id]=i.customId.split(':');
          if(!['proof','ban','start','allow','ignore','confirm'].includes(action))throw new Error('Ação inválida.');
          await tx(async db=>{
            const notice=(await db.query("SELECT * FROM vorken_notices WHERE id::text=$1 AND guild_id=$2 AND kind='prior_ban' FOR UPDATE",[id,i.guildId])).rows[0];
            if(!notice?.payload?.serverId)throw new Error('Alerta não encontrado ou antigo.');
            const p=notice.payload;
            await licensedServer(i.guildId,p.serverId);
            if(action==='proof'){
              const evidence=(p.bans||[]).map(b=>({servidor:b.server_name,motivo:b.reason,data:b.created_at,provas:b.evidence}));
              await i.editReply({content:'Provas do banimento de '+clean(p.playerName,80)+'. Revise o relatório antes de decidir.',files:[{attachment:Buffer.from(JSON.stringify(evidence,null,2)),name:'provas-vorken.json'}],allowedMentions:noMentions});return;
            }
            if(p.reviewed)throw new Error('Este alerta já recebeu uma decisão administrativa.');
            if(action==='ban'){
              await i.editReply({content:'Confirmar banimento de '+clean(p.playerName,80)+' neste servidor com base nas provas do alerta?',components:[new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId('vorken_prior:confirm:'+id).setLabel('Confirmar banimento neste servidor').setStyle(ButtonStyle.Danger))],allowedMentions:noMentions});return;
            }
            const actor=i.user.id+'|'+clean(member.displayName||i.user.username,80);
            if(action==='confirm'){
              const server=(await db.query('SELECT plugin_version FROM vorken_servers WHERE id=$1',[p.serverId])).rows[0];
              const version=/^(\d+)\.(\d+)\.(\d+)$/.exec(server?.plugin_version||'');
              if(!version||!(Number(version[1])>2||Number(version[1])===2&&(Number(version[2])>0||Number(version[3])>=5)))throw new Error('Atualize o plugin deste servidor para Vorken 2.0.5 ou superior antes de usar este botão.');
              const reason=clean('Banimento anterior: '+(p.bans||[]).map(b=>b.server_name+': '+b.reason).join('; '),500);
              p.commandId=await queue(db,p.serverId,'ban_prior',p.steamId,actor,null,reason);
            }else if(action==='start'){
              const pending=await db.query("SELECT id FROM vorken_commands WHERE server_id=$1 AND steam_id=$2 AND action='start' AND status='pending'",[p.serverId,p.steamId]);
              if(pending.rows.length)throw new Error('Já existe uma solicitação de verificação pendente.');
              await queue(db,p.serverId,'start',p.steamId,actor);
            }
            p.reviewed={action,administrator:i.user.id,at:new Date().toISOString()};
            await db.query('UPDATE vorken_notices SET payload=$2 WHERE id=$1',[notice.id,JSON.stringify(p)]);
            await platform.audit(db,i.user.id,'prior_ban_'+action,p.serverId,{noticeId:id,steamId:p.steamId});
            await i.editReply(action==='confirm'?'Banimento enviado. Aguarde a confirmação do plugin.':action==='start'?'Verificação enviada ao servidor.':action==='allow'?'Jogador autorizado nesta revisão. O banimento do servidor de origem permanece registrado.':'Alerta ignorado nesta revisão.');
          });return;
        }
        if(i.customId.startsWith('vorken_lang:')){
          const [,lang,id]=i.customId.split(':');
          const server=(await pool.query('SELECT * FROM vorken_servers WHERE id=$1 AND guild_id=$2',[id,i.guildId])).rows[0];
          if(!server)throw new Error('Servidor não encontrado.');
          await i.reply({embeds:[verificationEmbed(server,language(lang))],flags:MessageFlags.Ephemeral,allowedMentions:noMentions});return;
        }
        if(i.customId.startsWith('vorken_ticket_lang:')){
          const [,lang,sessionId]=i.customId.split(':');
          const payload=await initialTicketPayload(sessionId,lang);
          if(!payload)throw new Error('Sessão não encontrada.');
          await i.update(payload);return;
        }
        if(i.customId.startsWith('vorken_status_lang:')){
          const [,lang,sessionId,stage]=i.customId.split(':');
          const context=await sessionContext(sessionId);if(!context)throw new Error('Sessão não encontrada.');
          const row=new ActionRowBuilder().addComponents(...ticketLanguageButtons(sessionId,'vorken_status_lang',stage));
          await i.update({embeds:[statusEmbed(stage,lang)],components:[row],allowedMentions:noMentions});return;
        }
        if(i.customId.startsWith('vorken_decision_lang:')){
          const [,lang,sessionId,action]=i.customId.split(':');
          const s=(await pool.query('SELECT id FROM vorken_sessions WHERE id=$1',[sessionId])).rows[0];if(!s)throw new Error('Sessão não encontrada.');
          const reason=i.message.embeds?.[0]?.fields?.find(f=>f.name==='Motivo')?.value||'';
          const row=new ActionRowBuilder().addComponents(...ticketLanguageButtons(sessionId,'vorken_decision_lang',action));
          await i.update({embeds:[decisionEmbed(action,reason,lang)],components:[row],allowedMentions:noMentions});return;
        }
      }catch(error){if(!i.replied&&!i.deferred)await i.reply({content:error.message||'Não foi possível concluir.',flags:MessageFlags.Ephemeral,allowedMentions:noMentions}).catch(()=>{});}return;
    }
    if(!i.isChatInputCommand())return;
    try{
      await i.deferReply({flags:MessageFlags.Ephemeral});
      if(['telagem','verificar'].includes(i.commandName)){
        const member=await i.guild.members.fetch(i.user.id);
        if(!staff(member))throw new Error('Somente a administração pode usar este comando.');
      }
      if(i.commandName==='telagem'){
        const s=await licensedServer(i.guildId,i.options.getString('servidor')),steamId=i.options.getString('steamid');
        if(!STEAM.test(steamId))throw new Error('Informe um SteamID64 válido.');
        const pending=await pool.query("SELECT id FROM vorken_commands WHERE server_id=$1 AND steam_id=$2 AND action='start' AND status='pending'",[s.id,steamId]);
        if(pending.rows.length)throw new Error('Já existe uma solicitação pendente para esse jogador.');
        const member=await i.guild.members.fetch(i.user.id);
        const actor=`${i.user.id}|${clean(member.displayName||i.user.globalName||i.user.username,80)}`;
        await queue(pool,s.id,'start',steamId,actor);
        await i.editReply('Solicitação enviada ao Vorken. Assim que o Rust confirmar, o jogador verá o código de 4 dígitos na tela.');
      }else if(i.commandName==='verificar'){
        const id=i.options.getString('sessao');
        const session=(await pool.query('SELECT v.*,s.guild_id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id WHERE v.id::text=$1 AND s.guild_id=$2',[id,i.guildId])).rows[0];
        if(!session)throw new Error('Sessão não encontrada neste Discord.');
        await licensedServer(i.guildId,session.server_id);
        await tx(db=>decision(db,session.id,'approve',i.user.id,'Liberado após revisão da administração.',[],[]));
        await i.editReply('Liberação enviada. O cargo Verificado será aplicado após a confirmação do Rust.');
      }else{
        await refreshBanCount().catch(e=>console.error('Vorken statistics:',e.code||e.name));
        const embed=new EmbedBuilder().setColor(0x20d8b0).setTitle('Vorken Scanner · Proteção para Rust')
          .setDescription((banCount===null?'':`🔍 **${playerCount} jogadores · ${machineCount} máquinas verificadas**\n🛡️ **${banCount} jogadores banidos pelo Vorken Scanner**\n\n`)+
            'Use **/telagem** para iniciar a verificação. O jogador apenas envia os **4 dígitos diretamente no canal Verificação Vorken** e a sala privada é criada automaticamente.')
          .addFields({name:'Planos e contratação',value:plansUrl})
          .setFooter({text:'Vorken Scanner · Verificação integrada e privada'});
        const links=new ActionRowBuilder().addComponents(
          new ButtonBuilder().setLabel('Adicionar meu servidor · Ver planos').setStyle(ButtonStyle.Link).setURL(plansUrl),
          new ButtonBuilder().setLabel('Abrir meu painel').setStyle(ButtonStyle.Link).setURL(publicUrl+'/servidor'));
        await i.editReply({embeds:[embed],components:[links],allowedMentions:noMentions});
      }
    }catch(e){
      console.error('Vorken interaction:',e.code||e.name);
      const message=e.status===500?'Não foi possível concluir a operação.':e.message;
      if(i.deferred||i.replied)await i.editReply({content:message,allowedMentions:noMentions}).catch(()=>{});
      else await i.reply({content:message,flags:MessageFlags.Ephemeral}).catch(()=>{});
    }
  });

  let ticking=false;
  async function tick(){
    if(ticking||!client.isReady())return;ticking=true;
    const db=await pool.connect();
    try{
      if(!(await db.query('SELECT pg_try_advisory_lock(827463) AS locked')).rows[0].locked)return;
      const configured=await db.query('SELECT * FROM vorken_guilds');
      for(const config of configured.rows){
        const guild=await client.guilds.fetch(config.id).catch(()=>null);
        if(guild&&(!config.verified_role_id||!guild.channels.cache.has(config.verification_channel_id)||!guild.channels.cache.has(config.category_id)))await setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name));
        else if(guild)for(const server of (await db.query('SELECT * FROM vorken_servers WHERE guild_id=$1 AND enabled',[config.id])).rows)await publishInstructions(server,config).catch(e=>console.error('Vorken instruções:',e.code||e.name));
      }

      const tickets=await db.query("SELECT * FROM vorken_sessions WHERE status='redeemed' AND ticket_channel_id IS NULL LIMIT 10");
      for(const s of tickets.rows)await ensureTicket(s).catch(e=>console.error('Vorken ticket:',e.code||e.name));

      const progress=await db.query(`SELECT v.*,a.processing_stage,a.status AS analysis_status FROM vorken_sessions v JOIN analyses a ON a.id=v.analysis_id
        WHERE v.status='redeemed' AND v.ticket_channel_id IS NOT NULL AND v.notified_stage IS DISTINCT FROM a.processing_stage LIMIT 20`);
      for(const s of progress.rows){
        const channel=await client.channels.fetch(s.ticket_channel_id).catch(()=>null);
        if(!channel?.isSendable()){await db.query('UPDATE vorken_sessions SET notified_stage=$2 WHERE id=$1',[s.id,s.processing_stage]);continue;}
        const stage=['waiting','collecting','processing','completed'].includes(s.processing_stage)?s.processing_stage:'processing';
        const row=new ActionRowBuilder().addComponents(...ticketLanguageButtons(s.id,'vorken_status_lang',stage));
        await channel.send({embeds:[statusEmbed(stage,'pt')],components:[row],allowedMentions:noMentions});
        await db.query('UPDATE vorken_sessions SET notified_stage=$2 WHERE id=$1',[s.id,s.processing_stage]);
      }

      const notices=await db.query('SELECT n.*,g.alerts_channel_id,g.verified_role_id,g.screening_role_id FROM vorken_notices n JOIN vorken_guilds g ON g.id=n.guild_id WHERE n.sent_at IS NULL AND n.next_attempt_at<=NOW() ORDER BY n.created_at LIMIT 20');
      for(const n of notices.rows){
        await db.query("UPDATE vorken_notices SET next_attempt_at=NOW()+interval '5 minutes' WHERE id=$1",[n.id]);
        try{
          if(['public_ban','public_verified'].includes(n.kind)){
            const p=n.payload;
            const server=(await db.query('SELECT * FROM vorken_servers WHERE id=$1 AND guild_id=$2',[p.serverId,n.guild_id])).rows[0];
            if(!server){await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);continue;}
            const settings=notificationSettings(server.notification_settings),ban=n.kind==='public_ban';
            const id=ban?settings.banChannelId:settings.verifiedChannelId;
            if(!id||!(ban?settings.discordBans:settings.discordVerified)){await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);continue;}
            const channel=await client.channels.fetch(id).catch(()=>null);
            if(!channel?.isSendable()||channel.guildId!==n.guild_id)continue;
            const latest=(await db.query('SELECT administrator_id,discord_user_id FROM vorken_sessions WHERE server_id=$1 AND steam_id=$2 ORDER BY created_at DESC LIMIT 1',[p.serverId,p.steamId])).rows[0]||{};
            const guild=await client.guilds.fetch(n.guild_id);
            const admin=await administratorIdentity(guild,latest.administrator_id);
            const member=latest.discord_user_id?await guild.members.fetch(latest.discord_user_id).catch(()=>null):null;
            const enriched={...p,administratorName:p.administratorName||admin.name,discordUserId:latest.discord_user_id||null,avatarUrl:member?.user?.displayAvatarURL({size:256})||null,duration:p.duration||'Permanente'};
            await channel.send({content:enriched.discordUserId?`<@${enriched.discordUserId}>`:undefined,embeds:[publicNotice(n.kind,enriched)],allowedMentions:enriched.discordUserId?{users:[enriched.discordUserId]}:noMentions});
            await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);continue;
          }

          const p=n.payload;
          if(n.kind==='decision'){
            const guild=await client.guilds.fetch(n.guild_id);
            const member=p.discordUserId?await guild.members.fetch(p.discordUserId).catch(()=>null):null;
            if(member){await member.roles.remove(n.screening_role_id).catch(()=>{});if(p.action==='approve')await member.roles.add(n.verified_role_id).catch(()=>{});else await member.roles.remove(n.verified_role_id).catch(()=>{});}
            const channel=await client.channels.fetch(p.channelId).catch(()=>null);
            if(channel?.isSendable()){
              const row=new ActionRowBuilder().addComponents(...ticketLanguageButtons(p.sessionId,'vorken_decision_lang',p.action));
              await channel.send({embeds:[decisionEmbed(p.action,p.reason,'pt')],components:[row],allowedMentions:noMentions});
              const timer=setTimeout(()=>channel.delete('Verificação Vorken finalizada').catch(()=>{}),60000);timer.unref?.();
            }
            await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);continue;
          }

          const channel=await client.channels.fetch(n.alerts_channel_id).catch(()=>null);
          if(!channel?.isSendable())continue;
          if(n.kind==='command'){
            const embed=new EmbedBuilder().setColor(p.ok?0x2bf0c9:0xe53935).setTitle(p.ok?'✅ Verificação iniciada':'⚠️ Verificação não iniciada')
              .addFields({name:'Servidor',value:clean(p.serverName,100)||'—',inline:true},{name:'SteamID',value:clean(p.steamId,32)||'—',inline:true},{name:'Resultado',value:clean(p.result,500)||'—'})
              .setFooter({text:'Vorken Scanner'}).setTimestamp();
            await channel.send({embeds:[embed],allowedMentions:noMentions});
          }else if(n.kind==='prior_ban'){
            const summary=(p.bans||[]).map(b=>'• '+clean(b.server_name,100)+': '+clean(b.reason,300)).join('\n').slice(0,1800)||'Banimento anterior registrado.';
            const embed=new EmbedBuilder().setColor(0xe53935).setTitle('⚠️ Banimento anterior no Vorken')
              .setDescription(summary).addFields({name:'Jogador',value:clean(p.playerName,100)||'—',inline:true},{name:'SteamID',value:clean(p.steamId,32)||'—',inline:true},{name:'Servidor atual',value:clean(p.serverName,100)||'—',inline:true})
              .setFooter({text:'Revise as evidências no painel administrativo'}).setTimestamp();
            const actions=new ActionRowBuilder().addComponents(
              new ButtonBuilder().setCustomId('vorken_prior:proof:'+n.id).setLabel('Ver provas').setStyle(ButtonStyle.Secondary),
              new ButtonBuilder().setCustomId('vorken_prior:ban:'+n.id).setLabel('Banir daqui também').setStyle(ButtonStyle.Danger),
              new ButtonBuilder().setCustomId('vorken_prior:start:'+n.id).setLabel('Mandar para verificação').setStyle(ButtonStyle.Primary),
              new ButtonBuilder().setCustomId('vorken_prior:allow:'+n.id).setLabel('Liberar jogador').setStyle(ButtonStyle.Success),
              new ButtonBuilder().setCustomId('vorken_prior:ignore:'+n.id).setLabel('Ignorar').setStyle(ButtonStyle.Secondary));
            const links=new ActionRowBuilder().addComponents(new ButtonBuilder().setLabel('Abrir provas no Vorken').setStyle(ButtonStyle.Link).setURL(publicUrl+'/servidor?alert='+n.id+'#workspace'));
            await channel.send({embeds:[embed],components:[actions,links],allowedMentions:noMentions});
          }
          await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);
        }catch(e){console.error('Vorken notification:',e.code||e.name);}
      }
    }finally{await db.query('SELECT pg_advisory_unlock(827463)').catch(()=>{});db.release();ticking=false;}
  }

  client.once('clientReady',async()=>{
    console.log('Vorken bot conectado.');
    try{
      await client.application.fetch();
      const description='🛡️ Proteção para servidores Rust. Verificação de jogadores, tickets privados, relatórios com provas e alertas de banimentos.\n\n🚀 Use no seu servidor: '+publicUrl+'/servidor';
      if(client.application.description!==description)await client.application.edit({description});
    }catch(e){console.error('Vorken descrição do perfil:',e.code||e.name);}
    await updatePresence();
    const presenceTimer=setInterval(()=>updatePresence().catch(e=>console.error('Vorken presence:',e.code||e.name)),30000);presenceTimer.unref();
    for(const guild of client.guilds.cache.values())await setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name));
    const timer=setInterval(()=>tick().catch(e=>console.error('Vorken worker:',e.code||e.name)),10000);timer.unref();
    await tick();
  });
  client.on('guildCreate',guild=>setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name)));
  client.on('error',e=>console.error('Vorken Discord:',e.code||e.name));
  await client.login(token);
  return client;
}
