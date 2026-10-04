import crypto from 'node:crypto';
import { Client, GatewayIntentBits, PermissionFlagsBits as P, ChannelType, SlashCommandBuilder, MessageFlags, AttachmentBuilder } from 'discord.js';
const STEAM=/^7656119\d{10}$/;
const staff=member=>!!member?.permissions && (member.permissions.has(P.Administrator)||member.permissions.has(P.BanMembers));
const noMentions={parse:[]};

export async function startVorkenBot(platform) {
  const token=process.env.VORKEN_DISCORD_BOT_TOKEN;
  if(!token) {console.log('Vorken bot: aguardando configuração.');return null;}
  const {pool,tx,queue,decision,serverActive,publicUrl}=platform;
  const client=new Client({intents:[GatewayIntentBits.Guilds]});
  const commands=[
    new SlashCommandBuilder().setName('telagem').setDescription('Iniciar verificação de um jogador no Rust')
      .setDefaultMemberPermissions(P.BanMembers)
      .addStringOption(o=>o.setName('steamid').setDescription('SteamID64 do jogador').setRequired(true))
      .addStringOption(o=>o.setName('servidor').setDescription('Servidor Rust').setRequired(true).setAutocomplete(true)),
    new SlashCommandBuilder().setName('codigo').setDescription('Validar o código recebido na tela do Rust')
      .addStringOption(o=>o.setName('codigo').setDescription('Código de quatro dígitos').setRequired(true))
      .addStringOption(o=>o.setName('servidor').setDescription('Servidor Rust').setRequired(true).setAutocomplete(true)),
    new SlashCommandBuilder().setName('verificar').setDescription('Liberar uma sessão Vorken após revisar o relatório')
      .setDefaultMemberPermissions(P.BanMembers)
      .addStringOption(o=>o.setName('sessao').setDescription('ID da sessão exibido no ticket ou no painel').setRequired(true)),
    new SlashCommandBuilder().setName('vorken').setDescription('Abrir o painel e as instruções do seu servidor'),
  ].map(c=>c.toJSON());
  const pendingSetups=new Map();
  async function setup(guild){
    if(pendingSetups.has(guild.id)) return pendingSetups.get(guild.id);
    const promise=(async()=>{
      const stored=(await pool.query('SELECT * FROM vorken_guilds WHERE id=$1',[guild.id])).rows[0];
      if(!stored)return null;
      await guild.roles.fetch();await guild.channels.fetch();
      const role=async(id,name)=>guild.roles.cache.get(id)||guild.roles.cache.find(r=>r.name===name)||await guild.roles.create({name,reason:'Configuração automática Vorken'});
      const verified=await role(stored.verified_role_id,'Verificado');
      const screening=await role(stored.screening_role_id,'Em telagem');
      const staffRoles=guild.roles.cache.filter(r=>r.id!==guild.id&&!r.managed&&(r.permissions.has(P.Administrator)||r.permissions.has(P.BanMembers)));
      const botId=client.user.id;
      const privateOverwrites=[{id:guild.id,deny:[P.ViewChannel]},
        {id:botId,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.ManageChannels,P.AttachFiles,P.EmbedLinks]},
        ...staffRoles.map(r=>({id:r.id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory]}))];
      const channel=async(id,name,type,overwrites)=>guild.channels.cache.get(id)||await guild.channels.create({name,type,permissionOverwrites:overwrites});
      const category=await channel(stored.category_id,'VORKEN · VERIFICAÇÕES',ChannelType.GuildCategory,privateOverwrites);
      const instructions=await channel(stored.verification_channel_id,'verificacao',ChannelType.GuildText,[
        {id:guild.id,allow:[P.ViewChannel,P.ReadMessageHistory],deny:[P.SendMessages]},
        {id:botId,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.EmbedLinks]}]);
      const alerts=await channel(stored.alerts_channel_id,'vorken-alertas',ChannelType.GuildText,privateOverwrites);
      await pool.query(`UPDATE vorken_guilds SET verified_role_id=$2,screening_role_id=$3,category_id=$4,verification_channel_id=$5,alerts_channel_id=$6 WHERE id=$1`,
        [guild.id,verified.id,screening.id,category.id,instructions.id,alerts.id]);
      await guild.commands.set(commands);
      const recent=await instructions.messages.fetch({limit:30});
      if(!recent.some(m=>m.author.id===botId&&m.content.includes('VORKEN_INSTRUCOES'))){
        await instructions.send({content:'**Verificação Vorken**\nUse **/codigo** neste Discord, escolha o servidor Rust e informe o código exibido na sua tela. O bot criará um ticket privado com o link da análise.\nA administração usa **/telagem** para iniciar e **/verificar** para liberar após revisar o relatório.\nVORKEN_INSTRUCOES',allowedMentions:noMentions});
      }
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
      if(!s||new Date(s.expires_at)<=new Date()&&s.status==='pending')throw new Error('Código inválido ou expirado.');
      if(s.discord_user_id&&s.discord_user_id!==userId)throw new Error('Esse código já foi utilizado.');
      if(s.status==='redeemed')return s;
      const token=crypto.randomBytes(24).toString('base64url');
      const analysis=await db.query(`INSERT INTO analyses(public_token,label,expires_at,external_source,external_player_id,external_discord_user_id,external_verification_code)
        VALUES($1,$2,NOW()+interval '8 hours','vorken',$3,$4,$5) RETURNING id`,[token,'Vorken · '+server.name+' · '+s.player_name,s.steam_id,userId,code]);
      await db.query("UPDATE vorken_sessions SET status='redeemed',discord_user_id=$2,analysis_id=$3 WHERE id=$1",[s.id,userId,analysis.rows[0].id]);
      await queue(db,server.id,'attend',s.steam_id,userId,s.id);
      return {...s,status:'redeemed',discord_user_id:userId,analysis_id:analysis.rows[0].id};
    });
  }
  async function ensureTicket(session){
    const server=(await pool.query('SELECT * FROM vorken_servers WHERE id=$1',[session.server_id])).rows[0];
    const guild=await client.guilds.fetch(server.guild_id);
    const config=(await pool.query('SELECT * FROM vorken_guilds WHERE id=$1',[guild.id])).rows[0];
    if(!config?.category_id)return;
    await guild.channels.fetch();
    let ticket=guild.channels.cache.get(session.ticket_channel_id)||guild.channels.cache.find(c=>c.topic==='VORKEN_SESSION:'+session.id);
    if(!ticket){
      const category=guild.channels.cache.get(config.category_id);
      const overwrites=category?.permissionOverwrites.cache.map(o=>({id:o.id,type:o.type,allow:o.allow.bitfield,deny:o.deny.bitfield}))||[];
      overwrites.push({id:session.discord_user_id,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory,P.AttachFiles],deny:[]});
      const adminId=String(session.administrator_id||'').replace(/^discord:/,'');
      if(/^\d{16,20}$/.test(adminId)&&adminId!==session.discord_user_id)overwrites.push({id:adminId,allow:[P.ViewChannel,P.SendMessages,P.ReadMessageHistory],deny:[]});
      ticket=await guild.channels.create({name:'vorken-'+session.steam_id.slice(-6),type:ChannelType.GuildText,
        parent:config.category_id,topic:'VORKEN_SESSION:'+session.id,permissionOverwrites:overwrites});
    }
    const analysis=(await pool.query('SELECT public_token FROM analyses WHERE id=$1',[session.analysis_id])).rows[0];
    const member=await guild.members.fetch(session.discord_user_id).catch(()=>null);
    if(member){
      await member.roles.remove(config.verified_role_id);
      await member.roles.add(config.screening_role_id);
    }
    const recent=await ticket.messages.fetch({limit:20});
    if(!recent.some(m=>m.author.id===client.user.id&&m.content.includes('VORKEN_LINK:'+session.id)))
      await ticket.send({content:'**Verificação de '+session.player_name+'**\nSteamID: '+session.steam_id+'\nSessão: '+session.id+'\nAbra '+publicUrl+'/a/'+analysis.public_token+' para baixar e executar o Vorken com consentimento. Aguarde a conclusão e a decisão da administração.\nVORKEN_LINK:'+session.id,allowedMentions:noMentions});
    await pool.query('UPDATE vorken_sessions SET ticket_channel_id=$2 WHERE id=$1',[session.id,ticket.id]);
    await pool.query('UPDATE analyses SET external_ticket_channel_id=$2 WHERE id=$1',[session.analysis_id,ticket.id]);
    return ticket;
  }
  client.on('interactionCreate',async i=>{
    if(!i.guildId)return;
    if(i.isAutocomplete()){
      const rows=await pool.query('SELECT id,name FROM vorken_servers WHERE guild_id=$1 AND enabled ORDER BY name',[i.guildId]);
      const query=String(i.options.getFocused()).toLowerCase();
      await i.respond(rows.rows.filter(s=>s.name.toLowerCase().includes(query)).slice(0,25).map(s=>({name:s.name.slice(0,100),value:s.id}))).catch(()=>{});return;
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
        await queue(pool,s.id,'start',steamId,i.user.id);
        await i.editReply('Solicitação enviada ao plugin. O jogador receberá o código na tela quando o Rust confirmar a telagem.');
      }else if(i.commandName==='codigo'){
        const s=await licensedServer(i.guildId,i.options.getString('servidor'));
        const session=await redeem(s,i.options.getString('codigo'),i.user.id);
        const ticket=await ensureTicket(session);
        await i.editReply(ticket?'Sua sala privada está pronta: <#'+ticket.id+'>':'Código aceito. Aguarde a criação do ticket.');
      }else if(i.commandName==='verificar'){
        const id=i.options.getString('sessao');
        const session=(await pool.query('SELECT v.*,s.guild_id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id WHERE v.id::text=$1 AND s.guild_id=$2',[id,i.guildId])).rows[0];
        if(!session)throw new Error('Sessão não encontrada neste Discord.');
        await licensedServer(i.guildId,session.server_id);
        await tx(db=>decision(db,session.id,'approve',i.user.id,'Liberado após revisão da administração.',[],[]));
        await i.editReply('Liberação enviada. O cargo Verificado será aplicado após a confirmação do Rust. Para marcar falsos positivos, revise as evidências no painel.');
      }else await i.editReply('Painel e relatórios: '+publicUrl+'/servidor\nUse /telagem para iniciar uma verificação e /codigo para validar o código do Rust.');
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
      // One worker across all application replicas.
      if(!(await db.query('SELECT pg_try_advisory_lock(827463) AS locked')).rows[0].locked)return;
      const configured=await db.query('SELECT * FROM vorken_guilds');
      for(const config of configured.rows){
        const guild=await client.guilds.fetch(config.id).catch(()=>null);
        if(guild&&!config.verified_role_id)await setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name));
      }
      const tickets=await db.query("SELECT * FROM vorken_sessions WHERE status='redeemed' AND ticket_channel_id IS NULL LIMIT 10");
      for(const s of tickets.rows)await ensureTicket(s).catch(e=>console.error('Vorken ticket:',e.code||e.name));
      const progress=await db.query(`SELECT v.*,a.processing_stage,a.status AS analysis_status FROM vorken_sessions v JOIN analyses a ON a.id=v.analysis_id
        WHERE v.status='redeemed' AND v.ticket_channel_id IS NOT NULL AND v.notified_stage IS DISTINCT FROM a.processing_stage LIMIT 20`);
      for(const s of progress.rows){
        const channel=await client.channels.fetch(s.ticket_channel_id).catch(()=>null);
        if(!channel?.isSendable())continue;
        const labels={waiting:'Aguardando o jogador abrir o Vorken.',collecting:'Coleta em andamento.',processing:'Relatório em processamento.',completed:'Análise concluída. A administração pode revisar as provas no painel.'};
        const findings=s.analysis_status==='completed'?(await db.query('SELECT id,title,severity,artifact_type,artifact_value,evidence FROM scan_findings WHERE analysis_id=$1 ORDER BY id',[s.analysis_id])).rows:null;
        await channel.send({content:'**Vorken:** '+(labels[s.processing_stage]||'Estado da análise: '+s.analysis_status)+'\n'+publicUrl+'/servidor',
          ...(findings?{files:[new AttachmentBuilder(Buffer.from(JSON.stringify(findings,null,2)),{name:'relatorio-vorken-'+s.steam_id+'.json'})]}:{}),allowedMentions:noMentions});
        await db.query('UPDATE vorken_sessions SET notified_stage=$2 WHERE id=$1',[s.id,s.processing_stage]);
      }
      const notices=await db.query('SELECT n.*,g.alerts_channel_id,g.verified_role_id,g.screening_role_id FROM vorken_notices n JOIN vorken_guilds g ON g.id=n.guild_id WHERE n.sent_at IS NULL ORDER BY n.created_at LIMIT 20');
      for(const n of notices.rows){
        try{
          const channel=await client.channels.fetch(n.kind==='decision'?n.payload.channelId:n.alerts_channel_id).catch(()=>null);
          if(!channel?.isSendable())continue;
          const p=n.payload,marker='VORKEN_NOTICE:'+n.id;
          const messages=await channel.messages.fetch({limit:30});
          if(!messages.some(m=>m.author.id===client.user.id&&m.content.includes(marker))){
            if(n.kind==='command'){
              await channel.send({content:'**Telagem · '+p.serverName+'**\nSteamID: '+p.steamId+'\n'+(p.ok?'Confirmada no Rust: ':'Não executada: ')+p.result+'\n'+marker,allowedMentions:noMentions});
            }else if(n.kind==='prior_ban'){
              const summary=p.bans.map(b=>'• '+b.server_name+': '+b.reason).join('\n').slice(0,1400);
              await channel.send({content:'**Alerta: banimento anterior no Vorken**\nJogador: '+p.playerName+' · '+p.steamId+'\nEntrou em: '+p.serverName+'\n'+summary+'\nRevise as provas anexadas antes de decidir. Este alerta não aplica banimento.\n'+marker,
                files:[new AttachmentBuilder(Buffer.from(JSON.stringify(p.bans,null,2)),{name:'provas-vorken-'+p.steamId+'.json'})],allowedMentions:noMentions});
            }else await channel.send({content:'**'+(p.action==='approve'?'Jogador liberado e verificado.':p.action==='cancel'?'Verificação encerrada pelo plugin.':'Banimento confirmado no Rust.')+'**\n'+(p.reason||'')+'\n'+marker,allowedMentions:noMentions});
          }
          if(n.kind==='decision'&&p.discordUserId){
            const guild=await client.guilds.fetch(n.guild_id),member=await guild.members.fetch(p.discordUserId).catch(()=>null);
            if(member){await member.roles.remove(n.screening_role_id);if(p.action==='approve')await member.roles.add(n.verified_role_id);else await member.roles.remove(n.verified_role_id);}
          }
          await db.query('UPDATE vorken_notices SET sent_at=NOW() WHERE id=$1',[n.id]);
        }catch(e){console.error('Vorken notification:',e.code||e.name);}
      }
    }finally{await db.query('SELECT pg_advisory_unlock(827463)').catch(()=>{});db.release();ticking=false;}
  }
  client.once('clientReady',async()=>{
    console.log('Vorken bot conectado.');
    for(const guild of client.guilds.cache.values())await setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name));
    const timer=setInterval(()=>tick().catch(e=>console.error('Vorken worker:',e.code||e.name)),10000);timer.unref();
    await tick();
  });
  client.on('guildCreate',guild=>setup(guild).catch(e=>console.error('Vorken setup:',e.code||e.name)));
  client.on('error',e=>console.error('Vorken Discord:',e.code||e.name));
  await client.login(token);return client;
}
