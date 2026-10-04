import crypto from 'node:crypto';
import { notificationSettings, verificationSettings, canPublish } from './vorkenSettings.js';
import fs from 'node:fs';
import { createDiscordGuildCache } from './discordGuildCache.js';
import { hash, addMonths, licensed, managesGuild, validDiscordInvite, validIds, seal, unseal, serverSlug } from './vorkenDomain.js';

const uuid = value => /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(String(value || ''));
const steam = value => /^7656119\d{10}$/.test(String(value || ''));
const snowflake = value => /^\d{16,20}$/.test(String(value || ''));
const clean = (value, max = 200) => String(value || '').replace(/[\x00-\x1f]/g, ' ').trim().slice(0,max);
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const route = fn => async (req,res) => { try { await fn(req,res); } catch (e) {
  if (!e.status) console.error('Vorken platform:', e.code || e.name);
  if (!res.headersSent) res.status(e.status || 500).json({ message: e.status ? e.message : 'Não foi possível concluir. Tente novamente.' });
}};

export async function initVorkenPlatform(pool) {
  await pool.query(fs.readFileSync(new URL('./vorken-schema.sql', import.meta.url), 'utf8'));
  await pool.query("UPDATE vorken_plans SET price_cents=CASE id WHEN 'mensal' THEN 5000 WHEN 'trimestral' THEN 13500 WHEN 'semestral' THEN 25500 WHEN 'anual' THEN 48000 END WHERE price_cents IS NULL");
}

export async function backfillLegacyVorkenBans(pool){
  // The old integration has one known Discord community. Never guess a customer by name.
  const servers=await pool.query('SELECT id FROM vorken_servers WHERE guild_id=$1',[ '1499084540356853912' ]);
  if(servers.rows.length!==1)return 0;
  const target=servers.rows[0].id;
  const result=await pool.query(`INSERT INTO vorken_bans(id,server_id,steam_id,reason,evidence,created_at,legacy_analysis_id)
    SELECT gen_random_uuid(),$1,a.external_player_id,COALESCE(NULLIF(ep.reason,''),'Banimento confirmado pelo Vorken; motivo original não registrado.'),
      COALESCE(ep.findings,'[]'::jsonb),COALESCE(a.external_decision_at,a.created_at),a.id
    FROM analyses a LEFT JOIN LATERAL(SELECT reason,findings FROM evidence_packages WHERE analysis_id=a.id ORDER BY id DESC LIMIT 1) ep ON TRUE
    WHERE a.external_source IN ('guerra_fria','guerra_fria_manual') AND a.external_decision='deny'
      AND a.external_player_id ~ '^7656119[0-9]{10}$'
      AND NOT EXISTS(SELECT 1 FROM vorken_sessions v WHERE v.analysis_id=a.id)
    ON CONFLICT(legacy_analysis_id) DO NOTHING RETURNING id`,[target]);
  return result.rows.length;
}

export async function importLegacyVerificationBans(pool,records){
 const servers=await pool.query('SELECT id FROM vorken_servers WHERE guild_id=$1',['1499084540356853912']);
 if(servers.rows.length!==1)throw new Error('A comunidade de origem precisa ter exatamente um servidor Rust vinculado.');
 if(!Array.isArray(records))throw new Error('Histórico inválido.');
 let imported=0;
 for(const record of records){
  if(record.action!=='BAN'||record.admin_id!=='SYSTEM'||!['Sistema de Verificação','Prazo da Verificação'].includes(record.admin_name)||!steam(record.steam_id)||!Number.isSafeInteger(record.id)||record.id<=0||!record.reason||!Number.isFinite(new Date(record.created_at).getTime()))continue;
  const active=['BAN','PREVENTIVE_BAN'].includes(record.latest_action)&&(!record.ban_expires_at||new Date(record.ban_expires_at)>new Date());
  const proof=[{type:'verification_policy',title:'Banimento por regra de verificação',reason:clean(record.reason,500),evidence:{source:'Registro confirmado do plugin de verificação',legacyRecordId:record.id,administrator:record.admin_name,latestAction:record.latest_action}}];
  const result=await pool.query(`INSERT INTO vorken_bans(id,server_id,steam_id,player_name,reason,evidence,active,created_at,legacy_source,legacy_record_id,administrator_id,administrator_name)
    VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,'guerra_fria_verification_policy',$8,$9,$10)
    ON CONFLICT(legacy_source,legacy_record_id) DO NOTHING RETURNING id`,[servers.rows[0].id,record.steam_id,clean(record.player_name,100),clean(record.reason,500),JSON.stringify(proof),active,record.created_at,String(record.id),record.admin_id,record.admin_name]);
  imported+=result.rows.length;
 }
 return imported;
}

export function installVorkenPlatform(app, { pool, publicUrl, requireAdmin, learnAnalysisArtifacts, revokeLearnedTrustForFindings, loadAnalysisReport, loadPlayerProfiles, loadRawAnalysisReport }) {
  const auditProfiles=new Map();
  const secret = () => process.env.SESSION_SECRET || '';
  const rootHost=new URL(publicUrl).hostname;
  const cookieOptions = { httpOnly: true, sameSite: 'lax', secure: publicUrl.startsWith('https:'), path: '/',
    ...(process.env.VORKEN_SUBDOMAINS==='true'?{domain:'.'+rootHost}:{}) };
  const origin = new URL(publicUrl).origin;
  const origins=async req=>{
    if(req.get('origin')===origin) return true;
    if(process.env.VORKEN_SUBDOMAINS!=='true') return false;
    try{const url=new URL(req.get('origin'));
      if(url.protocol!=='https:'||url.port||!url.hostname.endsWith('.'+rootHost)) return false;
      const slug=url.hostname.slice(0,-rootHost.length-1);
      return /^[a-z0-9-]+$/.test(slug)&&(await pool.query('SELECT id FROM vorken_servers WHERE slug=$1',[slug])).rows.length>0;
    }catch{return false;}
  };
  const limits = new Map();
  const limit = (key, count = 60) => {
    const now = Date.now(), current = limits.get(key);
    if (limits.size > 10000) for (const [k,v] of limits) if (v.until < now) limits.delete(k);
    if (!current || current.until < now) limits.set(key, { count:1, until:now+60000 });
    else if (++current.count > count) fail(429,'Muitas tentativas. Aguarde um minuto.');
  };
  const csrf = (req,res,next) => {
    origins(req).then(valid=>{
      if (req.get('x-vorken-request') !== 'portal' || !valid)
        return res.status(403).json({ message:'Atualize a página e tente novamente.' });
      next();
    }).catch(()=>res.status(503).json({message:'Serviço temporariamente indisponível.'}));
  };
  const tx = async fn => {
    const c = await pool.connect();
    try { await c.query('BEGIN'); const result = await fn(c); await c.query('COMMIT'); return result; }
    catch(e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
  };
  const customer = async req => {
    const result = await pool.query(`SELECT c.*, l.access_token, l.expires_at AS login_expires
      FROM vorken_logins l JOIN vorken_customers c ON c.id=l.customer_id
      WHERE l.token_hash=$1 AND l.expires_at>NOW() AND c.status='active'`, [hash(req.cookies?.vorken_customer || '')]);
    if (!result.rows[0]) fail(401,'Entre com sua conta do Discord.');
    return result.rows[0];
  };
  const domainUrl=s=>process.env.VORKEN_SUBDOMAINS==='true'&&s.slug?'https://'+s.slug+'.'+rootHost+'/servidor':publicUrl+'/servidor';
  app.get('/api/vorken/site',route(async(req,res)=>{
    const hostname=String(req.hostname).toLowerCase();
    if(hostname===rootHost||!hostname.endsWith('.'+rootHost)) return res.json({name:'Vorken',server:null});
    const slug=hostname.slice(0,-rootHost.length-1);
    const s=(await pool.query('SELECT id,name,discord_invite,slug FROM vorken_servers WHERE slug=$1 AND enabled',[slug])).rows[0];
    if(!s) fail(404,'Servidor não encontrado.');
    res.json({name:s.name,server:s});
  }));
  const entitlement = async (id, db=pool) => {
    const r = await db.query(`SELECT c.status,l.status AS license_status,l.expires_at AS license_until,l.max_servers,l.plan_id
      FROM vorken_customers c LEFT JOIN vorken_licenses l ON l.customer_id=c.id WHERE c.id=$1`, [id]);
    return r.rows[0];
  };
  const serverActive=async(server,db=pool)=>{
    if(!server.enabled) return false;
    const e=await entitlement(server.customer_id,db);
    if(!licensed(e)) return false;
    const r=await db.query(`SELECT COUNT(*)::int AS rank FROM vorken_servers WHERE customer_id=$1 AND enabled
      AND (created_at,id)<=(SELECT created_at,id FROM vorken_servers WHERE id=$2)`,[server.customer_id,server.id]);
    return r.rows[0].rank<=e.max_servers;
  };
  const discord = async (endpoint, accessToken) => {
    const r = await fetch('https://discord.com/api/v10'+endpoint, { headers:{ Authorization:'Bearer '+accessToken }, signal:AbortSignal.timeout(10000) });
    if(r.status===429){
      const body=await r.json().catch(()=>({}));
      const seconds=Number(r.headers.get('retry-after')||body.retry_after);
      const retryAfter=Number.isFinite(seconds)&&seconds>0?seconds:1;
      throw Object.assign(new Error('O Discord limitou temporariamente as consultas. Aguarde '+Math.ceil(retryAfter)+' segundos e clique em Atualizar.'),{status:429,retryAfter});
    }
    if(r.status===401||r.status===403)fail(401,'Sua autorização do Discord expirou ou foi revogada. Saia e entre novamente com Discord.');
    if(!r.ok)fail(503,'O Discord está temporariamente indisponível. Tente atualizar em instantes.');
    return r.json();
  };
  const cachedGuilds=createDiscordGuildCache(async sealedToken=>(await discord('/users/@me/guilds',unseal(sealedToken,secret()))).filter(managesGuild));
  const guilds = user => cachedGuilds(user.access_token);
  const ownedServer = async (id,customerId,db=pool) => {
    if (!uuid(id)) fail(400,'Servidor inválido.');
    const r = await db.query('SELECT * FROM vorken_servers WHERE id=$1 AND customer_id=$2', [id,customerId]);
    if (!r.rows[0]) fail(404,'Servidor não encontrado.');
    return r.rows[0];
  };
  const accessSql=alias=>`(${alias}.customer_id=$2 OR EXISTS(SELECT 1 FROM vorken_team t WHERE t.server_id=${alias}.id AND t.customer_id=$2))`;
  const accessibleServer=async(id,userId,db=pool)=>{
    if(!uuid(id))fail(400,'Servidor inválido.');
    const s=(await db.query('SELECT s.* FROM vorken_servers s WHERE s.id=$1 AND '+accessSql('s'),[id,userId])).rows[0];
    if(!s)fail(404,'Servidor não encontrado.');return s;
  };
  const botApi=async endpoint=>{
    if(!process.env.VORKEN_DISCORD_BOT_TOKEN)fail(503,'Bot ainda não configurado.');
    const r=await fetch('https://discord.com/api/v10'+endpoint,{headers:{Authorization:'Bot '+process.env.VORKEN_DISCORD_BOT_TOKEN},signal:AbortSignal.timeout(10000)});
    if(!r.ok)fail(503,'Adicione o bot ao Discord e confira suas permissões.');return r.json();
  };
  const publishChannels=async server=>{
    const [channels,roles,member]=await Promise.all([botApi('/guilds/'+server.guild_id+'/channels'),botApi('/guilds/'+server.guild_id+'/roles'),botApi('/guilds/'+server.guild_id+'/members/'+process.env.VORKEN_DISCORD_CLIENT_ID)]);
    return channels.filter(c=>canPublish(c,server.guild_id,member,roles)).map(c=>({id:c.id,name:c.name}));
  };
  const audit = (db, actor,action,target,details={}) => db.query('INSERT INTO vorken_audit(actor,action,target,details) VALUES($1,$2,$3,$4)',[actor,action,target,JSON.stringify(details)]);
  const queue = async (db,serverId,action,steamId,actorId,sessionId=null,reason='',evidence=[],trusted=[]) => {
    const id=crypto.randomUUID();
    await db.query(`INSERT INTO vorken_commands(id,server_id,action,steam_id,actor_id,session_id,reason,evidence_ids,trusted_ids)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,serverId,action,steamId,actorId,sessionId,reason,JSON.stringify(evidence),JSON.stringify(trusted)]);
    return id;
  };
  async function decision(db, sessionId, action, actor, reason, evidenceIds, trustedIds) {
    const r=await db.query(`SELECT v.*,s.guild_id,s.customer_id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id WHERE v.id=$1 FOR UPDATE OF v`,[sessionId]);
    const s=r.rows[0]; if (!s || s.status!=='redeemed' || !s.analysis_id) fail(409,'Esta sessão não está disponível para decisão.');
    const analysis=await db.query('SELECT status,processing_stage FROM analyses WHERE id=$1',[s.analysis_id]);
    if (analysis.rows[0]?.status!=='completed'||analysis.rows[0]?.processing_stage!=='completed') fail(409,'Aguarde a conclusão bem-sucedida da análise.');
    if (action==='deny' && (!reason || !evidenceIds.length)) fail(400,'Informe o motivo e selecione as provas do banimento.');
    const selected=[...new Set([...evidenceIds,...trustedIds])];
    if (selected.length) {
      const matches=await db.query('SELECT id FROM scan_findings WHERE analysis_id=$1 AND id=ANY($2::bigint[])',[s.analysis_id,selected]);
      if (matches.rows.length!==selected.length) fail(400,'Evidência não pertence a esta análise.');
    }
    await db.query("UPDATE vorken_sessions SET status='deciding' WHERE id=$1",[s.id]);
    const commandId=await queue(db,s.server_id,action,s.steam_id,actor,s.id,reason,evidenceIds,trustedIds);
    await audit(db,actor,'decision_requested',s.id,{ action,commandId,evidenceIds,trustedIds });
    return commandId;
  }
  const notify=async (db,guildId,kind,payload) => db.query('INSERT INTO vorken_notices(id,guild_id,kind,payload) VALUES($1,$2,$3,$4)',[crypto.randomUUID(),guildId,kind,JSON.stringify(payload)]);

  // The owner and customers share the same operations, with separate authorization.
  for(const owner of [false,true]){
    const base='/api/vorken/'+(owner?'admin/':'')+'operations';
    const auth=owner?[requireAdmin]:[];
    const identity=async req=>owner?{id:null,actor:'owner'}:{id:(await customer(req)).id,actor:null};
    const accessible=async(req,db=pool)=>{
      const u=await identity(req);
      if(!uuid(req.params.serverId))fail(400,'Servidor inválido.');
      const s=(await db.query('SELECT * FROM vorken_servers WHERE id=$1'+(owner?'':' AND '+accessSql('vorken_servers')),owner?[req.params.serverId]:[req.params.serverId,u.id])).rows[0];
      if(!s)fail(404,'Servidor não encontrado.');
      return {s,actor:owner?'owner':'customer:'+u.id};
    };
    app.get(base,...auth,route(async(req,res)=>{
      const u=await identity(req);
      const r=await pool.query(`SELECT s.id,s.name,s.customer_id,s.enabled,s.last_seen,c.name AS customer_name
        FROM vorken_servers s JOIN vorken_customers c ON c.id=s.customer_id ${owner?'':'WHERE (s.customer_id=$1 OR EXISTS(SELECT 1 FROM vorken_team t WHERE t.server_id=s.id AND t.customer_id=$1))'} ORDER BY c.name,s.name`,owner?[]:[u.id]);
      res.set('Cache-Control','no-store').json({servers:r.rows});
    }));
    app.get(base+'/:serverId',...auth,route(async(req,res)=>{
      const {s}=await accessible(req);
      const connected=!!s.last_seen&&Date.now()-new Date(s.last_seen)<90000;
      const fresh=connected&&!!s.players_updated_at&&Date.now()-new Date(s.players_updated_at)<30000;
      const sessions=await pool.query(`SELECT v.id,v.steam_id,v.player_name,v.status,v.analysis_id,a.status AS analysis_status,a.processing_stage
        FROM vorken_sessions v LEFT JOIN analyses a ON a.id=v.analysis_id WHERE v.server_id=$1 ORDER BY v.created_at DESC LIMIT 100`,[s.id]);
      const commands=await pool.query("SELECT id,steam_id,status,result FROM vorken_commands WHERE server_id=$1 AND action='start' AND created_at>NOW()-interval '10 minutes' ORDER BY created_at DESC LIMIT 100",[s.id]);
      res.set('Cache-Control','no-store').json({connected,fresh,active:await serverActive(s),updatedAt:s.players_updated_at,players:fresh?s.online_players:[],sessions:sessions.rows,commands:commands.rows});
    }));
    app.post(base+'/:serverId/telagem',...auth,csrf,route(async(req,res)=>{
      if(!steam(req.body.steamId))fail(400,'SteamID inválido.');
      const id=await tx(async db=>{
        const {s,actor}=await accessible(req,db);
        await db.query('SELECT id FROM vorken_servers WHERE id=$1 FOR UPDATE',[s.id]);
        const current=(await db.query('SELECT * FROM vorken_servers WHERE id=$1',[s.id])).rows[0];
        if(!await serverActive(current,db))fail(403,'Servidor ou licença inativa.');
        if(!current.players_updated_at||Date.now()-new Date(current.players_updated_at)>30000)fail(409,'Lista desatualizada. Aguarde a conexão do plugin.');
        if(!current.online_players.some(p=>p.steamId===req.body.steamId))fail(409,'Jogador não está online neste servidor.');
        const pending=await db.query(`SELECT id FROM vorken_sessions WHERE server_id=$1 AND steam_id=$2 AND status IN ('pending','redeemed','deciding')
          UNION ALL SELECT id FROM vorken_commands WHERE server_id=$1 AND steam_id=$2 AND action='start' AND status='pending'`,[s.id,req.body.steamId]);
        if(pending.rows.length)fail(409,'Esse jogador já tem uma telagem em andamento.');
        const command=await queue(db,s.id,'start',req.body.steamId,actor);
        await audit(db,actor,'screening_requested',s.id,{steamId:req.body.steamId,commandId:command});return command;
      });res.json({commandId:id,message:'Telagem enviada. Aguardando confirmação do Rust.'});
    }));
    app.get(base+'/:serverId/sessions/:id/report',...auth,route(async(req,res)=>{
      const {s}=await accessible(req);if(!uuid(req.params.id))fail(400,'Sessão inválida.');
      const session=(await pool.query('SELECT v.*,a.status AS analysis_status,a.processing_stage FROM vorken_sessions v LEFT JOIN analyses a ON a.id=v.analysis_id WHERE v.id=$1 AND v.server_id=$2',[req.params.id,s.id])).rows[0];
      if(!session)fail(404,'Sessão não encontrada.');
      const findings=(await pool.query('SELECT id,title,severity,artifact_type,artifact_value,evidence FROM scan_findings WHERE analysis_id=$1 ORDER BY id',[session.analysis_id])).rows;
      const full=loadAnalysisReport?await loadAnalysisReport(session.analysis_id,s.id):null;
      res.json({session,findings,...(full||{})});
    }));
    app.get(base+'/:serverId/sessions/:id/raw',...auth,route(async(req,res)=>{
      const {s}=await accessible(req);if(!uuid(req.params.id))fail(400,'Sessão inválida.');
      const session=(await pool.query('SELECT analysis_id FROM vorken_sessions WHERE id=$1 AND server_id=$2',[req.params.id,s.id])).rows[0];
      if(!session)fail(404,'Sessão não encontrada.');
      const payload=loadRawAnalysisReport?await loadRawAnalysisReport(session.analysis_id):null;
      if(!payload)fail(404,'Relatório não encontrado.');
      res.attachment('vorken-analysis-'+session.analysis_id+'-raw.json').type('application/json').send(JSON.stringify(payload,null,2));
    }));
    app.post(base+'/:serverId/sessions/:id/decision',...auth,csrf,route(async(req,res)=>{
      const {s,actor}=await accessible(req);
      const action=['approve','deny'].includes(req.body.decision)?req.body.decision:null;
      const evidence=validIds(req.body.evidenceIds||[]),trusted=validIds(req.body.trustedIds||[]);
      if(!uuid(req.params.id)||!action||!evidence||!trusted||evidence.some(id=>trusted.includes(id)))fail(400,'Decisão inválida.');
      const id=await tx(async db=>{
        if(!await serverActive(s,db))fail(403,'Servidor ou licença inativa.');
        if(!(await db.query('SELECT id FROM vorken_sessions WHERE id=$1 AND server_id=$2',[req.params.id,s.id])).rows.length)fail(404,'Sessão não encontrada.');
        return decision(db,req.params.id,action,actor,clean(req.body.reason,500),evidence,trusted);
      });res.json({commandId:id,message:'Decisão enviada. Aguardando confirmação do Rust.'});
    }));
  }

  app.get('/api/vorken/plans',route(async(_req,res)=>{
    const r=await pool.query('SELECT * FROM vorken_plans WHERE enabled ORDER BY months');
    res.json({ plans:r.rows, billingReady:!!(process.env.MERCADO_PAGO_ACCESS_TOKEN && process.env.MERCADO_PAGO_WEBHOOK_SECRET),
      discordReady:!!(process.env.VORKEN_DISCORD_CLIENT_ID && process.env.VORKEN_DISCORD_CLIENT_SECRET && secret().length>=32) });
  }));
  app.get('/api/vorken/auth/discord',route(async(req,res)=>{
    limit('oauth:'+req.ip,20);
    if (!process.env.VORKEN_DISCORD_CLIENT_ID || !process.env.VORKEN_DISCORD_CLIENT_SECRET || secret().length<32) fail(503,'O cadastro será disponibilizado após a configuração do Discord.');
    const state=crypto.randomBytes(24).toString('base64url');
    res.cookie('vorken_oauth_state',state,{...cookieOptions,maxAge:600000});
    const q=new URLSearchParams({ client_id:process.env.VORKEN_DISCORD_CLIENT_ID,redirect_uri:publicUrl+'/api/vorken/auth/callback',
      response_type:'code',scope:'identify email guilds',state });
    res.redirect('https://discord.com/oauth2/authorize?'+q);
  }));
  app.get('/api/vorken/auth/callback',route(async(req,res)=>{
    if (!req.query.state || req.query.state!==req.cookies?.vorken_oauth_state) fail(403,'Autorização expirada. Tente entrar novamente.');
    res.clearCookie('vorken_oauth_state',cookieOptions);
    if (!req.query.code) fail(400,'A autorização do Discord foi cancelada.');
    const response=await fetch('https://discord.com/api/v10/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({client_id:process.env.VORKEN_DISCORD_CLIENT_ID,client_secret:process.env.VORKEN_DISCORD_CLIENT_SECRET,
        grant_type:'authorization_code',code:String(req.query.code),redirect_uri:publicUrl+'/api/vorken/auth/callback'}),signal:AbortSignal.timeout(10000)});
    if (!response.ok) fail(401,'Não foi possível autorizar sua conta.');
    const token=await response.json(), profile=await discord('/users/@me',token.access_token);
    const r=await pool.query(`INSERT INTO vorken_customers(id,discord_id,name,email) VALUES($1,$2,$3,$4)
      ON CONFLICT(discord_id) DO UPDATE SET name=EXCLUDED.name,email=EXCLUDED.email RETURNING *`,
      [crypto.randomUUID(),profile.id,clean(profile.global_name||profile.username),profile.email||null]);
    if (r.rows[0].status!=='active') fail(403,'Cadastro suspenso. Entre em contato com o suporte.');
    const login=crypto.randomBytes(32).toString('base64url'), ttl=Math.min(Number(token.expires_in),86400);
    await pool.query('DELETE FROM vorken_logins WHERE expires_at<NOW()');
    await pool.query('INSERT INTO vorken_logins(token_hash,customer_id,access_token,expires_at) VALUES($1,$2,$3,NOW()+$4*interval \'1 second\')',
      [hash(login),r.rows[0].id,seal(token.access_token,secret()),ttl]);
    res.cookie('vorken_customer',login,{...cookieOptions,maxAge:ttl*1000}); res.redirect('/servidor');
  }));
  app.post('/api/vorken/logout',csrf,route(async(req,res)=>{
    await pool.query('DELETE FROM vorken_logins WHERE token_hash=$1',[hash(req.cookies?.vorken_customer||'')]);
    res.clearCookie('vorken_customer',cookieOptions); res.json({ok:true});
  }));
  app.get('/api/vorken/me',route(async(req,res)=>{
    const u=await customer(req), e=await entitlement(u.id);
    const [servers,orders]=await Promise.all([
      pool.query('SELECT s.id,s.name,s.slug,s.guild_id,s.discord_invite,s.enabled,s.last_seen,s.plugin_version,(s.customer_id=$1) AS owned FROM vorken_servers s WHERE s.customer_id=$1 OR EXISTS(SELECT 1 FROM vorken_team t WHERE t.server_id=s.id AND t.customer_id=$1) ORDER BY s.created_at DESC',[u.id]),
      pool.query('SELECT id,plan_id,price_cents,status,created_at,checkout_url FROM vorken_orders WHERE customer_id=$1 ORDER BY created_at DESC LIMIT 50',[u.id])]);
    res.json({customer:{id:u.id,name:u.name,discord_id:u.discord_id},license:{...e,active:licensed(e)},servers:servers.rows.map(s=>({...s,portalUrl:domainUrl(s)})),orders:orders.rows,guilds:await guilds(u)});
  }));
  app.post('/api/vorken/servers',csrf,route(async(req,res)=>{
    const u=await customer(req); limit('create:'+u.id,10);
    const name=clean(req.body.name,80), guildId=String(req.body.guildId||''), invite=String(req.body.discordInvite||'');
    if (!name || !validDiscordInvite(invite)) fail(400,'Informe o nome e um convite válido do Discord.');
    const managed=(await guilds(u)).find(g=>g.id===guildId);
    if (!managed) fail(403,'Você precisa administrar esse Discord.');
    const id=await tx(async db=>{
      await db.query('SELECT id FROM vorken_customers WHERE id=$1 FOR UPDATE',[u.id]);
      const e=await entitlement(u.id,db); if (!licensed(e)) fail(403,'Ative uma licença antes de adicionar servidores.');
      const total=await db.query('SELECT COUNT(*)::int AS n FROM vorken_servers WHERE customer_id=$1 AND enabled',[u.id]);
      if (total.rows[0].n>=e.max_servers) fail(409,'Você atingiu o limite de servidores da licença.');
      const g=await db.query('SELECT customer_id FROM vorken_guilds WHERE id=$1',[guildId]);
      if (g.rows[0] && g.rows[0].customer_id!==u.id) fail(409,'Esse Discord já está vinculado a outro cadastro.');
      await db.query('INSERT INTO vorken_guilds(id,customer_id,name) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name',[guildId,u.id,managed.name]);
      const id=crypto.randomUUID();
      // Serialize allocation so simultaneous registrations get different addresses.
      await db.query("SELECT pg_advisory_xact_lock(827462)");
      const base=serverSlug(name); let slug=base, counter=2;
      while((await db.query('SELECT id FROM vorken_servers WHERE slug=$1',[slug])).rows.length) slug=base+'-'+counter++;
      await db.query('INSERT INTO vorken_servers(id,customer_id,guild_id,name,discord_invite,token_hash,slug) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,u.id,guildId,name,invite,hash(crypto.randomBytes(32)),slug]);
      await audit(db,u.id,'server_created',id); return id;
    }); res.status(201).json({id});
  }));
  app.patch('/api/vorken/servers/:id',csrf,route(async(req,res)=>{
    const u=await customer(req); await ownedServer(req.params.id,u.id);
    if (!clean(req.body.name,80) || !validDiscordInvite(req.body.discordInvite)) fail(400,'Nome e convite do Discord inválidos.');
    await pool.query('UPDATE vorken_servers SET name=$2,discord_invite=$3 WHERE id=$1',[req.params.id,clean(req.body.name,80),req.body.discordInvite]);
    res.json({ok:true});
  }));
  app.get('/api/vorken/servers/:id/settings',route(async(req,res)=>{
    const u=await customer(req),s=await accessibleServer(req.params.id,u.id);
    res.json({name:s.name,discordInvite:s.discord_invite,owned:s.customer_id===u.id,settings:notificationSettings(s.notification_settings),verification:verificationSettings(s.verification_settings),defaultVerification:verificationSettings(),channels:await publishChannels(s)});
  }));
  app.patch('/api/vorken/servers/:id/settings',csrf,route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id),v=req.body.settings;
    if(!v||typeof v!=='object')fail(400,'Configuração inválida.');
    const settings=notificationSettings();
    for(const key of Object.keys(settings)){
      if(key.endsWith('ChannelId')){if(v[key]!==null&&!snowflake(v[key]))fail(400,'Canal inválido.');settings[key]=v[key];}
      else {if(typeof v[key]!=='boolean')fail(400,'Opção inválida.');settings[key]=v[key];}
    }
    const channels=await publishChannels(s);
    for(const id of [settings.banChannelId,settings.verifiedChannelId])if(id&&!channels.some(c=>c.id===id))fail(400,'Escolha um canal deste Discord onde o bot possa publicar.');
    const verification=verificationSettings(s.verification_settings);
    if(req.body.verification){
      const v=req.body.verification;
      if(typeof v.rules!=='string'||v.rules.length>2000||typeof v.introduction!=='string'||!v.introduction.trim()||v.introduction.length>180||!/^#[0-9a-f]{6}$/i.test(v.color)||!Number.isInteger(v.timeoutSeconds)||v.timeoutSeconds<60||v.timeoutSeconds>3600||v.timeoutSeconds%60)fail(400,'Regras, cor ou prazo inválidos. Use de 1 a 60 minutos.');
      for(const key of ['banOnTimeout','banOnRefusal','banOnDisconnect','showRules'])if(typeof v[key]!=='boolean')fail(400,'Opção de verificação inválida.');
      Object.assign(verification,{rules:v.rules,introduction:clean(v.introduction,180),color:v.color,timeoutSeconds:v.timeoutSeconds,banOnTimeout:v.banOnTimeout,banOnRefusal:v.banOnRefusal,banOnDisconnect:v.banOnDisconnect,showRules:v.showRules});
    }
    await pool.query('UPDATE vorken_servers SET notification_settings=$2,verification_settings=$3 WHERE id=$1',[s.id,JSON.stringify(settings),JSON.stringify(verification)]);
    await audit(pool,u.id,'notification_settings',s.id,settings);res.json({ok:true});
  }));
  app.get('/api/vorken/servers/:id/team',route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);
    const members=await pool.query('SELECT c.id,c.name,c.discord_id,t.created_at FROM vorken_team t JOIN vorken_customers c ON c.id=t.customer_id WHERE t.server_id=$1',[s.id]);
    const invites=await pool.query('SELECT id,discord_id,expires_at FROM vorken_invites WHERE server_id=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>NOW()',[s.id]);
    res.json({members:members.rows,invites:invites.rows});
  }));
  app.post('/api/vorken/servers/:id/team/invites',csrf,route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);limit('invite:'+u.id,10);
    if(!snowflake(req.body.discordId))fail(400,'Informe o ID Discord do administrador convidado.');
    const token=crypto.randomBytes(32).toString('base64url'),id=crypto.randomUUID();
    await pool.query("INSERT INTO vorken_invites(id,server_id,token_hash,discord_id,created_by,expires_at) VALUES($1,$2,$3,$4,$5,NOW()+interval '7 days')",[id,s.id,hash(token),req.body.discordId,u.id]);
    await audit(pool,u.id,'team_invited',s.id,{discordId:req.body.discordId});
    res.status(201).json({id,url:publicUrl+'/servidor#convite='+token});
  }));
  app.post('/api/vorken/team/accept',csrf,route(async(req,res)=>{
    const u=await customer(req);limit('accept:'+u.id,10);
    if(!/^[\w-]{43}$/.test(String(req.body.token||'')))fail(400,'Convite inválido.');
    const result=await tx(async db=>{
      const i=(await db.query('SELECT i.*,s.customer_id,s.name,s.guild_id FROM vorken_invites i JOIN vorken_servers s ON s.id=i.server_id WHERE i.token_hash=$1 FOR UPDATE OF i',[hash(req.body.token)])).rows[0];
      if(!i||i.used_at||i.revoked_at||new Date(i.expires_at)<=new Date()||i.discord_id!==u.discord_id||i.created_by!==i.customer_id)fail(403,'Convite inválido, expirado ou destinado a outra conta Discord.');
      if(!(await guilds(u)).some(g=>g.id===i.guild_id))fail(403,'Sua conta deve administrar o Discord deste servidor.');
      await botApi('/guilds/'+i.guild_id+'/members/'+u.discord_id);
      await db.query('INSERT INTO vorken_team(server_id,customer_id,granted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[i.server_id,u.id,i.created_by]);
      await db.query('UPDATE vorken_invites SET used_at=NOW() WHERE id=$1',[i.id]);
      await audit(db,u.id,'team_joined',i.server_id);return {name:i.name};
    });res.json(result);
  }));
  app.delete('/api/vorken/servers/:id/team/:memberId',csrf,route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);
    if(!uuid(req.params.memberId))fail(400,'Membro inválido.');
    await tx(async db=>{
      const member=(await db.query('SELECT discord_id FROM vorken_customers WHERE id=$1',[req.params.memberId])).rows[0];
      await db.query('DELETE FROM vorken_team WHERE server_id=$1 AND customer_id=$2',[s.id,req.params.memberId]);
      if(member)await db.query('UPDATE vorken_invites SET revoked_at=NOW() WHERE server_id=$1 AND discord_id=$2 AND used_at IS NULL',[s.id,member.discord_id]);
      await audit(db,u.id,'team_removed',s.id,{memberId:req.params.memberId});
    });res.json({ok:true});
  }));
  app.delete('/api/vorken/servers/:id/invites/:inviteId',csrf,route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);
    if(!uuid(req.params.inviteId))fail(400,'Convite inválido.');
    await pool.query('UPDATE vorken_invites SET revoked_at=NOW() WHERE id=$1 AND server_id=$2',[req.params.inviteId,s.id]);res.json({ok:true});
  }));
  app.get('/api/vorken/servers/:id/bot',route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);
    if (!process.env.VORKEN_DISCORD_CLIENT_ID) fail(503,'Bot ainda não configurado.');
    const q=new URLSearchParams({client_id:process.env.VORKEN_DISCORD_CLIENT_ID,scope:'bot applications.commands',
      permissions:'268553232',guild_id:s.guild_id,disable_guild_select:'true',integration_type:'0'});
    res.redirect('https://discord.com/oauth2/authorize?'+q);
  }));
  app.post('/api/vorken/servers/:id/plugin',csrf,route(async(req,res)=>{
    const u=await customer(req),s=await ownedServer(req.params.id,u.id);
    if (!await serverActive(s)) fail(403,'Sua licença ou servidor está inativo, ou excede o limite contratado.');
    if (!publicUrl.startsWith('https:')) fail(503,'Configure o endereço HTTPS público antes de baixar o plugin.');
    const token=crypto.randomBytes(32).toString('base64url');
    let source=fs.readFileSync(new URL('./plugins/Vorken.cs',import.meta.url),'utf8');
    source=source.replace('__VORKEN_API__',publicUrl).replace('__VORKEN_INSTALLATION__',token);
    await tx(async db=>{
      await db.query('UPDATE vorken_servers SET token_hash=$2,last_seen=NULL WHERE id=$1',[s.id,hash(token)]);
      await audit(db,u.id,'plugin_rotated',s.id);
    });
    res.set({'Content-Type':'text/plain; charset=utf-8','Content-Disposition':'attachment; filename="Vorken.cs"','Cache-Control':'no-store'}).send(source);
  }));
  app.get('/api/vorken/sessions',route(async(req,res)=>{
    const u=await customer(req);
    const r=await pool.query(`SELECT v.*,s.name AS server_name,a.status AS analysis_status,a.processing_stage,a.external_decision
      FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id LEFT JOIN analyses a ON a.id=v.analysis_id
      WHERE (s.customer_id=$1 OR EXISTS(SELECT 1 FROM vorken_team t WHERE t.server_id=s.id AND t.customer_id=$1)) ORDER BY v.created_at DESC LIMIT 100`,[u.id]);
    res.json({sessions:r.rows});
  }));
  app.get('/api/vorken/sessions/:id/report',route(async(req,res)=>{
    const u=await customer(req); if (!uuid(req.params.id)) fail(400,'Sessão inválida.');
    const r=await pool.query(`SELECT v.*,a.status AS analysis_status,a.processing_stage FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id
      LEFT JOIN analyses a ON a.id=v.analysis_id WHERE v.id=$1 AND ${accessSql('s')}`,[req.params.id,u.id]);
    const s=r.rows[0]; if(!s) fail(404,'Sessão não encontrada.');
    const findings=await pool.query('SELECT id,title,severity,artifact_type,artifact_value,evidence FROM scan_findings WHERE analysis_id=$1 ORDER BY id',[s.analysis_id]);
    const full=loadAnalysisReport?await loadAnalysisReport(s.analysis_id,s.server_id):null;
    res.json({session:s,findings:findings.rows,...(full||{})});
  }));
  app.get('/api/vorken/sessions/:id/raw',route(async(req,res)=>{
    const u=await customer(req);if(!uuid(req.params.id))fail(400,'Sessão inválida.');
    const session=(await pool.query(`SELECT v.analysis_id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id WHERE v.id=$1 AND ${accessSql('s')}`,[req.params.id,u.id])).rows[0];
    if(!session)fail(404,'Sessão não encontrada.');
    const payload=loadRawAnalysisReport?await loadRawAnalysisReport(session.analysis_id):null;
    if(!payload)fail(404,'Relatório não encontrado.');
    res.attachment('vorken-analysis-'+session.analysis_id+'-raw.json').type('application/json').send(JSON.stringify(payload,null,2));
  }));
  app.post('/api/vorken/sessions/:id/decision',csrf,route(async(req,res)=>{
    const u=await customer(req), action=req.body.decision==='approve'?'approve':req.body.decision==='deny'?'deny':null;
    const evidence=validIds(req.body.evidenceIds||[]),trusted=validIds(req.body.trustedIds||[]);
    if(!uuid(req.params.id)||!action||!evidence||!trusted) fail(400,'Decisão inválida.');
    if(evidence.some(id=>trusted.includes(id))) fail(400,'Uma prova de banimento não pode ser marcada como confiável.');
    const id=await tx(async db=>{
      const r=await db.query(`SELECT v.id FROM vorken_sessions v JOIN vorken_servers s ON s.id=v.server_id WHERE v.id=$1 AND ${accessSql('s')}`,[req.params.id,u.id]);
      if(!r.rows[0]) fail(404,'Sessão não encontrada.');
      return decision(db,req.params.id,action,u.discord_id,clean(req.body.reason,500),evidence,trusted);
    });res.json({ok:true,commandId:id,message:'Decisão enviada. Aguardando confirmação do plugin.'});
  }));

  // Mercado Pago: cada compra renova o período escolhido, sem renovação automática.
  const mp=async (path,body,idempotency) => {
    const r=await fetch('https://api.mercadopago.com'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+process.env.MERCADO_PAGO_ACCESS_TOKEN,
      'Content-Type':'application/json',...(idempotency?{'X-Idempotency-Key':idempotency}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(12000)});
    if(!r.ok) fail(503,'O Mercado Pago não respondeu. Tente novamente.');
    return r.json();
  };
  app.post('/api/vorken/checkout',csrf,route(async(req,res)=>{
    const u=await customer(req);limit('checkout:'+u.id,5);
    if(!process.env.MERCADO_PAGO_ACCESS_TOKEN||!process.env.MERCADO_PAGO_WEBHOOK_SECRET||!publicUrl.startsWith('https:')) fail(503,'Pagamento ainda não disponível. Entre em contato com o suporte.');
    const p=(await pool.query('SELECT * FROM vorken_plans WHERE id=$1 AND enabled',[req.body.planId])).rows[0];
    if(!p?.price_cents) fail(400,'Plano indisponível.');
    const id=crypto.randomUUID();
    await pool.query('INSERT INTO vorken_orders(id,customer_id,plan_id,price_cents,months,max_servers,provider) VALUES($1,$2,$3,$4,$5,$6,\'mercadopago\')',[id,u.id,p.id,p.price_cents,p.months,p.max_servers]);
    const checkout=await mp('/checkout/preferences',{external_reference:id,items:[{id:p.id,title:'Vorken · '+p.name,quantity:1,currency_id:'BRL',unit_price:p.price_cents/100}],
      notification_url:publicUrl+'/api/vorken/payments/webhook',back_urls:{success:publicUrl+'/servidor?pagamento=retorno',pending:publicUrl+'/servidor?pagamento=pendente',failure:publicUrl+'/servidor?pagamento=falhou'},auto_return:'approved'},id);
    const checkoutUrl=process.env.MERCADO_PAGO_SANDBOX==='true'?checkout.sandbox_init_point:checkout.init_point;
    if(!checkoutUrl) fail(503,'Checkout indisponível. Confira as credenciais do Mercado Pago.');
    await pool.query('UPDATE vorken_orders SET provider_id=$2,checkout_url=$3 WHERE id=$1',[id,checkout.id,checkoutUrl]);
    res.json({url:checkoutUrl});
  }));
  async function processPayment(payment) {
    if(!uuid(payment.external_reference)) return;
    if(payment.live_mode!==(process.env.MERCADO_PAGO_SANDBOX!=='true')) fail(400,'Pagamento pertence a outro ambiente.');
    await tx(async db=>{
      const r=await db.query('SELECT * FROM vorken_orders WHERE id=$1 FOR UPDATE',[payment.external_reference]),order=r.rows[0];
      if(!order||payment.currency_id!=='BRL'||Math.round(Number(payment.transaction_amount)*100)!==order.price_cents) fail(400,'Pagamento não corresponde ao pedido.');
      if(['refunded','charged_back'].includes(payment.status) && order.status==='paid'){
        await db.query("UPDATE vorken_orders SET status=$2 WHERE id=$1",[order.id,payment.status]);
        await db.query("UPDATE vorken_licenses SET status='suspended' WHERE customer_id=$1",[order.customer_id]);
        await audit(db,'mercadopago','payment_reversed',order.id,{paymentId:payment.id}); return;
      }
    if(payment.status!=='approved'||Number(payment.transaction_amount_refunded||0)>0||order.status!=='pending') return;
      await db.query('SELECT id FROM vorken_customers WHERE id=$1 FOR UPDATE',[order.customer_id]);
      const old=await entitlement(order.customer_id,db);
      const base=old?.license_status==='active' && new Date(old.license_until)>new Date()?new Date(old.license_until):new Date();
      const until=addMonths(base,order.months);
      await db.query(`INSERT INTO vorken_licenses(customer_id,plan_id,status,expires_at,max_servers) VALUES($1,$2,'active',$3,$4)
        ON CONFLICT(customer_id) DO UPDATE SET plan_id=$2,status='active',expires_at=$3,max_servers=$4`,[order.customer_id,order.plan_id,until,order.max_servers]);
      await db.query("UPDATE vorken_orders SET status='paid',paid_at=NOW() WHERE id=$1",[order.id]);
      await audit(db,'mercadopago','payment_confirmed',order.id,{paymentId:payment.id,until});
    });
  }
  app.post('/api/vorken/payments/webhook',route(async(req,res)=>{
    const id=String(req.query['data.id']||''), requestId=req.get('x-request-id')||'';
    const fields=Object.fromEntries(String(req.get('x-signature')||'').split(',').map(x=>x.trim().split('=')));
    if(!process.env.MERCADO_PAGO_WEBHOOK_SECRET||!/^\d+$/.test(id)||!fields.ts||!fields.v1||!requestId) fail(401,'Assinatura inválida.');
    const digest=crypto.createHmac('sha256',process.env.MERCADO_PAGO_WEBHOOK_SECRET).update('id:'+id+';request-id:'+requestId+';ts:'+fields.ts+';').digest('hex');
    const a=Buffer.from(digest),b=Buffer.from(fields.v1);
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) fail(401,'Assinatura inválida.');
    if(req.body.type!=='payment') return res.json({ok:true});
    await processPayment(await mp('/v1/payments/'+id));res.json({ok:true});
  }));
  app.get('/api/vorken/alerts/:id',route(async(req,res)=>{
    const u=await customer(req);if(!uuid(req.params.id))fail(400,'Alerta inválido.');
    const r=await pool.query(`SELECT n.payload FROM vorken_notices n JOIN vorken_servers s ON s.id::text=n.payload->>'serverId'
      WHERE n.id=$1 AND n.kind='prior_ban' AND ${accessSql('s')}`,[req.params.id,u.id]);
    if(!r.rows[0])fail(404,'Alerta não encontrado.');res.json(r.rows[0].payload);
  }));
  app.get('/api/vorken/admin/bans',requireAdmin,route(async(req,res)=>{
    const offset=Math.max(0,Number.parseInt(req.query.offset,10)||0),q=clean(req.query.q,100);
    const r=await pool.query(`SELECT b.*,s.name AS server_name,COALESCE(v.player_name,b.player_name,legacy.player_name) AS player_name,
      COALESCE((SELECT name FROM vorken_customers WHERE discord_id=legacy.administrator_id),legacy.administrator_id) AS verification_administrator,
      COALESCE(b.administrator_name,NULLIF(split_part(c.actor_id,'|',2),''),(SELECT name FROM vorken_customers WHERE discord_id=split_part(c.actor_id,'|',1)),c.actor_id) AS administrator,
      COALESCE(v.analysis_id,b.legacy_analysis_id) AS analysis_id,COUNT(*) OVER()::int AS total
      FROM vorken_bans b JOIN vorken_servers s ON s.id=b.server_id LEFT JOIN vorken_sessions v ON v.id=b.session_id
      LEFT JOIN LATERAL(SELECT player_name,administrator_id FROM guerra_fria_verifications WHERE analysis_id=b.legacy_analysis_id ORDER BY id DESC LIMIT 1)legacy ON TRUE
      LEFT JOIN LATERAL(SELECT actor_id FROM vorken_commands WHERE (session_id=b.session_id AND action='deny' OR id=b.command_id) AND status='applied' ORDER BY completed_at DESC LIMIT 1)c ON TRUE
      WHERE $1='' OR b.steam_id ILIKE '%'||$1||'%' OR s.name ILIKE '%'||$1||'%' OR b.reason ILIKE '%'||$1||'%' OR COALESCE(v.player_name,b.player_name,legacy.player_name) ILIKE '%'||$1||'%'
      ORDER BY b.created_at DESC,b.id LIMIT 100 OFFSET $2`,[q,offset]);
    if(loadPlayerProfiles){
      const missing=[...new Set(r.rows.map(b=>b.steam_id))].filter(id=>!auditProfiles.has(id)||auditProfiles.get(id).until<Date.now());
      if(missing.length){try{const profiles=await loadPlayerProfiles(missing);for(const id of missing)auditProfiles.set(id,{profile:profiles.get(id)?.profile||null,until:Date.now()+3600000});}catch{}}
    }
    res.json({bans:r.rows.map(b=>({...b,profile:auditProfiles.get(b.steam_id)?.profile||null})),total:r.rows[0]?.total||0,offset});
  }));
  app.get('/api/vorken/admin',requireAdmin,route(async(_req,res)=>{
    const [customers,servers,orders,plans,audits,bans]=await Promise.all([
      pool.query(`SELECT c.*,l.plan_id,l.status AS license_status,l.expires_at AS license_until,l.max_servers FROM vorken_customers c LEFT JOIN vorken_licenses l ON l.customer_id=c.id ORDER BY c.created_at DESC LIMIT 1000`),
      pool.query('SELECT id,customer_id,guild_id,name,enabled,last_seen,plugin_version FROM vorken_servers ORDER BY created_at DESC LIMIT 1000'),
      pool.query('SELECT o.*,c.name FROM vorken_orders o JOIN vorken_customers c ON c.id=o.customer_id ORDER BY created_at DESC LIMIT 200'),
      pool.query('SELECT * FROM vorken_plans ORDER BY months'),pool.query('SELECT * FROM vorken_audit ORDER BY id DESC LIMIT 100'),
      pool.query('SELECT b.id,b.steam_id,b.reason,b.active,b.created_at,s.name AS server_name FROM vorken_bans b JOIN vorken_servers s ON s.id=b.server_id ORDER BY b.created_at DESC LIMIT 200')]);
    res.json({customers:customers.rows,servers:servers.rows,orders:orders.rows,plans:plans.rows,audits:audits.rows,bans:bans.rows,
      readiness:{discord:!!(process.env.VORKEN_DISCORD_CLIENT_ID&&process.env.VORKEN_DISCORD_CLIENT_SECRET&&process.env.VORKEN_DISCORD_BOT_TOKEN),payments:!!(process.env.MERCADO_PAGO_ACCESS_TOKEN&&process.env.MERCADO_PAGO_WEBHOOK_SECRET)}});
  }));
  app.patch('/api/vorken/admin/plans/:id',requireAdmin,csrf,route(async(req,res)=>{
    const {priceCents,maxServers,enabled}=req.body;
    if(!Number.isSafeInteger(priceCents)||priceCents<=0||!Number.isInteger(maxServers)||maxServers<1||maxServers>100||typeof enabled!=='boolean') fail(400,'Preço, limite ou disponibilidade inválidos.');
    const r=await pool.query('UPDATE vorken_plans SET price_cents=$2,max_servers=$3,enabled=$4 WHERE id=$1 RETURNING id',[req.params.id,priceCents,maxServers,enabled]);
    if(!r.rows[0]) fail(404,'Plano não encontrado.');
    await audit(pool,'owner','plan_updated',req.params.id,{priceCents,maxServers,enabled});res.json({ok:true});
  }));
  app.post('/api/vorken/admin/customers/:id/license',requireAdmin,csrf,route(async(req,res)=>{
    if(!uuid(req.params.id)||!['grant','suspend','revoke','resume'].includes(req.body.action)) fail(400,'Ação inválida.');
    await tx(async db=>{
      const user=await db.query('SELECT id FROM vorken_customers WHERE id=$1 FOR UPDATE',[req.params.id]);
      if(!user.rows[0]) fail(404,'Cadastro não encontrado.');
      if(req.body.action==='grant'){
        const p=(await db.query('SELECT * FROM vorken_plans WHERE id=$1',[req.body.planId])).rows[0];
        if(!p) fail(400,'Plano inválido.');
        const old=await entitlement(req.params.id,db),base=licensed(old)?new Date(old.license_until):new Date();
        await db.query(`INSERT INTO vorken_licenses(customer_id,plan_id,status,expires_at,max_servers) VALUES($1,$2,'active',$3,$4)
          ON CONFLICT(customer_id) DO UPDATE SET plan_id=$2,status='active',expires_at=$3,max_servers=$4`,[req.params.id,p.id,addMonths(base,p.months),p.max_servers]);
      } else await db.query('UPDATE vorken_licenses SET status=$2 WHERE customer_id=$1',[req.params.id,{suspend:'suspended',revoke:'revoked',resume:'active'}[req.body.action]]);
      await audit(db,'owner','license_'+req.body.action,req.params.id,{planId:req.body.planId});res.json({ok:true});
    });
  }));
  app.patch('/api/vorken/admin/customers/:id',requireAdmin,csrf,route(async(req,res)=>{
    if(!uuid(req.params.id)||!['active','suspended'].includes(req.body.status)) fail(400,'Cadastro inválido.');
    await pool.query('UPDATE vorken_customers SET status=$2 WHERE id=$1',[req.params.id,req.body.status]);
    await audit(pool,'owner','customer_'+req.body.status,req.params.id);res.json({ok:true});
  }));
  app.patch('/api/vorken/admin/servers/:id',requireAdmin,csrf,route(async(req,res)=>{
    if(!uuid(req.params.id)||typeof req.body.enabled!=='boolean') fail(400,'Servidor inválido.');
    await pool.query('UPDATE vorken_servers SET enabled=$2 WHERE id=$1',[req.params.id,req.body.enabled]);
    await audit(pool,'owner','server_enabled',req.params.id,{enabled:req.body.enabled});res.json({ok:true});
  }));
  app.patch('/api/vorken/admin/bans/:id',requireAdmin,csrf,route(async(req,res)=>{
    if(!uuid(req.params.id)||typeof req.body.active!=='boolean') fail(400,'Registro inválido.');
    await pool.query('UPDATE vorken_bans SET active=$2 WHERE id=$1',[req.params.id,req.body.active]);
    await audit(pool,'owner','ban_visibility',req.params.id,{active:req.body.active});res.json({ok:true});
  }));

  app.post('/api/vorken/plugin/sync',route(async(req,res)=>{
    const token=String(req.get('authorization')||'').replace(/^Bearer /,'');
    if(!/^[\w-]{43}$/.test(token)) fail(401,'Instalação inválida.');
    limit('plugin:'+hash(token),30);
    const server=(await pool.query('SELECT * FROM vorken_servers WHERE token_hash=$1',[hash(token)])).rows[0];
    if(!server) fail(401,'Instalação revogada.');
    const events=Array.isArray(req.body.events)?req.body.events.slice(0,50):[];
    const receipts=Array.isArray(req.body.receipts)?req.body.receipts.slice(0,50):[];
    const accepted=[],acknowledged=[];
    await tx(async db=>{
      await db.query('SELECT id FROM vorken_servers WHERE id=$1 FOR UPDATE',[server.id]);
      if(Array.isArray(req.body.players)){
        if(req.body.players.length>2000)fail(400,'Lista de jogadores excede o limite.');
        const players=[...new Map(req.body.players.filter(p=>p&&steam(p.steamId)).map(p=>[p.steamId,{steamId:p.steamId,name:clean(p.name,100)}])).values()];
        await db.query('UPDATE vorken_servers SET online_players=$2,players_updated_at=NOW() WHERE id=$1',[server.id,JSON.stringify(players)]);
      }
      for(const event of events){
        if(!uuid(event.id)||!steam(event.steamId)) continue;
        const inserted=await db.query('INSERT INTO vorken_events(id,server_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING id',[event.id,server.id]);
        // An event ID owned by another installation must not acknowledge that installation's event.
        if(!inserted.rows.length){
          const existing=await db.query('SELECT id FROM vorken_events WHERE id=$1 AND server_id=$2',[event.id,server.id]);
          if(existing.rows.length) accepted.push(event.id); continue;
        }
        accepted.push(event.id);
        if(event.eventType==='player_join'){
          const bans=await db.query(`SELECT b.id,b.reason,b.created_at,s.name AS server_name,b.evidence FROM vorken_bans b JOIN vorken_servers s ON s.id=b.server_id
            WHERE b.steam_id=$1 AND b.active AND b.server_id<>$2 ORDER BY b.created_at DESC LIMIT 10`,[event.steamId,server.id]);
          if(bans.rows.length) await notify(db,server.guild_id,'prior_ban',{serverId:server.id,steamId:event.steamId,playerName:clean(event.playerName,80),serverName:server.name,bans:bans.rows});
        } else if(event.eventType==='session_started'&&uuid(event.sessionId)&&/^\d{4}$/.test(event.code)){
          if(!await serverActive(server,db)) continue;
          const expiry=new Date(event.expiresAt); if(!Number.isFinite(expiry.getTime())) continue;
          await db.query(`INSERT INTO vorken_sessions(id,server_id,steam_id,player_name,code,administrator_id,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING`,[event.sessionId,server.id,event.steamId,clean(event.playerName,100),event.code,clean(event.administrator,40),expiry]);
        } else if(uuid(event.sessionId)&&['session_end','refusal_ban','timeout_ban'].includes(event.eventType)){
          const ended=await db.query("UPDATE vorken_sessions SET status='ended' WHERE id=$1 AND server_id=$2 AND status IN ('pending','redeemed') RETURNING discord_user_id,ticket_channel_id",[event.sessionId,server.id]);
          if(ended.rows[0]?.ticket_channel_id) await notify(db,server.guild_id,'decision',{sessionId:event.sessionId,
            steamId:event.steamId,discordUserId:ended.rows[0].discord_user_id,channelId:ended.rows[0].ticket_channel_id,action:'cancel',reason:'Sessão encerrada pelo plugin: '+clean(event.reason||event.eventType)});
          if(['refusal_ban','timeout_ban'].includes(event.eventType))await notify(db,server.guild_id,'public_ban',{serverId:server.id,steamId:event.steamId,playerName:clean(event.playerName,100),serverName:server.name,reason:clean(event.reason,500)});
          if(['refusal_ban','timeout_ban'].includes(event.eventType)){
            const session=(await db.query('SELECT id FROM vorken_sessions WHERE id=$1 AND server_id=$2',[event.sessionId,server.id])).rows[0];
            if(session)await db.query('INSERT INTO vorken_bans(id,session_id,server_id,steam_id,reason,evidence,player_name) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(session_id) DO NOTHING',
              [crypto.randomUUID(),session.id,server.id,event.steamId,clean(event.reason,500)||'Banimento por política de verificação do servidor.',JSON.stringify([{type:'verification_policy',event:event.eventType,reason:clean(event.reason,500)}]),clean(event.playerName,80)]);
          }
        }
      }
      for(const receipt of receipts){
        if(!uuid(receipt.id)||typeof receipt.ok!=='boolean') continue;
        const command=(await db.query('SELECT * FROM vorken_commands WHERE id=$1 AND server_id=$2 FOR UPDATE',[receipt.id,server.id])).rows[0];
        if(!command) continue; acknowledged.push(receipt.id);
        if(command.status!=='pending') continue;
        await db.query("UPDATE vorken_commands SET status=$2,result=$3,completed_at=NOW() WHERE id=$1",[command.id,receipt.ok?'applied':'failed',clean(receipt.result,500)]);
        if(command.action==='start') await notify(db,server.guild_id,'command',{steamId:command.steam_id,actorId:command.actor_id,
          result:clean(receipt.result,500),ok:receipt.ok,serverName:server.name});
        if(command.action==='ban_prior'){
          const notice=(await db.query("SELECT payload FROM vorken_notices WHERE kind='prior_ban' AND payload->>'commandId'=$1",[command.id])).rows[0];
          if(receipt.ok&&notice){
            const p=notice.payload;
            await db.query('INSERT INTO vorken_bans(id,server_id,steam_id,reason,evidence,command_id,player_name) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(command_id) DO NOTHING',
              [crypto.randomUUID(),server.id,command.steam_id,command.reason,JSON.stringify(p.bans),command.id,p.playerName]);
            await notify(db,server.guild_id,'public_ban',{serverId:server.id,playerName:p.playerName,serverName:server.name,steamId:command.steam_id,reason:command.reason,administratorName:command.actor_id.split('|').slice(1).join('|')});
          }
          await notify(db,server.guild_id,'command',{steamId:command.steam_id,actorId:command.actor_id,result:clean(receipt.result,500),ok:receipt.ok,serverName:server.name});
        }
        if(command.session_id&&['approve','deny'].includes(command.action)){
          if(!receipt.ok){await db.query("UPDATE vorken_sessions SET status='redeemed' WHERE id=$1 AND status='deciding'",[command.session_id]);continue;}
          const s=(await db.query('SELECT * FROM vorken_sessions WHERE id=$1',[command.session_id])).rows[0];
          if(!s) continue;
          await db.query("UPDATE vorken_sessions SET status=$2 WHERE id=$1",[s.id,command.action==='approve'?'approved':'denied']);
          await db.query('UPDATE analyses SET external_decision=$2,external_decision_at=NOW(),external_decision_result=$3 WHERE id=$1',[s.analysis_id,command.action,clean(receipt.result,500)]);
          if(command.action==='deny'){
            const evidence=await db.query('SELECT id,title,severity,artifact_type,artifact_value,evidence FROM scan_findings WHERE analysis_id=$1 AND id=ANY($2::bigint[])',[s.analysis_id,command.evidence_ids]);
            await db.query('INSERT INTO vorken_bans(id,session_id,server_id,steam_id,reason,evidence) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(session_id) DO NOTHING',
              [crypto.randomUUID(),s.id,server.id,s.steam_id,command.reason,JSON.stringify(evidence.rows)]);
          }
          await notify(db,server.guild_id,command.action==='deny'?'public_ban':'public_verified',{serverId:server.id,playerName:s.player_name,serverName:server.name,steamId:s.steam_id,reason:command.reason});
          await notify(db,server.guild_id,'decision',{sessionId:s.id,steamId:s.steam_id,discordUserId:s.discord_user_id,channelId:s.ticket_channel_id,action:command.action,reason:command.reason});
        }
      }
      await db.query('UPDATE vorken_servers SET last_seen=NOW(),plugin_version=$2 WHERE id=$1',[server.id,clean(req.body.version,24)]);
    });
    // Global learning runs only after the Rust server confirms an actual decision.
    for(const receipt of receipts.filter(r=>acknowledged.includes(r.id)&&r.ok)){
      const r=await pool.query(`SELECT c.*,v.analysis_id FROM vorken_commands c JOIN vorken_sessions v ON v.id=c.session_id WHERE c.id=$1 AND c.server_id=$2 AND c.status='applied' AND NOT c.learning_complete`,[receipt.id,server.id]);
      const c=r.rows[0];if(!c||!['approve','deny'].includes(c.action)) continue;
      if(c.action==='deny') await revokeLearnedTrustForFindings(c.analysis_id,c.evidence_ids);
      if(c.trusted_ids.length) await learnAnalysisArtifacts(c.analysis_id,c.reason||'Falso positivo revisado pelo servidor',{includeIds:c.trusted_ids});
      await pool.query('UPDATE vorken_commands SET learning_complete=TRUE WHERE id=$1',[c.id]);
    }
    const active=await serverActive(server);
    await pool.query("UPDATE vorken_commands SET status='failed',result='Solicitação de telagem expirada.',completed_at=NOW() WHERE server_id=$1 AND status='pending' AND action='start' AND created_at<NOW()-interval '2 minutes'",[server.id]);
    const commands=active?(await pool.query("SELECT id,session_id AS \"sessionId\",action,steam_id AS \"steamId\",actor_id AS \"actorId\",reason FROM vorken_commands WHERE server_id=$1 AND status='pending' ORDER BY created_at LIMIT 20",[server.id])).rows:[];
    const g=(await pool.query('SELECT verification_channel_id FROM vorken_guilds WHERE id=$1',[server.guild_id])).rows[0];
    res.json({active,accepted,acknowledged,commands,discord:server.discord_invite,channel:g?.verification_channel_id?'https://discord.com/channels/'+server.guild_id+'/'+g.verification_channel_id:'#verificacao',notifications:notificationSettings(server.notification_settings),verification:verificationSettings(server.verification_settings)});
  }));

  return { pool, entitlement, serverActive, ownedServer, queue, decision, tx, notify, publicUrl, audit };
}
