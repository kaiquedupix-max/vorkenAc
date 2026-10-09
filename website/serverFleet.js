import crypto from 'node:crypto';

const STEAM = /^7656119\d{10}$/;
const text = (value, max = 120) => String(value ?? '').replace(/[\x00-\x1f<>]/g, '').trim().slice(0, max);
const fault = (status, message) => Object.assign(new Error(message), {status});
export function integer(value, min, max, label) {
  if (value === '' || value == null || typeof value === 'boolean') throw fault(400, `${label} inválido.`);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw fault(400, `${label} deve estar entre ${min} e ${max}.`);
  return n;
}
export function normalizePolicy(body) {
  if (typeof body.associationEnabled !== 'boolean' || typeof body.notifyChat !== 'boolean') throw fault(400, 'Informe as opções da política.');
  return {associationEnabled: body.associationEnabled, notifyChat: body.notifyChat, associationDays: integer(body.associationDays, 1, 365, 'Dias de associação')};
}
export function associationMembers(steamId, teams) {
  if (!STEAM.test(String(steamId))) throw fault(400, 'SteamID64 inválido.');
  const members = new Set();
  for (const team of Array.isArray(teams) ? teams : []) {
    if (!Array.isArray(team) || !team.map(String).includes(String(steamId))) continue;
    for (const id of team) if (STEAM.test(String(id)) && String(id) !== String(steamId)) members.add(String(id));
  }
  return [...members].slice(0, 100);
}
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

export async function initFleetDb(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS fleet_clients (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL,
      server_limit INTEGER NOT NULL DEFAULT 3 CHECK(server_limit BETWEEN 1 AND 1000),
      association_enabled BOOLEAN NOT NULL DEFAULT true,
      association_days INTEGER NOT NULL DEFAULT 7 CHECK(association_days BETWEEN 1 AND 365),
      notify_chat BOOLEAN NOT NULL DEFAULT true, revision BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS fleet_servers (
      id BIGSERIAL PRIMARY KEY, client_id BIGINT NOT NULL REFERENCES fleet_clients(id),
      name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
      last_seen_at TIMESTAMPTZ, teams JSONB NOT NULL DEFAULT '[]',
      applied_revision BIGINT NOT NULL DEFAULT 0, notification_cursor BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE fleet_servers ADD COLUMN IF NOT EXISTS report_visibility TEXT NOT NULL DEFAULT 'manual' CHECK(report_visibility IN ('manual','automatic'));
    ALTER TABLE analyses ADD COLUMN IF NOT EXISTS fleet_server_id BIGINT REFERENCES fleet_servers(id);
    CREATE TABLE IF NOT EXISTS fleet_bans (
      id BIGSERIAL PRIMARY KEY, client_id BIGINT NOT NULL REFERENCES fleet_clients(id),
      steam_id TEXT NOT NULL, player_name TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('direct','association')), source_steam_id TEXT NOT NULL,
      source_server_id BIGINT REFERENCES fleet_servers(id), analysis_id BIGINT REFERENCES analyses(id),
      evidence_ids JSONB NOT NULL DEFAULT '[]', evidence_snapshot JSONB NOT NULL DEFAULT '[]', expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS fleet_bans_scope ON fleet_bans(client_id,steam_id);
    CREATE TABLE IF NOT EXISTS fleet_receipts (
      server_id BIGINT NOT NULL REFERENCES fleet_servers(id), event_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(server_id,event_id)
    );
    CREATE TABLE IF NOT EXISTS fleet_notifications (
      id BIGSERIAL PRIMARY KEY, client_id BIGINT NOT NULL REFERENCES fleet_clients(id),
      message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

export async function clientReportVisibility(pool, analysis) {
  if (!analysis || analysis.status !== 'completed') return {released: false, automatic: false};
  const server = analysis.fleet_server_id
    ? await pool.query('SELECT report_visibility FROM fleet_servers WHERE id=$1', [analysis.fleet_server_id])
    : {rows: []};
  const automatic = server.rows[0]?.report_visibility === 'automatic';
  return {released: automatic || analysis.client_report_released === true, automatic};
}

async function transaction(pool, clientId, run) {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const {rows} = await db.query('SELECT * FROM fleet_clients WHERE id=$1 FOR UPDATE', [clientId]);
    if (!rows[0]) throw fault(404, 'Cliente não encontrado.');
    const result = await run(db, rows[0]);
    await db.query('COMMIT');
    return result;
  } catch (error) { await db.query('ROLLBACK'); throw error; }
  finally {db.release();}
}

async function addBan(db, client, input, teams) {
  const steamId = String(input.steamId);
  if (!STEAM.test(steamId)) throw fault(400, 'SteamID64 inválido.');
  const reason = text(input.reason, 500);
  if (!reason) throw fault(400, 'Informe o motivo.');
  let inserted = 0;
  const add = async (id, kind, expiresAt) => {
    // Never downgrade an existing permanent ban or extend associations on retries.
    const existing = await db.query(`SELECT id FROM fleet_bans WHERE client_id=$1 AND steam_id=$2 AND kind=$3 AND source_steam_id=$4 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>NOW()) LIMIT 1`, [client.id, id, kind, steamId]);
    if (existing.rows.length) return false;
    await db.query(`INSERT INTO fleet_bans(client_id,steam_id,player_name,reason,kind,source_steam_id,source_server_id,analysis_id,evidence_ids,evidence_snapshot,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)`, [client.id, id, kind === 'direct' ? text(input.playerName) : '', kind === 'direct' ? reason : `Associação com ${steamId}: ${reason}`, kind, steamId, input.serverId || null, input.analysisId || null, JSON.stringify(input.evidenceIds || []), JSON.stringify(input.evidenceSnapshot || []), expiresAt]);
    inserted++;
    if (client.notify_chat) {
      const message = kind === 'association'
        ? `[VORKEN] ${id} banido por associação com ${steamId} por ${client.association_days} dia(s).`
        : `[VORKEN] ${text(input.playerName) || id} banido. Motivo: ${reason}`;
      await db.query('INSERT INTO fleet_notifications(client_id,message) VALUES($1,$2)', [client.id, message]);
    }
    return true;
  };
  const added = await add(steamId, 'direct', input.expiresAt || null);
  if (added && client.association_enabled) {
    const expiresAt = new Date(Date.now() + client.association_days * 86400000);
    for (const id of associationMembers(steamId, teams)) await add(id, 'association', expiresAt);
  }
  if (inserted) await db.query('UPDATE fleet_clients SET revision=revision+1 WHERE id=$1', [client.id]);
  return inserted;
}

async function revoke(db, clientId, steamId) {
  if (!STEAM.test(String(steamId))) throw fault(400, 'SteamID64 inválido.');
  const result = await db.query('UPDATE fleet_bans SET revoked_at=NOW() WHERE client_id=$1 AND steam_id=$2 AND revoked_at IS NULL RETURNING id', [clientId, steamId]);
  if (result.rows.length) await db.query('UPDATE fleet_clients SET revision=revision+1 WHERE id=$1', [clientId]);
  return result.rows.length;
}

export function installFleet(app, {pool, requireAdmin}) {
  const route = fn => async (req, res) => {
    try {await fn(req, res);} catch (error) {
      if (!error.status) console.error('Fleet operation failed:', error.message);
      res.status(error.status || 500).json({message: error.status ? error.message : 'Não foi possível concluir a operação. Tente novamente.'});
    }
  };
  app.get('/api/admin/fleet', requireAdmin, route(async (_req, res) => {
    const clients = await pool.query(`SELECT c.*, (SELECT COUNT(*)::integer FROM fleet_servers s WHERE s.client_id=c.id) AS server_count FROM fleet_clients c ORDER BY c.id`);
    const servers = await pool.query(`SELECT s.id,s.client_id,s.name,s.report_visibility,s.last_seen_at,s.applied_revision,c.revision, s.last_seen_at>NOW()-INTERVAL '90 seconds' AS online FROM fleet_servers s JOIN fleet_clients c ON c.id=s.client_id ORDER BY s.id`);
    res.json({clients: clients.rows, servers: servers.rows});
  }));
  app.post('/api/admin/fleet/clients', requireAdmin, route(async (req, res) => {
    const name = text(req.body.name);
    if (name.length < 2) throw fault(400, 'Informe o nome do cliente.');
    const limit = integer(req.body.serverLimit, 1, 1000, 'Limite de servidores');
    const result = await pool.query('INSERT INTO fleet_clients(name,server_limit) VALUES($1,$2) RETURNING *', [name, limit]);
    res.status(201).json({client: result.rows[0]});
  }));
  app.patch('/api/admin/fleet/clients/:id', requireAdmin, route(async (req, res) => {
    const clientId = integer(req.params.id, 1, Number.MAX_SAFE_INTEGER, 'Cliente');
    const client = await transaction(pool, clientId, async (db, current) => {
      const limit = req.body.serverLimit == null ? current.server_limit : integer(req.body.serverLimit, 1, 1000, 'Limite de servidores');
      const count = await db.query('SELECT COUNT(*)::integer AS total FROM fleet_servers WHERE client_id=$1', [clientId]);
      if (limit < count.rows[0].total) throw fault(409, 'O limite não pode ser menor que a quantidade já registrada.');
      const policy = req.body.associationDays == null ? {associationEnabled: current.association_enabled, associationDays: current.association_days, notifyChat: current.notify_chat} : normalizePolicy(req.body);
      const updated = await db.query('UPDATE fleet_clients SET server_limit=$2,association_enabled=$3,association_days=$4,notify_chat=$5 WHERE id=$1 RETURNING *', [clientId, limit, policy.associationEnabled, policy.associationDays, policy.notifyChat]);
      return updated.rows[0];
    });
    res.json({client});
  }));
  app.post('/api/admin/fleet/servers', requireAdmin, route(async (req, res) => {
    const clientId = integer(req.body.clientId, 1, Number.MAX_SAFE_INTEGER, 'Cliente');
    const name = text(req.body.name);
    if (name.length < 2) throw fault(400, 'Informe o nome do servidor.');
    const token = crypto.randomBytes(32).toString('hex');
    const server = await transaction(pool, clientId, async (db, client) => {
      const count = await db.query('SELECT COUNT(*)::integer AS total FROM fleet_servers WHERE client_id=$1', [clientId]);
      if (count.rows[0].total >= client.server_limit) throw fault(409, 'Limite de servidores atingido. Amplie a cota deste cliente.');
      const result = await db.query(`INSERT INTO fleet_servers(client_id,name,token_hash,notification_cursor) VALUES($1,$2,$3,(SELECT COALESCE(MAX(id),0) FROM fleet_notifications WHERE client_id=$1)) RETURNING id,client_id,name`, [clientId, name, hash(token)]);
      return result.rows[0];
    });
    res.status(201).json({server, token});
  }));
  app.patch('/api/admin/fleet/servers/:id', requireAdmin, route(async (req, res) => {
    const id = integer(req.params.id, 1, Number.MAX_SAFE_INTEGER, 'Servidor');
    const visibility = req.body.reportVisibility;
    if (!['manual', 'automatic'].includes(visibility)) throw fault(400, 'Escolha quando disponibilizar o relatório.');
    const result = await pool.query('UPDATE fleet_servers SET report_visibility=$2 WHERE id=$1 RETURNING id,client_id,name,report_visibility', [id, visibility]);
    if (!result.rows[0]) throw fault(404, 'Servidor não encontrado.');
    res.json({server: result.rows[0]});
  }));
  app.get('/api/admin/fleet/bans', requireAdmin, route(async (req, res) => {
    const clientId = req.query.clientId ? integer(req.query.clientId, 1, Number.MAX_SAFE_INTEGER, 'Cliente') : null;
    const result = await pool.query(`SELECT b.*,c.name AS client_name, (b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at>NOW())) AS active FROM fleet_bans b JOIN fleet_clients c ON c.id=b.client_id WHERE ($1::bigint IS NULL OR b.client_id=$1) ORDER BY b.id DESC LIMIT 500`, [clientId]);
    res.json({bans: result.rows});
  }));
  app.post('/api/admin/fleet/bans', requireAdmin, route(async (req, res) => {
    const clientId = integer(req.body.clientId, 1, Number.MAX_SAFE_INTEGER, 'Cliente');
    const analysisId = integer(req.body.analysisId, 1, Number.MAX_SAFE_INTEGER, 'Análise');
    const serverId = integer(req.body.serverId, 1, Number.MAX_SAFE_INTEGER, 'Servidor de origem');
    const ids = [...new Set(Array.isArray(req.body.evidenceIds) ? req.body.evidenceIds : [])].map(id => integer(id, 1, Number.MAX_SAFE_INTEGER, 'Evidência'));
    if (!ids.length || ids.length > 80) throw fault(400, 'Selecione de 1 a 80 evidências.');
    const result = await transaction(pool, clientId, async (db, client) => {
      const analysis = await db.query('SELECT id,status FROM analyses WHERE id=$1', [analysisId]);
      if (analysis.rows[0]?.status !== 'completed') throw fault(409, 'A análise precisa estar concluída.');
      const findings = await db.query('SELECT id,title,severity,artifact_type,artifact_value FROM scan_findings WHERE analysis_id=$1 AND id=ANY($2::bigint[])', [analysisId, ids]);
      if (findings.rows.length !== ids.length) throw fault(400, 'As evidências devem pertencer à análise selecionada.');
      const server = await db.query('SELECT * FROM fleet_servers WHERE id=$1 AND client_id=$2', [serverId, clientId]);
      if (!server.rows[0]) throw fault(400, 'Servidor não pertence a este cliente.');
      // A fresh team snapshot is mandatory while association is enabled, preventing silent omissions.
      if (client.association_enabled && (!server.rows[0].last_seen_at || Date.now() - new Date(server.rows[0].last_seen_at).getTime() > 120000)) throw fault(409, 'Conecte o servidor de origem para obter os integrantes atuais do time antes de banir.');
      return addBan(db, client, {steamId: req.body.steamId, playerName: req.body.playerName, reason: req.body.reason, serverId, analysisId, evidenceIds: ids, evidenceSnapshot: findings.rows}, server.rows[0].teams);
    });
    res.status(201).json({created: result, message: 'Banimento registrado. Os servidores conectados aplicarão a decisão na próxima sincronização.'});
  }));
  app.get('/api/admin/fleet/bans/:id/evidence', requireAdmin, route(async (req, res) => {
    const id = integer(req.params.id, 1, Number.MAX_SAFE_INTEGER, 'Banimento');
    const result = await pool.query('SELECT id,analysis_id,evidence_ids,evidence_snapshot,reason,kind,source_steam_id FROM fleet_bans WHERE id=$1', [id]);
    const ban = result.rows[0];
    if (!ban) throw fault(404, 'Banimento não encontrado.');
    // Audit is deliberately restricted to the exact evidence chosen for this decision.
    const {evidence_snapshot, ...decision} = ban;
    res.json({ban: decision, evidence: evidence_snapshot});
  }));
  app.post('/api/admin/fleet/unban', requireAdmin, route(async (req, res) => {
    const clientId = integer(req.body.clientId, 1, Number.MAX_SAFE_INTEGER, 'Cliente');
    const count = await transaction(pool, clientId, db => revoke(db, clientId, String(req.body.steamId)));
    res.json({revoked: count, message: 'Desbanimento registrado em todos os servidores deste cliente.'});
  }));
  app.post('/api/fleet/sync', route(async (req, res) => {
    const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
    if (!/^[a-f0-9]{64}$/.test(token)) throw fault(401, 'Chave de servidor inválida.');
    const auth = await pool.query('SELECT id,client_id FROM fleet_servers WHERE token_hash=$1', [hash(token)]);
    const server = auth.rows[0];
    if (!server) throw fault(401, 'Chave de servidor inválida.');
    if (!Array.isArray(req.body.teams) || req.body.teams.length > 10000) throw fault(400, 'Snapshot de times inválido.');
    const teams = req.body.teams.map(team => {
      if (!Array.isArray(team) || team.length > 100) throw fault(400, 'Time inválido.');
      return [...new Set(team.map(String).filter(id => STEAM.test(id)))];
    });
    const events = Array.isArray(req.body.events) ? req.body.events : [];
    if (events.length > 50) throw fault(400, 'Máximo de 50 eventos por sincronização.');
    const payload = await transaction(pool, server.client_id, async (db, client) => {
      const ack = integer(req.body.notificationCursor ?? 0, 0, Number.MAX_SAFE_INTEGER, 'Cursor');
      const revision = integer(req.body.appliedRevision ?? 0, 0, Number.MAX_SAFE_INTEGER, 'Revisão');
      const max = await db.query('SELECT COALESCE(MAX(id),0) AS id FROM fleet_notifications WHERE client_id=$1', [client.id]);
      await db.query(`UPDATE fleet_servers SET teams=$2::jsonb,last_seen_at=NOW(),applied_revision=$3,notification_cursor=GREATEST(notification_cursor,$4) WHERE id=$1`, [server.id, JSON.stringify(teams), Math.min(revision, Number(client.revision)), Math.min(ack, Number(max.rows[0].id))]);
      for (const event of events) {
        if (!/^[a-zA-Z0-9-]{16,80}$/.test(String(event.id)) || !['ban','unban'].includes(event.type) || !STEAM.test(String(event.steamId))) throw fault(400, 'Evento inválido.');
        const receipt = await db.query('INSERT INTO fleet_receipts(server_id,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_id', [server.id, event.id]);
        if (!receipt.rows.length) continue;
        if (event.type === 'unban') await revoke(db, client.id, String(event.steamId));
        else {
          const expiry = Number(event.expiry || 0);
          if (!Number.isSafeInteger(expiry) || expiry < -1) throw fault(400, 'Expiração inválida.');
          if (expiry > 0 && expiry * 1000 <= Date.now()) continue;
          const eventTeams = event.team == null ? teams : [event.team];
          if (event.team != null && (!Array.isArray(event.team) || event.team.length > 100)) throw fault(400, 'Time do evento inválido.');
          await addBan(db, client, {steamId: event.steamId, playerName: event.playerName, serverId: server.id, reason: event.reason || 'Banimento no servidor de origem.', expiresAt: expiry > 0 ? new Date(expiry * 1000) : null}, eventTeams);
        }
      }
      const active = await db.query(`SELECT steam_id, MAX(player_name) AS player_name, CASE WHEN BOOL_OR(expires_at IS NULL) THEN NULL ELSE MAX(expires_at) END AS expires_at, BOOL_OR(kind='direct') AS direct, MAX(reason) AS reason FROM fleet_bans WHERE client_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>NOW()) GROUP BY steam_id`, [client.id]);
      const notices = await db.query(`SELECT id,message FROM fleet_notifications WHERE client_id=$1 AND id>(SELECT notification_cursor FROM fleet_servers WHERE id=$2) ORDER BY id LIMIT 100`, [client.id, server.id]);
      const current = await db.query('SELECT revision FROM fleet_clients WHERE id=$1', [client.id]);
      return {bans: active.rows, notifications: notices.rows, revision: Number(current.rows[0].revision), acknowledgedEvents: events.map(e => e.id), associationDays: client.association_days};
    });
    res.json(payload);
  }));
}
