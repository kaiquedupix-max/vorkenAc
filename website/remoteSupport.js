import crypto from "node:crypto";
import express from "express";
import { WebSocketServer, WebSocket } from "ws";

const ACCESS_TTL_MS = 12 * 60 * 60 * 1000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const PRESENCE_TTL_MS = 45 * 1000;
const MAX_FRAME_BYTES = 2 * 1024 * 1024;
const accessTokens = new Map();
const presence = new Map();
const agentSockets = new Map();
const adminSockets = new Map();
const loginAttempts = new Map();
const sessionRuntime = new Map();
const latestFrames = new Map();
const inputQueues = new Map();
const sessionObservers = new Map();

function clean(value, max = 120) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}

function bearer(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  return match?.[1] || "";
}

function tokenRecord(token) {
  const item = accessTokens.get(String(token || ""));
  if (!item || item.expiresAt <= Date.now()) {
    if (token) accessTokens.delete(String(token));
    return null;
  }
  return item;
}

function hashSecret(secret) {
  return crypto.createHash("sha256").update(String(secret)).digest("hex");
}

export function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const value = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash: value };
}

export function verifyPassword(password, salt, expected) {
  try {
    const actual = Buffer.from(hashPassword(password, salt).hash, "hex");
    const target = Buffer.from(String(expected), "hex");
    return actual.length === target.length && crypto.timingSafeEqual(actual, target);
  } catch {
    return false;
  }
}

export function normalizeRemoteMode(value) {
  return value === "control" ? "control" : value === "view" ? "view" : null;
}

export async function initRemoteSupportDb(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS remote_admins (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      display_name TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_admins_username
      ON remote_admins(LOWER(username));

    CREATE TABLE IF NOT EXISTS remote_support_sessions (
      id TEXT PRIMARY KEY,
      analysis_id BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
      admin_id BIGINT NOT NULL REFERENCES remote_admins(id) ON DELETE RESTRICT,
      mode TEXT NOT NULL CHECK (mode IN ('view', 'control')),
      status TEXT NOT NULL DEFAULT 'pending',
      agent_secret_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      accepted_at TIMESTAMPTZ NULL,
      ended_at TIMESTAMPTZ NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_remote_sessions_admin_status
      ON remote_support_sessions(admin_id, status, created_at DESC);

    CREATE TABLE IF NOT EXISTS remote_support_events (
      id BIGSERIAL PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES remote_support_sessions(id) ON DELETE CASCADE,
      actor TEXT NOT NULL,
      event_type TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const username = clean(process.env.REMOTE_ADMIN_BOOTSTRAP_USER, 80);
  const password = String(process.env.REMOTE_ADMIN_BOOTSTRAP_PASSWORD || "");
  if (username && password.length >= 12) {
    const displayName = clean(process.env.REMOTE_ADMIN_BOOTSTRAP_NAME || username, 100);
    const { salt, hash } = hashPassword(password);
    await pool.query(
      `INSERT INTO remote_admins(username, display_name, password_salt, password_hash)
       VALUES($1,$2,$3,$4)
       ON CONFLICT (LOWER(username)) DO NOTHING`,
      [username, displayName, salt, hash]
    );
  }
}

async function audit(pool, sessionId, actor, eventType, metadata = {}) {
  await pool.query(
    `INSERT INTO remote_support_events(session_id, actor, event_type, metadata)
     VALUES($1,$2,$3,$4::jsonb)`,
    [sessionId, actor, eventType, JSON.stringify(metadata)]
  ).catch(() => {});
}

export function installRemoteSupport(app, { pool, getAnalysisByToken, validToken, publicUrl, requireSiteAdmin }) {
  function requireRemoteAdmin(req, res, next) {
    const item = tokenRecord(bearer(req));
    if (!item) return res.status(401).json({ error: "unauthorized" });
    req.remoteAdmin = item;
    next();
  }

  async function runtimeSession(sessionId) {
    const cached = sessionRuntime.get(sessionId);
    if (cached) return cached;
    const result = await pool.query(
      `SELECT analysis_id, admin_id, mode, status, agent_secret_hash, expires_at
       FROM remote_support_sessions WHERE id=$1`,
      [sessionId]
    );
    const row = result.rows[0];
    if (!row) return null;
    const runtime = {
      analysisId: Number(row.analysis_id),
      adminId: Number(row.admin_id),
      mode: row.mode,
      status: row.status,
      agentSecretHash: row.agent_secret_hash,
      expiresAt: new Date(row.expires_at).getTime(),
      agentToken: null,
    };
    sessionRuntime.set(sessionId, runtime);
    return runtime;
  }

  function clearRelay(sessionId) {
    latestFrames.delete(sessionId);
    inputQueues.delete(sessionId);
    sessionObservers.delete(sessionId);
  }

  function storeFrame(sessionId, data) {
    const previous = latestFrames.get(sessionId);
    const sequence = (previous?.sequence || 0) + 1;
    latestFrames.set(sessionId, { sequence, data: Buffer.from(data), createdAt: Date.now() });
    return sequence;
  }

  function queueInput(sessionId, event) {
    const current = inputQueues.get(sessionId) || { sequence: 0, events: [] };
    current.sequence += 1;
    current.events.push({ sequence: current.sequence, event });
    if (current.events.length > 200) current.events.splice(0, current.events.length - 200);
    inputQueues.set(sessionId, current);
    return current.sequence;
  }

  async function authorizeAgentRelay(req, res) {
    if (!validToken(req.params.token)) {
      res.status(404).end();
      return null;
    }
    const runtime = await runtimeSession(req.params.id);
    if (!runtime || runtime.status !== "accepted" || runtime.expiresAt <= Date.now()) {
      res.status(409).json({ error: "session_unavailable" });
      return null;
    }
    if (runtime.agentSecretHash !== hashSecret(req.headers["x-vorken-session-secret"] || "")) {
      res.status(401).json({ error: "unauthorized" });
      return null;
    }
    if (runtime.agentToken && runtime.agentToken !== req.params.token) {
      res.status(401).json({ error: "unauthorized" });
      return null;
    }
    if (!runtime.agentToken) {
      const analysis = await getAnalysisByToken(req.params.token);
      if (!analysis || Number(analysis.id) !== runtime.analysisId) {
        res.status(401).json({ error: "unauthorized" });
        return null;
      }
      runtime.agentToken = req.params.token;
    }
    return runtime;
  }

  async function authorizeAdminRelay(req, res) {
    const runtime = await runtimeSession(req.params.id);
    const observer = sessionObservers.get(req.params.id)?.has(req.remoteAdmin.adminId) === true;
    if (!runtime || (runtime.adminId !== req.remoteAdmin.adminId && !observer) ||
        runtime.status !== "accepted" || runtime.expiresAt <= Date.now()) {
      res.status(409).json({ error: "session_unavailable" });
      return null;
    }
    return runtime;
  }

  app.get("/api/admin/remote-admins", requireSiteAdmin, async (_req, res) => {
    const result = await pool.query(
      `SELECT id, username, display_name, enabled, created_at
       FROM remote_admins ORDER BY enabled DESC, display_name, username`
    );
    res.json({
      admins: result.rows.map((row) => ({
        id: Number(row.id),
        username: row.username,
        displayName: row.display_name,
        enabled: row.enabled,
        online: row.enabled && (presence.get(Number(row.id)) || 0) > Date.now(),
        createdAt: row.created_at,
      })),
    });
  });

  app.post("/api/admin/remote-admins", requireSiteAdmin, async (req, res) => {
    const username = clean(req.body?.username, 80);
    const displayName = clean(req.body?.displayName, 100);
    const password = String(req.body?.password || "");
    if (!/^[A-Za-z0-9._-]{3,40}$/.test(username)) {
      return res.status(400).json({ error: "invalid_username", message: "Use de 3 a 40 caracteres: letras, números, ponto, hífen ou underline." });
    }
    if (displayName.length < 2) {
      return res.status(400).json({ error: "invalid_display_name", message: "Informe o nome exibido do administrador." });
    }
    if (password.length < 12 || password.length > 200) {
      return res.status(400).json({ error: "invalid_password", message: "A senha precisa ter pelo menos 12 caracteres." });
    }
    const { salt, hash } = hashPassword(password);
    try {
      const result = await pool.query(
        `INSERT INTO remote_admins(username, display_name, password_salt, password_hash)
         VALUES($1,$2,$3,$4)
         RETURNING id, username, display_name, enabled, created_at`,
        [username, displayName, salt, hash]
      );
      const row = result.rows[0];
      res.status(201).json({ admin: { id: Number(row.id), username: row.username, displayName: row.display_name, enabled: row.enabled, online: false, createdAt: row.created_at } });
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({ error: "username_exists", message: "Este nome de usuário já está cadastrado." });
      }
      throw error;
    }
  });

  app.post("/api/admin/remote-admins/:id/toggle", requireSiteAdmin, async (req, res) => {
    const adminId = Number(req.params.id);
    if (!Number.isSafeInteger(adminId) || adminId <= 0) return res.status(404).json({ error: "not_found" });
    const current = await pool.query(`SELECT id, enabled FROM remote_admins WHERE id=$1`, [adminId]);
    if (!current.rows[0]) return res.status(404).json({ error: "not_found", message: "Administrador não encontrado." });
    const nextEnabled = !current.rows[0].enabled;
    if (!nextEnabled) {
      const enabledCount = await pool.query(`SELECT COUNT(*)::int AS count FROM remote_admins WHERE enabled=TRUE`);
      if (Number(enabledCount.rows[0]?.count || 0) <= 1) {
        return res.status(409).json({ error: "last_admin", message: "Mantenha pelo menos um administrador ativo." });
      }
    }
    await pool.query(`UPDATE remote_admins SET enabled=$1 WHERE id=$2`, [nextEnabled, adminId]);
    if (!nextEnabled) await revokeRemoteAdmin(adminId, "Conta desativada no painel.");
    res.json({ id: adminId, enabled: nextEnabled });
  });

  app.post("/api/admin/remote-admins/:id/password", requireSiteAdmin, async (req, res) => {
    const adminId = Number(req.params.id);
    const password = String(req.body?.password || "");
    if (!Number.isSafeInteger(adminId) || adminId <= 0) return res.status(404).json({ error: "not_found" });
    if (password.length < 12 || password.length > 200) {
      return res.status(400).json({ error: "invalid_password", message: "A senha precisa ter pelo menos 12 caracteres." });
    }
    const { salt, hash } = hashPassword(password);
    const result = await pool.query(
      `UPDATE remote_admins SET password_salt=$1, password_hash=$2 WHERE id=$3 RETURNING id`,
      [salt, hash, adminId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "not_found", message: "Administrador não encontrado." });
    await revokeRemoteAdmin(adminId, "Senha redefinida no painel.");
    res.json({ ok: true });
  });

  async function revokeRemoteAdmin(adminId, reason) {
    for (const [token, item] of accessTokens) {
      if (item.adminId === adminId) accessTokens.delete(token);
    }
    presence.delete(adminId);
    const sessions = await pool.query(
      `UPDATE remote_support_sessions SET status='ended', ended_at=NOW()
       WHERE admin_id=$1 AND status IN ('pending','accepted') RETURNING id`,
      [adminId]
    );
    for (const row of sessions.rows) {
      const runtime = sessionRuntime.get(row.id);
      if (runtime) runtime.status = "ended";
      closeSessionSockets(row.id, reason);
    }
  }

  app.post("/api/remote/admin/login", async (req, res) => {
    const username = clean(req.body?.username, 80);
    const password = String(req.body?.password || "");
    const attemptKey = `${clean(req.ip, 80)}:${username.toLowerCase()}`;
    const previous = loginAttempts.get(attemptKey);
    if (previous?.blockedUntil > Date.now()) {
      return res.status(429).json({ error: "try_later", message: "Muitas tentativas. Aguarde alguns minutos." });
    }
    const result = await pool.query(
      `SELECT id, username, display_name, password_salt, password_hash
       FROM remote_admins WHERE LOWER(username)=LOWER($1) AND enabled=TRUE LIMIT 1`,
      [username]
    );
    const admin = result.rows[0];
    if (!admin || !verifyPassword(password, admin.password_salt, admin.password_hash)) {
      const failures = (previous?.failures || 0) + 1;
      loginAttempts.set(attemptKey, {
        failures,
        blockedUntil: failures >= 5 ? Date.now() + 15 * 60 * 1000 : 0,
      });
      return res.status(401).json({ error: "invalid_credentials", message: "Usuário ou senha inválidos." });
    }
    loginAttempts.delete(attemptKey);
    const accessToken = crypto.randomBytes(32).toString("base64url");
    accessTokens.set(accessToken, {
      adminId: Number(admin.id),
      username: admin.username,
      displayName: admin.display_name,
      expiresAt: Date.now() + ACCESS_TTL_MS,
    });
    res.json({ accessToken, displayName: admin.display_name, expiresInSeconds: ACCESS_TTL_MS / 1000 });
  });

  app.post("/api/remote/admin/logout", requireRemoteAdmin, (req, res) => {
    const token = bearer(req);
    presence.delete(req.remoteAdmin.adminId);
    accessTokens.delete(token);
    res.status(204).end();
  });

  app.post("/api/remote/admin/presence", requireRemoteAdmin, (req, res) => {
    if (req.body?.available === false) presence.delete(req.remoteAdmin.adminId);
    else presence.set(req.remoteAdmin.adminId, Date.now() + PRESENCE_TTL_MS);
    res.json({ available: presence.has(req.remoteAdmin.adminId) });
  });

  app.get("/api/remote/admin/requests", requireRemoteAdmin, async (req, res) => {
    const result = await pool.query(
      `SELECT s.id, s.mode, s.status, s.created_at AS "createdAt", s.expires_at AS "expiresAt",
              s.admin_id AS "ownerId", a.label, a.machine_name AS "machineName",
              ra.display_name AS "ownerDisplayName"
       FROM remote_support_sessions s
       JOIN analyses a ON a.id=s.analysis_id
       JOIN remote_admins ra ON ra.id=s.admin_id
       WHERE ((s.admin_id=$1 AND s.status='pending') OR s.status='accepted')
         AND s.expires_at>NOW()
       ORDER BY s.created_at DESC LIMIT 20`,
      [req.remoteAdmin.adminId]
    );
    res.json({ requests: result.rows.map((row) => ({
      ...row,
      canObserve: row.status === "accepted" && Number(row.ownerId) !== req.remoteAdmin.adminId,
    })) });
  });

  app.post("/api/remote/admin/sessions/:id/watch", requireRemoteAdmin, async (req, res) => {
    const runtime = await runtimeSession(req.params.id);
    if (!runtime || runtime.status !== "accepted" || runtime.expiresAt <= Date.now()) {
      return res.status(409).json({ error: "session_unavailable" });
    }
    let observers = sessionObservers.get(req.params.id);
    if (!observers) {
      observers = new Set();
      sessionObservers.set(req.params.id, observers);
    }
    observers.add(req.remoteAdmin.adminId);
    await audit(pool, req.params.id, "admin_observer", "watching", { adminId: req.remoteAdmin.adminId });
    res.json({ id: req.params.id, mode: "view", status: "accepted" });
  });

  app.post("/api/remote/admin/sessions/:id/:decision", requireRemoteAdmin, async (req, res, next) => {
    const decision = req.params.decision;
    if (!['accept', 'reject', 'end'].includes(decision)) return next();
    const nextStatus = decision === 'accept' ? 'accepted' : decision === 'reject' ? 'rejected' : 'ended';
    const result = await pool.query(
      `UPDATE remote_support_sessions SET status=$1,
          accepted_at=CASE WHEN $1='accepted' THEN NOW() ELSE accepted_at END,
          ended_at=CASE WHEN $1 IN ('rejected','ended') THEN NOW() ELSE ended_at END
       WHERE id=$2 AND admin_id=$3 AND expires_at>NOW()
         AND status ${decision === 'accept' ? "='pending'" : "IN ('pending','accepted')"}
       RETURNING id, mode, status`,
      [nextStatus, req.params.id, req.remoteAdmin.adminId]
    );
    if (!result.rows[0]) return res.status(409).json({ error: "session_unavailable" });
    const runtime = await runtimeSession(req.params.id);
    if (runtime) runtime.status = nextStatus;
    await audit(pool, req.params.id, "admin", nextStatus);
    if (nextStatus !== 'accepted') closeSessionSockets(req.params.id, "Sessão encerrada pelo administrador.");
    res.json(result.rows[0]);
  });

  app.get("/api/agent/:token/remote/admins", async (req, res) => {
    if (!validToken(req.params.token)) return res.status(404).json({ error: "analysis_not_found" });
    const analysis = await getAnalysisByToken(req.params.token);
    if (!analysis) return res.status(404).json({ error: "analysis_not_found" });
    const onlineIds = [...presence.entries()].filter(([, until]) => until > Date.now()).map(([id]) => id);
    if (!onlineIds.length) return res.json({ admins: [] });
    const result = await pool.query(
      `SELECT id, display_name FROM remote_admins WHERE enabled=TRUE AND id=ANY($1::bigint[]) ORDER BY display_name`,
      [onlineIds]
    );
    res.json({ admins: result.rows.map((row) => ({ id: Number(row.id), displayName: row.display_name })) });
  });

  app.post("/api/agent/:token/remote/sessions", async (req, res) => {
    if (!validToken(req.params.token)) return res.status(404).json({ error: "analysis_not_found" });
    const analysis = await getAnalysisByToken(req.params.token);
    const mode = normalizeRemoteMode(req.body?.mode);
    const adminId = Number(req.body?.adminId);
    if (!analysis || !mode || !Number.isSafeInteger(adminId)) return res.status(400).json({ error: "invalid_request" });
    if ((presence.get(adminId) || 0) <= Date.now()) return res.status(409).json({ error: "admin_offline" });
    const sessionId = crypto.randomUUID();
    const agentSecret = crypto.randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    const inserted = await pool.query(
      `INSERT INTO remote_support_sessions(id, analysis_id, admin_id, mode, agent_secret_hash, expires_at)
       SELECT $1,$2,id,$3,$4,$5 FROM remote_admins WHERE id=$6 AND enabled=TRUE`,
      [sessionId, analysis.id, mode, hashSecret(agentSecret), expiresAt, adminId]
    );
    if (!inserted.rowCount) {
      presence.delete(adminId);
      return res.status(409).json({ error: "admin_offline" });
    }
    sessionRuntime.set(sessionId, {
      analysisId: Number(analysis.id), adminId, mode, status: "pending",
      agentSecretHash: hashSecret(agentSecret), expiresAt: expiresAt.getTime(),
      agentToken: req.params.token,
    });
    await audit(pool, sessionId, "agent", "requested", { mode });
    res.status(201).json({
      sessionId, agentSecret, status: "pending", expiresAt,
      webSocketUrl: publicUrl.replace(/^http/i, "ws") + "/ws/remote",
    });
  });

  app.get("/api/agent/:token/remote/sessions/:id", async (req, res) => {
    if (!validToken(req.params.token)) return res.status(404).end();
    const analysis = await getAnalysisByToken(req.params.token);
    const result = analysis ? await pool.query(
      `SELECT status, mode, expires_at FROM remote_support_sessions WHERE id=$1 AND analysis_id=$2`,
      [req.params.id, analysis.id]
    ) : { rows: [] };
    if (!result.rows[0]) return res.status(404).end();
    res.json(result.rows[0]);
  });

  app.post("/api/agent/:token/remote/sessions/:id/end", async (req, res) => {
    if (!validToken(req.params.token)) return res.status(404).end();
    const analysis = await getAnalysisByToken(req.params.token);
    if (!analysis) return res.status(404).end();
    const result = await pool.query(
      `UPDATE remote_support_sessions SET status='ended', ended_at=NOW()
       WHERE id=$1 AND analysis_id=$2 AND status IN ('pending','accepted') RETURNING id`,
      [req.params.id, analysis.id]
    );
    if (result.rows[0]) {
      const runtime = await runtimeSession(req.params.id);
      if (runtime) runtime.status = "ended";
      await audit(pool, req.params.id, "agent", "ended");
      closeSessionSockets(req.params.id, "Sessão encerrada pelo jogador.");
    }
    res.status(204).end();
  });

  // HTTPS relay used automatically when a reverse proxy does not forward
  // WebSocket Upgrade headers. Secrets and session ownership are checked on
  // every endpoint while frames remain ephemeral and only in memory.
  app.post(
    "/api/agent/:token/remote/sessions/:id/frame",
    express.raw({ type: "image/jpeg", limit: MAX_FRAME_BYTES }),
    async (req, res) => {
      const runtime = await authorizeAgentRelay(req, res);
      if (!runtime) return;
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({ error: "invalid_frame" });
      }
      const sequence = storeFrame(req.params.id, req.body);
      const target = adminSockets.get(req.params.id);
      if (target?.readyState === WebSocket.OPEN) target.send(req.body, { binary: true });
      res.set("Cache-Control", "no-store").json({ sequence });
    }
  );

  app.get("/api/remote/admin/sessions/:id/frame", requireRemoteAdmin, async (req, res) => {
    const runtime = await authorizeAdminRelay(req, res);
    if (!runtime) return;
    const after = Math.max(0, Number(req.query.after) || 0);
    const frame = latestFrames.get(req.params.id);
    if (!frame || frame.sequence <= after || Date.now() - frame.createdAt > 15_000) {
      return res.status(204).end();
    }
    res.set({
      "Cache-Control": "no-store, max-age=0",
      "Content-Type": "image/jpeg",
      "X-Frame-Sequence": String(frame.sequence),
    });
    res.send(frame.data);
  });

  app.post("/api/remote/admin/sessions/:id/input", requireRemoteAdmin, async (req, res) => {
    const runtime = await authorizeAdminRelay(req, res);
    if (!runtime) return;
    if (runtime.mode !== "control" || runtime.adminId !== req.remoteAdmin.adminId) {
      return res.status(403).json({ error: "view_only" });
    }
    const type = req.body?.type;
    if (type !== "pointer" && type !== "key") return res.status(400).json({ error: "invalid_input" });
    if (JSON.stringify(req.body).length > 16_384) return res.status(413).json({ error: "input_too_large" });
    const target = agentSockets.get(req.params.id);
    if (target?.readyState === WebSocket.OPEN) {
      target.send(JSON.stringify(req.body));
      return res.status(202).json({ sequence: 0, relayed: true });
    }
    const sequence = queueInput(req.params.id, req.body);
    res.status(202).json({ sequence });
  });

  app.get("/api/agent/:token/remote/sessions/:id/input", async (req, res) => {
    const runtime = await authorizeAgentRelay(req, res);
    if (!runtime) return;
    if (runtime.mode !== "control") return res.json({ events: [] });
    const after = Math.max(0, Number(req.query.after) || 0);
    const queue = inputQueues.get(req.params.id);
    const events = queue?.events.filter((item) => item.sequence > after).slice(0, 50) || [];
    if (queue && after > 0) queue.events = queue.events.filter((item) => item.sequence > after);
    res.set("Cache-Control", "no-store").json({ events });
  });

  function closeSessionSockets(sessionId, reason) {
    for (const socket of [agentSockets.get(sessionId), adminSockets.get(sessionId)]) {
      if (socket?.readyState === WebSocket.OPEN) socket.close(1000, reason.slice(0, 120));
    }
    agentSockets.delete(sessionId);
    adminSockets.delete(sessionId);
    clearRelay(sessionId);
  }

  async function authenticateSocket(ws, auth) {
    const sessionId = clean(auth?.sessionId, 80);
    if (!sessionId) return null;
    if (auth?.role === "agent") {
      const result = await pool.query(
        `SELECT id, mode, status FROM remote_support_sessions
         WHERE id=$1 AND agent_secret_hash=$2 AND status='accepted' AND expires_at>NOW()`,
        [sessionId, hashSecret(auth.secret)]
      );
      if (!result.rows[0]) return null;
      agentSockets.set(sessionId, ws);
      return { role: "agent", sessionId, mode: result.rows[0].mode };
    }
    if (auth?.role === "admin") {
      const admin = tokenRecord(auth.accessToken);
      if (!admin) return null;
      const result = await pool.query(
        `SELECT id, mode, status FROM remote_support_sessions
         WHERE id=$1 AND admin_id=$2 AND status='accepted' AND expires_at>NOW()`,
        [sessionId, admin.adminId]
      );
      if (!result.rows[0]) return null;
      adminSockets.set(sessionId, ws);
      return { role: "admin", sessionId, mode: result.rows[0].mode };
    }
    return null;
  }

  return {
    attach(server) {
      const wss = new WebSocketServer({ server, path: "/ws/remote", maxPayload: MAX_FRAME_BYTES });
      wss.on("connection", (ws) => {
        let identity = null;
        const authTimer = setTimeout(() => ws.close(1008, "Autenticação necessária."), 10_000);
        ws.on("message", async (data, isBinary) => {
          if (!identity) {
            if (isBinary) return ws.close(1008, "Autenticação necessária.");
            try { identity = await authenticateSocket(ws, JSON.parse(data.toString())); } catch { identity = null; }
            if (!identity) return ws.close(1008, "Sessão inválida.");
            clearTimeout(authTimer);
            ws.send(JSON.stringify({ type: "authenticated", mode: identity.mode }));
            await audit(pool, identity.sessionId, identity.role, "connected");
            return;
          }
          if (identity.role === "agent" && isBinary) {
            storeFrame(identity.sessionId, data);
            const target = adminSockets.get(identity.sessionId);
            if (target?.readyState === WebSocket.OPEN) target.send(data, { binary: true });
          } else if (identity.role === "admin" && !isBinary && identity.mode === "control") {
            const target = agentSockets.get(identity.sessionId);
            if (target?.readyState === WebSocket.OPEN) target.send(data.toString());
            else {
              try { queueInput(identity.sessionId, JSON.parse(data.toString())); } catch { }
            }
          }
        });
        ws.on("close", () => {
          clearTimeout(authTimer);
          if (!identity) return;
          const map = identity.role === "agent" ? agentSockets : adminSockets;
          if (map.get(identity.sessionId) === ws) map.delete(identity.sessionId);
        });
      });
      return wss;
    },
  };
}
