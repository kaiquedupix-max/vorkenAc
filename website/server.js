import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import archiver from "archiver";
import pg from "pg";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const publicUrl = String(process.env.PUBLIC_URL || "http://localhost:" + port).replace(/\/$/, "");
const agentBinaryPath = String(
  process.env.AGENT_BINARY_PATH || path.join(__dirname, "agent-build", "Vorken.Agent.exe")
);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
});

const ADMIN_COOKIE = "vorken_admin";
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;

app.disable("x-powered-by");
app.use(express.json({ limit: "24mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: 0,
  setHeaders(res) {
    res.setHeader("Cache-Control", "no-store");
  },
}));

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sessionSecret() {
  return String(process.env.SESSION_SECRET || "");
}

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", sessionSecret())
    .update(body)
    .digest("base64url");
  return body + "." + signature;
}

function verifySession(token) {
  if (!token || !sessionSecret()) return null;
  const [body, signature] = String(token).split(".");
  if (!body || !signature) return null;

  const expected = crypto
    .createHmac("sha256", sessionSecret())
    .update(body)
    .digest("base64url");

  if (!safeEqual(signature, expected)) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const session = verifySession(req.cookies?.[ADMIN_COOKIE]);
  if (!session?.admin) return res.status(401).json({ error: "unauthorized" });
  next();
}

function analysisToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function validToken(value) {
  return /^[A-Za-z0-9_-]{20,80}$/.test(String(value || ""));
}

function normalizeSeverity(value) {
  const allowed = new Set(["info", "low", "medium", "high", "critical"]);
  const severity = String(value || "medium").toLowerCase();
  return allowed.has(severity) ? severity : "medium";
}

function cleanText(value, max = 250) {
  return String(value || "").trim().slice(0, max);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS analyses (
      id BIGSERIAL PRIMARY KEY,
      public_token TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'waiting',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      started_at TIMESTAMPTZ NULL,
      finished_at TIMESTAMPTZ NULL,
      machine_name TEXT NULL,
      os_version TEXT NULL,
      agent_version TEXT NULL
    );

    CREATE TABLE IF NOT EXISTS detection_rules (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      pattern TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      description TEXT NOT NULL DEFAULT '',
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scan_reports (
      id BIGSERIAL PRIMARY KEY,
      analysis_id BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scan_findings (
      id BIGSERIAL PRIMARY KEY,
      analysis_id BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
      rule_id BIGINT NULL REFERENCES detection_rules(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      artifact_type TEXT NOT NULL,
      artifact_value TEXT NOT NULL,
      evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_analysis ON scan_findings(analysis_id, id);
    CREATE INDEX IF NOT EXISTS idx_reports_analysis ON scan_reports(analysis_id, id DESC);

    INSERT INTO detection_rules(name, type, pattern, severity, description)
    SELECT 'Nome contendo loader', 'filename_contains', 'loader', 'medium',
           'Arquivo executável com loader no nome; requer revisão manual.'
    WHERE NOT EXISTS (
      SELECT 1 FROM detection_rules WHERE type='filename_contains' AND pattern='loader'
    );

    INSERT INTO detection_rules(name, type, pattern, severity, description)
    SELECT 'Nome contendo injector', 'filename_contains', 'injector', 'high',
           'Arquivo executável com injector no nome; requer revisão manual.'
    WHERE NOT EXISTS (
      SELECT 1 FROM detection_rules WHERE type='filename_contains' AND pattern='injector'
    );

    INSERT INTO detection_rules(name, type, pattern, severity, description)
    SELECT 'Dispositivo DMA', 'device_keyword', 'dma', 'high',
           'Dispositivo cujo nome/identificador contém DMA; não é prova isolada de cheat.'
    WHERE NOT EXISTS (
      SELECT 1 FROM detection_rules WHERE type='device_keyword' AND pattern='dma'
    );
  `);
}

async function getAnalysisByToken(token) {
  const result = await pool.query(
    `SELECT *
     FROM analyses
     WHERE public_token = $1
     LIMIT 1`,
    [token]
  );
  return result.rows[0] || null;
}

function ensureAnalysisUsable(analysis, res) {
  if (!analysis) {
    res.status(404).json({ error: "analysis_not_found", message: "Análise não encontrada." });
    return false;
  }

  if (new Date(analysis.expires_at).getTime() <= Date.now() && analysis.status !== "completed") {
    res.status(410).json({ error: "analysis_expired", message: "Esta análise expirou." });
    return false;
  }

  return true;
}

function flattenArtifacts(report) {
  const items = [];
  const push = (type, value, evidence = {}) => {
    if (!value) return;
    items.push({ type, value: String(value), evidence });
  };

  for (const file of report.files || []) {
    push("file", file.path || file.name, file);
  }

  for (const process of report.processes || []) {
    push("process", process.name || process.path, process);
  }

  for (const device of [...(report.usbCurrent || []), ...(report.usbHistory || []), ...(report.serialDevices || [])]) {
    push("device", device.name || device.deviceId || device.instanceId, device);
  }

  for (const service of report.services || []) {
    push("service", service.name || service.displayName, service);
  }

  for (const driver of report.drivers || []) {
    push("driver", driver.name || driver.pathName, driver);
  }

  for (const prefetch of report.prefetch || []) {
    push("prefetch", prefetch.name || prefetch.path, prefetch);
  }

  for (const startup of report.startup || []) {
    push("startup", startup.name || startup.command, startup);
  }

  for (const bam of report.bam || []) {
    push("bam", bam.path, bam);
  }

  for (const item of report.userAssist || []) {
    push("userassist", item.decodedName || item.encodedName, item);
  }

  for (const item of report.muiCache || []) {
    push("muicache", item.path || item.displayName, item);
  }

  for (const item of report.pca || []) {
    push("pca", item.path, item);
  }

  for (const item of report.setupApiUsb || []) {
    push("setupapi_usb", item.evidence || item.section, item);
  }

  for (const item of report.powerShellHits || []) {
    push("powershell", item.matchedLine || item.pattern, item);
  }

  for (const item of report.prefetchIntegrity || []) {
    push("prefetch_integrity", item.name || item.kind, item);
  }

  for (const item of report.hiddenVolumes || []) {
    push("volume", item.deviceId || item.label, item);
  }

  for (const item of report.logClearSignals || []) {
    push("log_signal", item.signal || item.channel, item);
  }

  if (report.systemArtifacts) {
    push("system_artifact", "windows-artifact-state", report.systemArtifacts);
  }

  return items;
}

function matchesRule(rule, artifact) {
  const pattern = String(rule.pattern || "").toLowerCase();
  const value = String(artifact.value || "").toLowerCase();
  const evidence = artifact.evidence || {};

  switch (rule.type) {
    case "filename_contains":
      return artifact.type === "file" &&
        String(evidence.name || path.basename(value)).toLowerCase().includes(pattern);
    case "path_contains":
      return artifact.type === "file" && value.includes(pattern);
    case "sha256":
      return artifact.type === "file" &&
        String(evidence.sha256 || "").toLowerCase() === pattern.replace(/\s/g, "");
    case "process_name":
      return artifact.type === "process" &&
        String(evidence.name || value).toLowerCase().includes(pattern);
    case "service_name":
      return artifact.type === "service" &&
        (String(evidence.name || "").toLowerCase().includes(pattern) ||
         String(evidence.displayName || "").toLowerCase().includes(pattern));
    case "driver_name":
      return artifact.type === "driver" &&
        (String(evidence.name || "").toLowerCase().includes(pattern) ||
         String(evidence.pathName || "").toLowerCase().includes(pattern));
    case "device_keyword":
      return artifact.type === "device" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "prefetch_contains":
      return artifact.type === "prefetch" && value.includes(pattern);
    case "bam_contains":
      return artifact.type === "bam" && value.includes(pattern);
    case "userassist_contains":
      return artifact.type === "userassist" && value.includes(pattern);
    case "muicache_contains":
      return artifact.type === "muicache" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "pca_contains":
      return artifact.type === "pca" && value.includes(pattern);
    case "setupapi_contains":
      return artifact.type === "setupapi_usb" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "powershell_contains":
      return artifact.type === "powershell" &&
        (value.includes(pattern) ||
         String(evidence.pattern || "").toLowerCase() === pattern);
    case "signer_contains":
      return ["file", "process"].includes(artifact.type) &&
        String(evidence.signerSubject || "").toLowerCase().includes(pattern);
    case "prefetch_integrity":
      return artifact.type === "prefetch_integrity" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "volume_keyword":
      return artifact.type === "volume" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "log_clear_signal":
      return artifact.type === "log_signal" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    default:
      return false;
  }
}

async function rebuildFindings(analysisId, report) {
  await pool.query("DELETE FROM scan_findings WHERE analysis_id = $1", [analysisId]);

  const rulesResult = await pool.query(
    `SELECT id, name, type, pattern, severity, description
     FROM detection_rules
     WHERE enabled = TRUE
     ORDER BY id ASC`
  );

  const artifacts = flattenArtifacts(report);

  for (const rule of rulesResult.rows) {
    for (const artifact of artifacts) {
      if (!matchesRule(rule, artifact)) continue;

      await pool.query(
        `INSERT INTO scan_findings(
           analysis_id, rule_id, title, severity, artifact_type, artifact_value, evidence
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
        [
          analysisId,
          rule.id,
          rule.name,
          normalizeSeverity(rule.severity),
          artifact.type,
          artifact.value.slice(0, 2000),
          JSON.stringify({
            ...artifact.evidence,
            ruleDescription: rule.description || "",
          }),
        ]
      );
    }
  }

  await addBuiltInReviewFindings(analysisId, report);
}

async function insertReviewFinding(
  analysisId,
  title,
  severity,
  artifactType,
  artifactValue,
  evidence
) {
  await pool.query(
    `INSERT INTO scan_findings(
       analysis_id, rule_id, title, severity, artifact_type, artifact_value, evidence
     )
     VALUES ($1,NULL,$2,$3,$4,$5,$6::jsonb)`,
    [
      analysisId,
      title,
      normalizeSeverity(severity),
      artifactType,
      String(artifactValue || "").slice(0, 2000),
      JSON.stringify(evidence || {}),
    ]
  );
}

async function addBuiltInReviewFindings(analysisId, report) {
  for (const item of report.prefetchIntegrity || []) {
    await insertReviewFinding(
      analysisId,
      item.kind === "duplicate_hash"
        ? "Revisão: arquivos Prefetch com hash duplicado"
        : "Revisão: integridade do Prefetch",
      item.kind === "duplicate_hash" ? "medium" : "low",
      "prefetch_integrity",
      item.name || item.kind,
      {
        ...item,
        note: "Indicador técnico para revisão; não é prova isolada de cheat.",
      }
    );
  }

  for (const item of report.hiddenVolumes || []) {
    if (item.expectedSystemVolume) continue;

    await insertReviewFinding(
      analysisId,
      "Revisão: volume sem letra de unidade",
      "low",
      "volume",
      item.deviceId || item.label || "volume",
      {
        ...item,
        note: "Volumes sem letra podem ser legítimos; correlacione com outras evidências.",
      }
    );
  }

  for (const item of report.logClearSignals || []) {
    await insertReviewFinding(
      analysisId,
      "Revisão: limpeza recente de log do Windows",
      "medium",
      "event_log",
      item.signal || item.channel,
      {
        ...item,
        note: "Limpeza de log pode ter causa administrativa legítima; requer contexto.",
      }
    );
  }

  const state = report.systemArtifacts || {};

  if (state.prefetchDirectoryExists === false) {
    await insertReviewFinding(
      analysisId,
      "Revisão: diretório Prefetch ausente",
      "medium",
      "system_artifact",
      "Prefetch",
      {
        ...state,
        note: "A ausência do Prefetch reduz evidências de execução e também pode decorrer de configuração do sistema.",
      }
    );
  }

  if (state.enablePrefetcher === 0) {
    await insertReviewFinding(
      analysisId,
      "Revisão: Prefetch desativado",
      "medium",
      "system_artifact",
      "EnablePrefetcher=0",
      {
        ...state,
        note: "Configuração pode ser legítima; correlacione com o restante da análise.",
      }
    );
  }

  if (state.bamStart === 4) {
    await insertReviewFinding(
      analysisId,
      "Revisão: BAM desativado",
      "medium",
      "system_artifact",
      "BAM Start=4",
      {
        ...state,
        note: "BAM desativado reduz um artefato de execução; não implica cheat por si só.",
      }
    );
  }
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "vorken-anticheat" });
});

app.post("/api/admin/login", (req, res) => {
  const configured = String(process.env.ADMIN_PASSWORD || "");
  if (!configured || !sessionSecret()) {
    return res.status(503).json({
      error: "admin_not_configured",
      message: "Configure ADMIN_PASSWORD e SESSION_SECRET.",
    });
  }

  if (!safeEqual(req.body?.password, configured)) {
    return res.status(401).json({ error: "invalid_credentials", message: "Senha incorreta." });
  }

  const token = signSession({
    admin: true,
    exp: Date.now() + ADMIN_SESSION_MS,
  });

  res.cookie(ADMIN_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: ADMIN_SESSION_MS,
  });

  res.json({ ok: true });
});

app.post("/api/admin/logout", (_req, res) => {
  res.clearCookie(ADMIN_COOKIE);
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (_req, res) => {
  res.json({ authenticated: true });
});

app.get("/api/admin/analyses", requireAdmin, async (_req, res) => {
  const result = await pool.query(`
    SELECT
      a.*,
      COALESCE(f.total_findings, 0)::int AS total_findings,
      COALESCE(f.high_findings, 0)::int AS high_findings
    FROM analyses a
    LEFT JOIN (
      SELECT
        analysis_id,
        COUNT(*) AS total_findings,
        COUNT(*) FILTER (WHERE severity IN ('high','critical')) AS high_findings
      FROM scan_findings
      GROUP BY analysis_id
    ) f ON f.analysis_id = a.id
    ORDER BY a.id DESC
    LIMIT 500
  `);

  res.json({ analyses: result.rows });
});

app.post("/api/admin/analyses", requireAdmin, async (req, res) => {
  const label = cleanText(req.body?.label, 140);
  const ttlHours = Math.max(1, Math.min(168, Math.trunc(Number(req.body?.ttlHours || 24))));

  if (label.length < 2) {
    return res.status(400).json({ error: "invalid_label", message: "Informe um nome para a análise." });
  }

  const token = analysisToken();
  const result = await pool.query(
    `INSERT INTO analyses(public_token, label, expires_at)
     VALUES ($1,$2,NOW() + ($3 || ' hours')::interval)
     RETURNING *`,
    [token, label, String(ttlHours)]
  );

  const analysis = result.rows[0];
  res.status(201).json({
    analysis,
    publicLink: publicUrl + "/a/" + token,
  });
});

app.get("/api/admin/analyses/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid_id" });

  const analysisResult = await pool.query("SELECT * FROM analyses WHERE id = $1 LIMIT 1", [id]);
  const analysis = analysisResult.rows[0];
  if (!analysis) return res.status(404).json({ error: "analysis_not_found" });

  const reportResult = await pool.query(
    "SELECT payload, created_at FROM scan_reports WHERE analysis_id = $1 ORDER BY id DESC LIMIT 1",
    [id]
  );

  const findingsResult = await pool.query(
    `SELECT id, rule_id, title, severity, artifact_type, artifact_value, evidence, created_at
     FROM scan_findings
     WHERE analysis_id = $1
     ORDER BY
       CASE severity
         WHEN 'critical' THEN 5
         WHEN 'high' THEN 4
         WHEN 'medium' THEN 3
         WHEN 'low' THEN 2
         ELSE 1
       END DESC,
       id ASC`,
    [id]
  );

  res.json({
    analysis,
    report: reportResult.rows[0] || null,
    findings: findingsResult.rows,
  });
});

app.get("/api/admin/rules", requireAdmin, async (_req, res) => {
  const result = await pool.query(
    "SELECT * FROM detection_rules ORDER BY enabled DESC, id DESC"
  );
  res.json({ rules: result.rows });
});

app.post("/api/admin/rules", requireAdmin, async (req, res) => {
  const allowedTypes = new Set([
    "filename_contains",
    "path_contains",
    "sha256",
    "process_name",
    "service_name",
    "driver_name",
    "device_keyword",
    "prefetch_contains",
    "bam_contains",
    "userassist_contains",
    "muicache_contains",
    "pca_contains",
    "setupapi_contains",
    "powershell_contains",
    "signer_contains",
    "prefetch_integrity",
    "volume_keyword",
    "log_clear_signal",
  ]);

  const name = cleanText(req.body?.name, 120);
  const type = cleanText(req.body?.type, 60);
  const pattern = cleanText(req.body?.pattern, 500);
  const description = cleanText(req.body?.description, 600);
  const severity = normalizeSeverity(req.body?.severity);

  if (!name || !allowedTypes.has(type) || !pattern) {
    return res.status(400).json({ error: "invalid_rule", message: "Regra inválida." });
  }

  const result = await pool.query(
    `INSERT INTO detection_rules(name, type, pattern, severity, description)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING *`,
    [name, type, pattern, severity, description]
  );

  res.status(201).json({ rule: result.rows[0] });
});

app.post("/api/admin/rules/:id/toggle", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const result = await pool.query(
    `UPDATE detection_rules
     SET enabled = NOT enabled
     WHERE id = $1
     RETURNING *`,
    [id]
  );

  if (!result.rows[0]) return res.status(404).json({ error: "rule_not_found" });
  res.json({ rule: result.rows[0] });
});

app.get("/api/public/analyses/:token", async (req, res) => {
  const token = String(req.params.token || "");
  if (!validToken(token)) return res.status(404).json({ error: "analysis_not_found" });

  const analysis = await getAnalysisByToken(token);
  if (!ensureAnalysisUsable(analysis, res)) return;

  res.json({
    analysis: {
      label: analysis.label,
      status: analysis.status,
      createdAt: analysis.created_at,
      expiresAt: analysis.expires_at,
      startedAt: analysis.started_at,
      finishedAt: analysis.finished_at,
    },
    packageUrl: "/api/public/analyses/" + token + "/package",
  });
});

app.get("/api/public/analyses/:token/package", async (req, res) => {
  const token = String(req.params.token || "");
  if (!validToken(token)) return res.status(404).send("Análise não encontrada.");

  const analysis = await getAnalysisByToken(token);
  if (!ensureAnalysisUsable(analysis, res)) return;

  if (!fs.existsSync(agentBinaryPath)) {
    return res.status(503).send(
      "O executável do Vorken Agent ainda não foi publicado no servidor."
    );
  }

  const config = JSON.stringify({
    token,
    serverUrl: publicUrl,
    analysisLabel: analysis.label,
  }, null, 2);

  res.setHeader("Content-Type", "application/zip");
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="Vorken-' + analysis.id + '.zip"'
  );

  const zip = archiver("zip", { zlib: { level: 9 } });
  zip.on("error", (error) => {
    console.error(error);
    if (!res.headersSent) res.status(500).end();
    else res.destroy(error);
  });

  zip.pipe(res);
  zip.file(agentBinaryPath, { name: "Vorken.Agent.exe" });
  zip.append(config, { name: "vorken-analysis.json" });
  zip.finalize();
});

app.get("/api/agent/:token/rules", async (req, res) => {
  const token = String(req.params.token || "");
  const analysis = validToken(token) ? await getAnalysisByToken(token) : null;
  if (!ensureAnalysisUsable(analysis, res)) return;

  const result = await pool.query(
    `SELECT id, name, type, pattern, severity, description
     FROM detection_rules
     WHERE enabled = TRUE
     ORDER BY id ASC`
  );

  res.json({
    analysisId: Number(analysis.id),
    rules: result.rows,
  });
});

app.post("/api/agent/:token/start", async (req, res) => {
  const token = String(req.params.token || "");
  const analysis = validToken(token) ? await getAnalysisByToken(token) : null;
  if (!ensureAnalysisUsable(analysis, res)) return;

  if (analysis.status === "completed") {
    return res.status(409).json({
      error: "analysis_completed",
      message: "Esta análise já foi concluída.",
    });
  }

  await pool.query(
    `UPDATE analyses
     SET status='running',
         started_at=COALESCE(started_at, NOW()),
         machine_name=COALESCE($2, machine_name),
         os_version=COALESCE($3, os_version),
         agent_version=COALESCE($4, agent_version)
     WHERE id=$1`,
    [
      analysis.id,
      cleanText(req.body?.machineName, 180) || null,
      cleanText(req.body?.osVersion, 250) || null,
      cleanText(req.body?.agentVersion, 80) || null,
    ]
  );

  res.json({ ok: true });
});

app.post("/api/agent/:token/report", async (req, res) => {
  const token = String(req.params.token || "");
  const analysis = validToken(token) ? await getAnalysisByToken(token) : null;
  if (!ensureAnalysisUsable(analysis, res)) return;

  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    return res.status(400).json({ error: "invalid_report" });
  }

  const report = req.body;

  await pool.query(
    "INSERT INTO scan_reports(analysis_id, payload) VALUES ($1,$2::jsonb)",
    [analysis.id, JSON.stringify(report)]
  );

  await rebuildFindings(analysis.id, report);

  await pool.query(
    `UPDATE analyses
     SET status='completed',
         finished_at=NOW(),
         machine_name=COALESCE($2, machine_name),
         os_version=COALESCE($3, os_version),
         agent_version=COALESCE($4, agent_version)
     WHERE id=$1`,
    [
      analysis.id,
      cleanText(report.machine?.machineName, 180) || null,
      cleanText(report.machine?.osVersion, 250) || null,
      cleanText(report.agentVersion, 80) || null,
    ]
  );

  const findingCount = await pool.query(
    "SELECT COUNT(*)::int AS total FROM scan_findings WHERE analysis_id=$1",
    [analysis.id]
  );

  res.json({
    ok: true,
    findings: Number(findingCount.rows[0]?.total || 0),
  });
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/a/:token", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "analysis.html"));
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb()
  .then(() => {
    app.listen(port, "0.0.0.0", () => {
      console.log("Vorken web ouvindo na porta " + port);
    });
  })
  .catch((error) => {
    console.error("Falha ao inicializar Vorken:", error);
    process.exit(1);
  });
