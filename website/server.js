import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
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

const rustThreatCatalogPath = path.join(
  __dirname,
  "data",
  "rust-threat-catalog.json"
);

function loadRustThreatCatalog() {
  try {
    const payload = JSON.parse(
      fs.readFileSync(rustThreatCatalogPath, "utf8")
    );

    return Array.isArray(payload?.brands)
      ? payload.brands
      : [];
  } catch (error) {
    console.error("Falha ao carregar catálogo Rust:", error.message);
    return [];
  }
}

const rustThreatCatalog = loadRustThreatCatalog();
const commonAppCatalogPath = path.join(
  __dirname,
  "data",
  "common-app-catalog.json"
);

function loadCommonAppCatalog() {
  try {
    const payload = JSON.parse(
      fs.readFileSync(commonAppCatalogPath, "utf8")
    );

    return Array.isArray(payload?.apps)
      ? payload.apps
      : [];
  } catch (error) {
    console.error("Falha ao carregar catálogo de apps comuns:", error.message);
    return [];
  }
}

const commonAppCatalog = loadCommonAppCatalog();


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

function findCommonAppByFileName(value) {
  const name = path.basename(String(value || "")).toLowerCase();
  if (!name) return null;

  for (const appInfo of commonAppCatalog) {
    const exact = (appInfo.filenames || [])
      .some((item) => String(item || "").toLowerCase() === name);

    if (exact) return appInfo;

    const prefix = (appInfo.filenamePrefixes || [])
      .some((item) => {
        const needle = String(item || "").toLowerCase();
        return needle && name.startsWith(needle);
      });

    if (prefix) return appInfo;
  }

  return null;
}

function signerMatchesCommonApp(appInfo, signerSubject) {
  if (!appInfo) return false;

  const signer = String(signerSubject || "").toLowerCase();
  if (!signer) return false;

  return (appInfo.signerContains || [])
    .some((needle) =>
      signer.includes(String(needle || "").toLowerCase()));
}

function downloadMatchesOfficialSource(appInfo, download) {
  if (!appInfo) return false;

  const urls = [
    download?.sourceUrl,
    download?.finalUrl,
    download?.referrerUrl,
    download?.siteUrl,
    download?.pageUrl,
    ...(Array.isArray(download?.urlChain) ? download.urlChain : [])
  ]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());

  if (!urls.length) return false;

  for (const needleRaw of appInfo.officialUrlIncludes || []) {
    const needle = String(needleRaw || "").toLowerCase();
    if (!needle) continue;

    if (urls.some((url) => url.includes(needle)))
      return true;
  }

  return false;
}

function isTrustedInstalledPathForCommonApp(value) {
  const p = String(value || "")
    .replaceAll("/", "\\")
    .toLowerCase();

  return (
    p.includes("\\program files\\") ||
    p.includes("\\program files (x86)\\") ||
    p.includes("\\windowsapps\\") ||
    p.includes("\\appdata\\local\\discord\\") ||
    p.includes("\\appdata\\local\\programs\\") ||
    p.includes("\\appdata\\local\\spotify\\")
  );
}

function looksRandomExecutableName(value) {
  const name = path.basename(String(value || ""));
  let stem = path.basename(name, path.extname(name));

  stem = stem.replace(/\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$/i, "");

  if (stem.length < 4 || stem.length > 28) return false;
  if (!/^[a-z0-9]+$/i.test(stem)) return false;

  const letters = [...stem].filter((ch) => /[a-z]/i.test(ch));
  const digits = [...stem].filter((ch) => /[0-9]/.test(ch));
  const vowels = letters.filter((ch) => /[aeiou]/i.test(ch));
  const distinct = new Set(stem.toUpperCase()).size;
  const allUpperOrDigits = /^[A-Z0-9]+$/.test(stem);
  const vowelRatio = letters.length ? vowels.length / letters.length : 0;

  // 4-5 chars: only flag very "machine-like" tokens. This protects short
  // legitimate names such as java/node/code while still catching X7Q2.exe.
  if (stem.length <= 5) {
    return (
      allUpperOrDigits &&
      distinct >= Math.max(4, stem.length - 1) &&
      (
        digits.length >= 1 ||
        vowels.length === 0
      ) &&
      vowelRatio <= 0.25
    );
  }

  if (
    allUpperOrDigits &&
    distinct >= Math.min(6, stem.length - 1) &&
    vowelRatio <= 0.35 &&
    (
      digits.length >= 1 ||
      letters.length >= 5
    )
  ) {
    return true;
  }

  if (
    stem.length >= 8 &&
    stem.length <= 18 &&
    digits.length === 0 &&
    letters.length === stem.length &&
    distinct >= 7 &&
    vowelRatio <= 0.22
  ) {
    return true;
  }

  return (
    stem.length >= 10 &&
    letters.length >= 6 &&
    digits.length >= 2 &&
    distinct >= 8
  );
}

function isDeceptiveDoubleExtensionExecutable(value) {
  const name = path.basename(String(value || "")).toLowerCase();
  return /\.(zip|rar|7z|pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx|ppt|pptx)\.exe$/.test(name);
}

function downloadOriginKind(download) {
  const values = [
    download?.sourceUrl,
    download?.finalUrl,
    download?.referrerUrl,
    download?.siteUrl,
    download?.pageUrl,
    ...(Array.isArray(download?.urlChain) ? download.urlChain : [])
  ]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());

  const joined = values.join(" ");

  const discord =
    joined.includes("discord.com/") ||
    joined.includes("discord.gg/") ||
    joined.includes("discordapp.com/") ||
    joined.includes("cdn.discordapp.com/") ||
    joined.includes("media.discordapp.net/") ||
    joined.includes("discordattachments.com/");

  if (discord) return "Discord";

  const telegram =
    joined.includes("t.me/") ||
    joined.includes("telegram.me/") ||
    joined.includes("telegram.org/") ||
    joined.includes("web.telegram.org/") ||
    joined.includes("telegram-cdn.org/") ||
    joined.includes("cdn-telegram.org/");

  if (telegram) return "Telegram";

  return "";
}

function chromiumDangerInfo(value) {
  const code = Number(value ?? 0);

  const map = new Map([
    [1, ["Arquivo perigoso", "high"]],
    [2, ["URL perigosa", "high"]],
    [3, ["Conteúdo perigoso", "high"]],
    [4, ["Conteúdo possivelmente perigoso", "medium"]],
    [5, ["Download incomum", "medium"]],
    [6, ["Alerta validado/ignorado pelo usuário", "medium"]],
    [7, ["Host perigoso", "high"]],
    [8, ["Software potencialmente indesejado", "high"]],
    [16, ["Deep Scan: perigoso", "high"]],
    [19, ["Risco de comprometimento de conta", "high"]],
  ]);

  const hit = map.get(code);
  return hit
    ? { code, label: hit[0], severity: hit[1], suspicious: true }
    : { code, label: code ? "DangerType " + code : "Sem alerta", severity: "info", suspicious: false };
}

function isRiskyDownloadName(value) {
  const name = String(value || "").toLowerCase();
  return /\.(exe|com|scr|dll|msi|bat|cmd|ps1|zip|rar|7z)$/.test(name) ||
    isDeceptiveDoubleExtensionExecutable(name);
}

function findRustCatalogMatches(...values) {
  const haystack = values
    .flat(Infinity)
    .filter((value) => value !== null && value !== undefined)
    .map((value) =>
      typeof value === "string"
        ? value
        : JSON.stringify(value)
    )
    .join(" ")
    .toLowerCase();

  if (!haystack) return [];

  const matches = [];

  for (const brand of rustThreatCatalog) {
    let matchedBy = "";

    for (const domain of brand.domains || []) {
      const needle = String(domain || "").toLowerCase();
      if (needle && haystack.includes(needle)) {
        matchedBy = "domain:" + domain;
        break;
      }
    }

    if (!matchedBy) {
      for (const invite of brand.discordInvites || []) {
        const needle = String(invite || "").toLowerCase();
        if (
          needle &&
          (
            haystack.includes("discord.gg/" + needle) ||
            haystack.includes("discord.com/invite/" + needle) ||
            haystack.includes("discord.me/" + needle)
          )
        ) {
          matchedBy = "discord:" + invite;
          break;
        }
      }
    }

    if (!matchedBy) {
      for (const alias of brand.aliases || []) {
        const needle = String(alias || "").toLowerCase().trim();
        if (!needle || !haystack.includes(needle)) continue;

        const distinctive =
          needle.length >= 7 ||
          /rust|cheat|script|aimbot|recoil|loader|private|dma|external|internal/.test(needle);

        if (!distinctive) continue;

        matchedBy = "alias:" + alias;
        break;
      }
    }

    if (matchedBy) {
      matches.push({
        name: brand.name,
        severity: normalizeSeverity(brand.severity || "high"),
        matchedBy,
      });
    }
  }

  return matches;
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

    ALTER TABLE analyses
      ADD COLUMN IF NOT EXISTS machine_fingerprint TEXT NULL;

    CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_analyses_fingerprint ON analyses(machine_fingerprint);
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

  for (const item of report.peInspections || []) {
    push("pe_inspection", item.path || item.name, item);
  }

  for (const item of report.zoneIdentifiers || []) {
    push("zone_identifier", item.path || item.hostUrl || item.fileName, item);
  }

  for (const item of report.alternateDataStreams || []) {
    push("alternate_stream", (item.path || "") + (item.streamName || ""), item);
  }

  for (const item of report.autorunIntegrity || []) {
    push("autorun_integrity", item.executablePath || item.command || item.name, item);
  }

  for (const item of report.processModuleIntegrity || []) {
    push("module_integrity", item.modulePath || item.moduleName, item);
  }

  for (const item of report.protectedWindows || []) {
    push("protected_window", item.processPath || item.processName, item);
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

  for (const execution of report.prefetchExecutions || []) {
    push(
      "prefetch_execution",
      execution.executableName || execution.nativeExecutablePath || execution.prefetchFile,
      execution
    );
  }

  for (const usbEvent of report.usbTimeline || []) {
    push(
      "usb_event",
      usbEvent.deviceId || usbEvent.evidence || String(usbEvent.eventId || ""),
      usbEvent
    );
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

  for (const item of report.amcache || []) {
    push("amcache", item.fullPath || item.name, item);
  }

  for (const item of report.shimCache || []) {
    push("shimcache", item.path, item);
  }

  for (const item of report.setupApiUsb || []) {
    push("setupapi_usb", item.evidence || item.section, item);
  }

  for (const item of report.powerShellHits || []) {
    push("powershell", item.matchedLine || item.pattern, item);
  }

  for (const item of report.powerShellArtifacts || []) {
    push("powershell_artifact", item.command || item.source, item);
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

  for (const item of report.processCreationEvents || []) {
    push("process_history", item.processPath || item.processName, item);
  }

  for (const item of report.defenderDetections || []) {
    push("defender_detection", item.threatName || item.path, item);
  }

  for (const item of report.recentShortcuts || []) {
    push("recent_link", item.targetPath || item.shortcutName, item);
  }

  for (const item of report.crashArtifacts || []) {
    push("crash_artifact", item.appPath || item.appName || item.artifactPath, item);
  }

  for (const item of report.securityProducts || []) {
    push("security_product", item.displayName || item.category, item);
  }

  for (const item of report.browserDownloads || []) {
    push(
      "browser_download",
      item.targetPath || item.fileName || item.sourceUrl || item.finalUrl,
      item
    );
  }

  for (const item of report.browserHistorySignals || []) {
    push(
      "browser_history",
      item.searchQuery || item.url || item.title || item.host,
      item
    );
  }

  for (const item of report.browserRecoveredArtifacts || []) {
    push(
      "browser_recovery",
      item.recoveredUrl || item.recoveredFileName || item.sourceArtifact,
      item
    );
  }

  for (const item of report.networkIndicators || []) {
    push(
      "network_indicator",
      item.domain || item.processPath || item.remoteAddress || item.processName,
      item
    );
  }

  for (const item of report.deletedUsnRecords || []) {
    push(
      "usn_delete",
      item.fileName || item.volume,
      item
    );
  }

  for (const item of report.recycleBin || []) {
    push(
      "recycle_bin",
      item.originalPath || item.fileName || item.recycledDataPath,
      item
    );
  }

  for (const item of report.extensionMismatches || []) {
    push("extension_mismatch", item.path || item.name, item);
  }

  for (const item of report.defenderExclusions || []) {
    push("defender_exclusion", item.value || item.category, item);
  }

  for (const item of report.bootIntegrity || []) {
    push("boot_integrity", item.raw || item.setting, item);
  }

  for (const item of report.systemTimeChanges || []) {
    push("time_change", item.processName || item.newTime, item);
  }

  for (const item of report.virtualDisks || []) {
    push("virtual_disk", item.model || item.caption || item.deviceId, item);
  }

  for (const item of report.rustModules || []) {
    push("rust_module", item.path || item.moduleName, item);
  }

  for (const item of report.usnJournalState || []) {
    push("usn_state", item.volume, item);
  }

  for (const item of report.usnActivity || []) {
    push("usn_activity", item.fileName || item.volume, item);
  }

  for (const item of report.systemIntegrityExpansion || []) {
    push("system_integrity_expansion", item.name || item.kind || item.detail, item);
  }

  if (report.activityHistory) {
    push("activity_history", "activity-history-state", report.activityHistory);
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
    case "amcache_contains":
      return artifact.type === "amcache" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "shimcache_contains":
      return artifact.type === "shimcache" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
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
    case "execution_name":
      return artifact.type === "prefetch_execution" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "usb_event_keyword":
      return artifact.type === "usb_event" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "process_history_contains":
      return artifact.type === "process_history" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "recent_link_contains":
      return artifact.type === "recent_link" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "download_url_contains":
      return artifact.type === "browser_download" &&
        [
          evidence.sourceUrl,
          evidence.finalUrl,
          evidence.referrerUrl,
          evidence.pageUrl,
          evidence.siteUrl,
        ].some((value) =>
          String(value || "").toLowerCase().includes(pattern));
    case "download_name_contains":
      return artifact.type === "browser_download" &&
        [
          evidence.fileName,
          evidence.targetPath,
          evidence.currentPath,
        ].some((value) =>
          String(value || "").toLowerCase().includes(pattern));
    case "browser_history_contains":
      return artifact.type === "browser_history" &&
        [
          evidence.url,
          evidence.host,
          evidence.title,
          evidence.searchQuery,
          ...(Array.isArray(evidence.matchedTerms) ? evidence.matchedTerms : []),
        ].some((value) =>
          String(value || "").toLowerCase().includes(pattern));
    case "browser_recovery_contains":
      return artifact.type === "browser_recovery" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "deleted_name_contains":
      return artifact.type === "usn_delete" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "recycle_name_contains":
      return artifact.type === "recycle_bin" &&
        [
          evidence.fileName,
          evidence.originalPath,
          evidence.recycledDataPath,
        ].some((value) =>
          String(value || "").toLowerCase().includes(pattern));
    case "rust_module_contains":
      return artifact.type === "rust_module" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "defender_history_contains":
      return artifact.type === "defender_detection" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "defender_exclusion_contains":
      return artifact.type === "defender_exclusion" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "pe_indicator_contains":
      return artifact.type === "pe_inspection" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "zone_url_contains":
      return artifact.type === "zone_identifier" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "ads_contains":
      return artifact.type === "alternate_stream" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "autorun_contains":
      return artifact.type === "autorun_integrity" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "powershell_artifact_contains":
      return artifact.type === "powershell_artifact" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "network_indicator_contains":
      return artifact.type === "network_indicator" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "usn_activity_contains":
      return artifact.type === "usn_activity" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "system_integrity_contains":
      return artifact.type === "system_integrity_expansion" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "module_integrity_contains":
      return artifact.type === "module_integrity" &&
        JSON.stringify(evidence).toLowerCase().includes(pattern);
    case "crash_contains":
      return artifact.type === "crash_artifact" &&
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
  const now = Date.now();

  const ageDays = (value) => {
    if (!value) return Number.POSITIVE_INFINITY;
    const ms = new Date(value).getTime();
    return Number.isFinite(ms)
      ? (now - ms) / 86400000
      : Number.POSITIVE_INFINITY;
  };

  const normalizePath = (value) =>
    String(value || "")
      .replaceAll("/", "\\")
      .toLowerCase();

  const isTrustedInstalledPath = (value) => {
    const p = normalizePath(value);

    return (
      p.includes("\\windows\\") ||
      p.includes("\\program files\\") ||
      p.includes("\\program files (x86)\\") ||
      p.includes("\\steam\\steamapps\\common\\") ||
      p.includes("\\steamapps\\common\\")
    );
  };

  const isSuspiciousUserPath = (value) => {
    const p = normalizePath(value);

    return (
      p.includes("\\appdata\\local\\temp\\") ||
      p.includes("\\temp\\") ||
      p.includes("\\downloads\\") ||
      p.includes("\\desktop\\")
    );
  };

  const isVolumeRootExecutable = (value) => {
    const p = normalizePath(value);
    return /^\\volume\{[^}]+\}\\[^\\]+\.(exe|com|scr)$/i.test(p);
  };

  const fileName = (value) => {
    const p = normalizePath(value);
    const parts = p.split("\\").filter(Boolean);
    return parts.at(-1) || "";
  };

  const catalogFindingKeys = new Set();

  const addCatalogFindings = async (artifactType, artifactValue, evidence, values) => {
    const matches = findRustCatalogMatches(values);

    for (const match of matches) {
      const key = [
        artifactType,
        match.name,
        String(artifactValue || "").toLowerCase()
      ].join("|");

      if (catalogFindingKeys.has(key))
        continue;

      catalogFindingKeys.add(key);

      const catalogSeverity =
        ["browser_download", "browser_history"].includes(artifactType)
          ? "critical"
          : match.severity === "critical"
            ? "critical"
            : "high";

      await insertReviewFinding(
        analysisId,
        "Catálogo Rust: " + match.name,
        catalogSeverity,
        artifactType,
        artifactValue || match.name,
        {
          ...evidence,
          catalogMatch: match,
          confidence: "high",
          note: "Nome, domínio ou convite público associado a software/comunidade de cheat/script para Rust foi encontrado. Esta assinatura é tratada como evidência de alta prioridade, mas ainda deve ser revisada no contexto completo.",
        }
      );
    }
  };

  for (const item of report.files || []) {
    await addCatalogFindings(
      "file",
      item.path || item.name,
      item,
      [item.name, item.path, item.archiveEntries]
    );
  }

  for (const item of report.browserDownloads || []) {
    await addCatalogFindings(
      "browser_download",
      item.targetPath || item.fileName || item.sourceUrl,
      item,
      [
        item.fileName,
        item.targetPath,
        item.currentPath,
        item.sourceUrl,
        item.finalUrl,
        item.pageUrl,
        item.referrerUrl,
        item.siteUrl
      ]
    );
  }

  for (const item of report.browserHistorySignals || []) {
    await addCatalogFindings(
      "browser_history",
      item.searchQuery || item.url || item.host,
      item,
      [
        item.url,
        item.host,
        item.title,
        item.searchQuery,
        item.matchedTerms
      ]
    );
  }

  for (const item of report.browserRecoveredArtifacts || []) {
    await addCatalogFindings(
      "browser_recovery",
      item.recoveredUrl || item.recoveredFileName || item.sourceArtifact,
      item,
      [
        item.recoveredUrl,
        item.recoveredFileName,
        item.catalogMatches,
        item.matchedTerms
      ]
    );
  }

  for (const item of report.deletedUsnRecords || []) {
    await addCatalogFindings(
      "usn_delete",
      item.fileName || item.volume,
      item,
      [item.fileName]
    );
  }

  for (const item of report.recycleBin || []) {
    await addCatalogFindings(
      "recycle_bin",
      item.originalPath || item.fileName,
      item,
      [item.fileName, item.originalPath, item.recycledDataPath]
    );
  }

  for (const item of report.prefetchExecutions || []) {
    await addCatalogFindings(
      "prefetch_execution",
      item.resolvedExecutablePath ||
        item.nativeExecutablePath ||
        item.executableName,
      item,
      [
        item.executableName,
        item.resolvedExecutablePath,
        item.nativeExecutablePath,
        item.prefetchFile
      ]
    );
  }

  for (const item of report.bam || []) {
    await addCatalogFindings(
      "bam",
      item.path,
      item,
      [item.path]
    );
  }

  const liveBrowserText = JSON.stringify([
    ...(report.browserDownloads || []),
    ...(report.browserHistorySignals || [])
  ]).toLowerCase();

  for (const item of report.browserRecoveredArtifacts || []) {
    const recoveredUrl = String(item.recoveredUrl || "");
    const recoveredFileName = String(item.recoveredFileName || "");

    const alreadyLive =
      (recoveredUrl && liveBrowserText.includes(recoveredUrl.toLowerCase())) ||
      (recoveredFileName && liveBrowserText.includes(recoveredFileName.toLowerCase()));

    if (alreadyLive)
      continue;

    const catalogHit =
      Array.isArray(item.catalogMatches) &&
      item.catalogMatches.length > 0;

    const strongTerms =
      Array.isArray(item.matchedTerms) &&
      item.matchedTerms.length >= 2;

    let severity = "medium";
    let title = "Vestígio recuperado de histórico apagado";

    if (item.randomLikeName === true ||
        item.deceptiveDoubleExtension === true ||
        catalogHit) {
      severity = "critical";
      title = "Vestígio crítico recuperado de histórico apagado";
    } else if (strongTerms) {
      severity = "high";
    }

    await insertReviewFinding(
      analysisId,
      title,
      severity,
      "browser_recovery",
      recoveredUrl || recoveredFileName || item.sourceArtifact || "SQLite",
      {
        ...item,
        confidence: severity === "critical" ? "high" : "medium",
        note: "O dado não estava presente nas tabelas ativas do histórico, mas foi recuperado de páginas SQLite/WAL/journal ainda não sobrescritas. Isso é vestígio forense e pode sobreviver após a limpeza do histórico.",
      }
    );
  }

  const deletedRiskTerms = [
    "loader",
    "injector",
    "cheat",
    "hack",
    "script",
    "aimbot",
    "recoil",
    "spoofer",
    "bypass",
    "eac"
  ];

  for (const item of report.deletedUsnRecords || []) {
    if (String(item.reason || "") !== "FILE_DELETE")
      continue;

    if (ageDays(item.timestampUtc) > 30)
      continue;

    const name = String(item.fileName || "");
    const lower = name.toLowerCase();
    const catalogMatches = findRustCatalogMatches(name);
    const matchedRiskTerms = deletedRiskTerms.filter((term) =>
      lower.includes(term));

    const critical =
      item.randomLikeName === true ||
      item.deceptiveDoubleExtension === true ||
      catalogMatches.length > 0;

    if (critical) {
      await insertReviewFinding(
        analysisId,
        "Arquivo apagado recuperado pelo USN Journal",
        "critical",
        "usn_delete",
        name || item.volume || "arquivo apagado",
        {
          ...item,
          catalogMatches,
          matchedRiskTerms,
          confidence: "high",
          note: "O NTFS registrou a exclusão do arquivo no USN Journal. Essa evidência não depende de o arquivo ter sido executado.",
        }
      );

      continue;
    }

    if (matchedRiskTerms.length > 0) {
      await insertReviewFinding(
        analysisId,
        "Arquivo apagado com nome de alto interesse",
        "high",
        "usn_delete",
        name,
        {
          ...item,
          matchedRiskTerms,
          confidence: "medium",
          note: "O arquivo foi apagado e o nome contém termo frequentemente associado a loaders/scripts/cheats. Não é necessário haver Prefetch para esta ocorrência.",
        }
      );
    }
  }

  // PE / StringExplorer-style metadata checks.
  for (const item of report.peInspections || []) {
    const pathValue = item.path || item.name || "PE";

    if (item.randomLikeName === true && item.signed !== true) {
      await insertReviewFinding(
        analysisId,
        "Executável aleatório com indicadores PE",
        "critical",
        "pe_inspection",
        pathValue,
        {
          ...item,
          confidence: "high",
          note: "Executável com nome aleatório e sem assinatura confiável também apresentou metadados PE relevantes."
        }
      );
      continue;
    }

    if (item.packedLike === true && item.signed !== true) {
      await insertReviewFinding(
        analysisId,
        "Executável não assinado com packer/protector",
        (item.packerIndicators || []).length > 0 ? "high" : "medium",
        "pe_inspection",
        pathValue,
        {
          ...item,
          confidence: (item.packerIndicators || []).length > 0 ? "high" : "medium",
          note: "Packer/protector ou entropia alta detectada. Isso pode ocorrer em software legítimo, portanto requer revisão."
        }
      );
    }

    if (
      item.signed !== true &&
      (item.suspiciousApis || []).length >= 3 &&
      isSuspiciousUserPath(pathValue)
    ) {
      await insertReviewFinding(
        analysisId,
        "Executável não assinado com APIs de injeção/memória",
        "high",
        "pe_inspection",
        pathValue,
        {
          ...item,
          confidence: "medium",
          note: "O arquivo contém várias referências a APIs usadas para manipulação/injeção de processos. As APIs também podem existir em ferramentas legítimas."
        }
      );
    }
  }

  // Mark-of-the-Web / SavedFiles-style origin checks.
  for (const item of report.zoneIdentifiers || []) {
    await addCatalogFindings(
      "zone_identifier",
      item.path || item.fileName || item.hostUrl,
      item,
      [item.fileName, item.path, item.hostUrl, item.referrerUrl]
    );

    const name = item.fileName || item.path || "";
    const source = [
      item.hostUrl,
      item.referrerUrl
    ].filter(Boolean).join(" ").toLowerCase();

    const social =
      source.includes("discord.com/") ||
      source.includes("discordapp.com/") ||
      source.includes("cdn.discordapp.com/") ||
      source.includes("t.me/") ||
      source.includes("telegram.org/");

    if (social && isRiskyDownloadName(name)) {
      const randomExe =
        path.extname(name).toLowerCase() === ".exe" &&
        looksRandomExecutableName(name);

      await insertReviewFinding(
        analysisId,
        "Arquivo com origem Discord/Telegram preservada no Zone.Identifier",
        randomExe ? "critical" : "medium",
        "zone_identifier",
        item.path || name,
        {
          ...item,
          confidence: randomExe ? "high" : "medium",
          note: "A origem sobrevive no Mark-of-the-Web mesmo quando o histórico do navegador não está mais disponível."
        }
      );
    }
  }

  // Alternate Data Streams.
  for (const item of report.alternateDataStreams || []) {
    if (item.suspicious !== true)
      continue;

    await insertReviewFinding(
      analysisId,
      item.executableLike === true
        ? "Alternate Data Stream executável/suspeito"
        : "Alternate Data Stream suspeito",
      item.executableLike === true ? "high" : "medium",
      "alternate_stream",
      (item.path || "") + (item.streamName || ""),
      {
        ...item,
        confidence: "medium",
        note: "Foi encontrado um fluxo NTFS alternativo não padrão. A presença isolada não prova execução por ADS."
      }
    );
  }

  // Autoruns / persistence integrity.
  for (const item of report.autorunIntegrity || []) {
    if (item.suspicious !== true)
      continue;

    await insertReviewFinding(
      analysisId,
      "Autorun/tarefa suspeita em caminho gravável pelo usuário",
      item.fileExists === true && item.signed !== true ? "high" : "medium",
      "autorun_integrity",
      item.executablePath || item.command || item.name,
      {
        ...item,
        confidence: "medium",
        note: "Entrada de inicialização aponta para caminho do usuário/Temp ou executável não assinado."
      }
    );
  }

  // Full PowerShell history/event correlation.
  for (const item of report.powerShellArtifacts || []) {
    const command = String(item.command || "").toLowerCase();
    const strong =
      item.longEncodedPayload === true ||
      command.includes("add-mppreference") ||
      command.includes("set-mppreference") ||
      command.includes("writeprocessmemory") ||
      command.includes("createremotethread") ||
      command.includes("frombase64string") ||
      command.includes("-encodedcommand");

    await insertReviewFinding(
      analysisId,
      "PowerShell com padrão de alto interesse",
      strong ? "high" : "medium",
      "powershell_artifact",
      item.command || item.source || "PowerShell",
      {
        ...item,
        confidence: strong ? "high" : "medium",
        note: "Comando preservado em PSReadLine/Event Log contém padrões associados a download, execução codificada, exclusões do Defender ou manipulação de processos."
      }
    );
  }

  // Unsigned modules loaded into Rust/system processes.
  for (const item of report.processModuleIntegrity || []) {
    if (item.suspicious !== true)
      continue;

    const processName = String(item.processName || "").toLowerCase();
    const gameProcess =
      processName === "rust" ||
      processName === "rustclient";

    await insertReviewFinding(
      analysisId,
      gameProcess
        ? "DLL externa não assinada carregada no Rust"
        : "Módulo não assinado em processo de alto valor",
      gameProcess ? "high" : "medium",
      "module_integrity",
      item.modulePath || item.moduleName,
      {
        ...item,
        confidence: gameProcess ? "high" : "medium",
        note: "Módulo vindo do perfil do usuário/Temp foi carregado em processo relevante e não possui assinatura Authenticode confiável."
      }
    );
  }

  // Streamproof / display-affinity indicators.
  for (const item of report.protectedWindows || []) {
    if (item.excludedFromCapture !== true)
      continue;

    const appInfo = findCommonAppByFileName(
      item.processPath || ((item.processName || "") + ".exe")
    );

    const trustedCommon =
      appInfo &&
      item.signed === true &&
      signerMatchesCommonApp(appInfo, item.signerSubject);

    if (trustedCommon)
      continue;

    await insertReviewFinding(
      analysisId,
      "Janela excluída de captura de tela",
      item.signed === true ? "medium" : "high",
      "protected_window",
      item.processPath || item.processName || "window",
      {
        ...item,
        confidence: item.signed === true ? "medium" : "high",
        note: "O processo usa WDA_EXCLUDEFROMCAPTURE. Esse recurso possui usos legítimos, mas também é usado por aplicações streamproof."
      }
    );
  }

  // Crash / WER correlation.
  for (const item of report.crashArtifacts || []) {
    const value =
      item.appPath ||
      item.appName ||
      item.faultingModulePath ||
      "";

    const matches = findRustCatalogMatches(
      value,
      item.faultingModulePath,
      item.artifactPath
    );

    if (matches.length > 0) {
      await insertReviewFinding(
        analysisId,
        "Artefato de crash ligado ao catálogo Rust",
        "high",
        "crash_artifact",
        value || item.artifactPath,
        {
          ...item,
          catalogMatches: matches,
          confidence: "high",
          note: "Windows Error Reporting preservou referência a nome/caminho ligado ao catálogo defensivo."
        }
      );
    } else if (
      /\.exe$/i.test(value) &&
      looksRandomExecutableName(value)
    ) {
      await insertReviewFinding(
        analysisId,
        "Crash preservou executável com nome aleatório",
        "high",
        "crash_artifact",
        value,
        {
          ...item,
          confidence: "medium",
          note: "WER/minidump preservou referência a um executável com nome de alta aleatoriedade."
        }
      );
    }
  }

  // Network/DNS indicators. DNS cache is intentionally not presented as
  // proof of which process made the request.
  for (const item of report.networkIndicators || []) {
    if (String(item.source || "") === "DNS Cache") {
      const indicators = item.matchedIndicators || [];
      const authHit = indicators.some((value) =>
        ["keyauth.cc", "keyauth.win", "eauth.us.to"].includes(
          String(value || "").toLowerCase()
        )
      );

      const catalogHit = indicators.some((value) =>
        !["keyauth.cc", "keyauth.win", "eauth.us.to"].includes(
          String(value || "").toLowerCase()
        )
      );

      await insertReviewFinding(
        analysisId,
        catalogHit
          ? "Domínio do catálogo Rust encontrado no cache DNS"
          : "Domínio de autenticação de alto interesse no cache DNS",
        catalogHit ? "critical" : authHit ? "medium" : "info",
        "network_indicator",
        item.domain || "DNS",
        {
          ...item,
          confidence: catalogHit ? "high" : "low",
          note: "Cache DNS indica resolução do domínio, mas não atribui sozinho a consulta a um executável específico."
        }
      );
      continue;
    }

    if (
      item.processSigned !== true &&
      isSuspiciousUserPath(item.processPath)
    ) {
      await insertReviewFinding(
        analysisId,
        "Executável não assinado com conexão TCP ativa",
        "medium",
        "network_indicator",
        item.processPath || item.processName || item.remoteAddress,
        {
          ...item,
          confidence: "low",
          note: "Conexão de rede atual de processo não assinado em caminho do usuário/Temp. Requer correlação com outras evidências."
        }
      );
    }
  }

  // USN Journal activity and anti-forensic changes.
  for (const item of report.usnActivity || []) {
    if (item.deleted !== true)
      continue;

    const name = String(item.fileName || "");
    const lower = name.toLowerCase();

    if (
      item.underPrefetchDirectory === true &&
      lower.endsWith(".pf")
    ) {
      await insertReviewFinding(
        analysisId,
        "Prefetch apagado",
        "high",
        "usn_activity",
        name,
        {
          ...item,
          confidence: "high",
          note: "O USN Journal registrou exclusão de arquivo .PF dentro do diretório Prefetch."
        }
      );
      continue;
    }

    if (
      item.browserDatabase === true
    ) {
      await insertReviewFinding(
        analysisId,
        "Banco de histórico do navegador apagado/alterado",
        "medium",
        "usn_activity",
        name,
        {
          ...item,
          confidence: "medium",
          note: "O USN Journal registrou exclusão de banco do navegador como History/places.sqlite."
        }
      );
      continue;
    }

    if (
      item.windowsForensicArtifact === true &&
      (
        lower === "srudb.dat" ||
        lower.endsWith(".evtx") ||
        lower.endsWith(".hve")
      )
    ) {
      await insertReviewFinding(
        analysisId,
        "Artefato forense do Windows apagado",
        "high",
        "usn_activity",
        name,
        {
          ...item,
          confidence: "high",
          note: "O USN Journal registrou exclusão de artefato usado em análise forense do Windows."
        }
      );
    }
  }

  // System integrity expansion.
  for (const item of report.systemIntegrityExpansion || []) {
    const severity =
      String(item.severityHint || "info").toLowerCase();

    if (!["medium", "high", "critical"].includes(severity))
      continue;

    await insertReviewFinding(
      analysisId,
      "Integridade do sistema: " + (item.name || item.kind || "sinal"),
      severity,
      "system_integrity_expansion",
      item.detail || item.name || item.kind,
      {
        ...item,
        confidence: severity === "high" ? "high" : "medium",
        note: "Configuração/estado do Windows relevante para a confiabilidade do scan."
      }
    );
  }

  // Executed and later modified (self-destruct / replacement signal).
  for (const item of report.files || []) {
    if (!item.prefetchEvidenceUtc || !item.lastWriteUtc)
      continue;

    const executed = new Date(item.prefetchEvidenceUtc).getTime();
    const modified = new Date(item.lastWriteUtc).getTime();

    if (!Number.isFinite(executed) || !Number.isFinite(modified))
      continue;

    if (modified <= executed + 120000)
      continue;

    if (
      ageDays(item.lastWriteUtc) > 30 ||
      isTrustedInstalledPath(item.path)
    ) {
      continue;
    }

    await insertReviewFinding(
      analysisId,
      "Executado e modificado depois",
      "medium",
      "file",
      item.path || item.name,
      {
        ...item,
        confidence: "medium",
        note: "O arquivo possui evidência de execução anterior e data de modificação posterior, compatível com atualização legítima ou self-destruct/replacement."
      }
    );
  }

  // Bypass routes: network paths and common RAR temporary execution paths.
  const executionSources = [
    ...(report.prefetchExecutions || []).map((item) => ({
      type: "prefetch_execution",
      value:
        item.resolvedExecutablePath ||
        item.nativeExecutablePath ||
        item.executableName,
      evidence: item
    })),
    ...(report.bam || []).map((item) => ({
      type: "bam",
      value: item.path,
      evidence: item
    })),
    ...(report.processCreationEvents || []).map((item) => ({
      type: "process_history",
      value: item.processPath,
      evidence: item
    }))
  ];

  for (const execution of executionSources) {
    const value = String(execution.value || "");
    const normalized = normalizePath(value);

    if (value.startsWith("\\")) {
      await insertReviewFinding(
        analysisId,
        "Execução a partir de recurso de rede",
        "high",
        execution.type,
        value,
        {
          ...execution.evidence,
          confidence: "high",
          note: "A execução aponta para caminho UNC/recurso de rede."
        }
      );
    }

    if (
      normalized.includes("\\rar$") ||
      normalized.includes("\\winrar\\") &&
      normalized.includes("\\temp\\")
    ) {
      await insertReviewFinding(
        analysisId,
        "Execução a partir de extração temporária RAR",
        "high",
        execution.type,
        value,
        {
          ...execution.evidence,
          confidence: "medium",
          note: "Caminho é compatível com execução temporária proveniente de arquivo RAR/WinRAR."
        }
      );
    }
  }

  // Known applications are trusted only when their signature and/or
  // download source matches the official vendor catalog. A familiar filename
  // by itself is never enough to suppress a finding.
  for (const item of report.files || []) {
    const ext = String(item.extension || path.extname(item.name || "")).toLowerCase();
    if (ext !== ".exe" && ext !== ".msi")
      continue;

    const appInfo = findCommonAppByFileName(item.name || item.path);
    const signerOk = appInfo
      ? signerMatchesCommonApp(appInfo, item.signerSubject)
      : false;

    const officialDownloadOk = appInfo
      ? (report.browserDownloads || []).some((download) => {
          const downloadName = path.basename(
            String(download.fileName || download.targetPath || "")
          ).toLowerCase();

          const itemName = path.basename(
            String(item.name || item.path || "")
          ).toLowerCase();

          return (
            downloadName &&
            itemName &&
            downloadName === itemName &&
            downloadMatchesOfficialSource(appInfo, download)
          );
        })
      : false;

    if (appInfo) {
      const expectedSigners = appInfo.signerContains || [];
      const explicitSignerMismatch =
        item.signed === true &&
        expectedSigners.length > 0 &&
        signerOk !== true;

      if (signerOk)
        continue;

      if (explicitSignerMismatch) {
        await insertReviewFinding(
          analysisId,
          "Aplicativo conhecido assinado por entidade inesperada",
          "high",
          "unknown_app",
          item.path || item.name || appInfo.name,
          {
            ...item,
            expectedApplication: appInfo.name,
            expectedSigners,
            signatureMatched: false,
            officialDownloadMatched: officialDownloadOk,
            confidence: "high",
            note: "A assinatura Authenticode é válida, porém o certificado não corresponde ao fabricante esperado para este nome de aplicativo.",
          }
        );

        continue;
      }

      if (officialDownloadOk)
        continue;

      if (
        item.signed !== true ||
        !isTrustedInstalledPathForCommonApp(item.path)
      ) {
        await insertReviewFinding(
          analysisId,
          "Aplicativo conhecido com assinatura/origem não confirmada",
          "high",
          "unknown_app",
          item.path || item.name || appInfo.name,
          {
            ...item,
            expectedApplication: appInfo.name,
            expectedSigners,
            signatureMatched: signerOk,
            officialDownloadMatched: officialDownloadOk,
            confidence: "high",
            note: "O nome imita um aplicativo comum, mas nem a assinatura digital esperada nem uma origem oficial de download foram confirmadas.",
          }
        );
      }

      continue;
    }

    if (
      item.signed !== true &&
      isSuspiciousUserPath(item.path) &&
      ageDays(item.lastWriteUtc) <= 120
    ) {
      await insertReviewFinding(
        analysisId,
        "Aplicativo desconhecido / não assinado",
        looksRandomExecutableName(item.name || item.path) ? "critical" : "medium",
        "unknown_app",
        item.path || item.name || "executável",
        {
          ...item,
          confidence: looksRandomExecutableName(item.name || item.path) ? "high" : "medium",
          note: "Executável recente em Downloads/Desktop/Temp que não corresponde ao catálogo de aplicativos comuns e não possui assinatura digital confirmada.",
        }
      );
    }
  }

  for (const download of report.browserDownloads || []) {
    const appInfo = findCommonAppByFileName(
      download.fileName || download.targetPath
    );

    if (!appInfo)
      continue;

    const hasSource = [
      download.sourceUrl,
      download.finalUrl,
      download.referrerUrl,
      download.siteUrl,
      download.pageUrl,
      ...(Array.isArray(download.urlChain) ? download.urlChain : [])
    ].some(Boolean);

    if (!hasSource)
      continue;

    if (downloadMatchesOfficialSource(appInfo, download))
      continue;

    await insertReviewFinding(
      analysisId,
      "Aplicativo conhecido baixado de fonte não oficial",
      "high",
      "browser_download",
      download.targetPath || download.fileName || appInfo.name,
      {
        ...download,
        expectedApplication: appInfo.name,
        officialSourcePatterns: appInfo.officialUrlIncludes || [],
        confidence: "high",
        note: "O arquivo usa o nome de um aplicativo comum, porém o histórico de download não aponta para uma fonte oficial cadastrada.",
      }
    );
  }

  const archiveRiskTerms = [
    "rust",
    "cheat",
    "hack",
    "script",
    "loader",
    "injector",
    "aimbot",
    "recoil",
    "macro",
    "spoofer",
    "bypass",
    "eac"
  ];

  for (const item of report.files || []) {
    const ext = String(item.extension || path.extname(item.path || item.name || ""))
      .toLowerCase();

    if ([".zip", ".rar", ".7z"].includes(ext)) {
      const archiveText = [
        item.name,
        item.path,
        ...(Array.isArray(item.archiveEntries) ? item.archiveEntries : [])
      ].join(" ").toLowerCase();

      const matchedTerms = archiveRiskTerms.filter((term) =>
        archiveText.includes(term));

      const randomExecutables = ext === ".zip"
        ? (item.archiveEntries || [])
            .filter((entry) =>
              /\.exe$/i.test(String(entry || "")) &&
              looksRandomExecutableName(entry))
            .slice(0, 20)
        : [];

      if (
        matchedTerms.length >= 2 ||
        randomExecutables.length > 0
      ) {
        await insertReviewFinding(
          analysisId,
          ext === ".zip"
            ? "ZIP suspeito em pasta de usuário"
            : "Arquivo compactado suspeito em pasta de usuário",
          randomExecutables.length > 0 ? "high" : "medium",
          "archive",
          item.path || item.name || "arquivo compactado",
          {
            ...item,
            matchedTerms,
            randomExecutables,
            confidence: randomExecutables.length > 0 ? "high" : "medium",
            note: ext === ".zip"
              ? "ZIP recente contém combinação de termos associados a cheat/script ou executáveis com nome aleatório. O conteúdo é apenas listado; nada é extraído ou executado."
              : "RAR/7Z recente possui combinação de termos associados a cheat/script no nome/caminho. O agente não extrai nem executa o arquivo.",
          }
        );
      }
    }

    const isRandomExe =
      ext === ".exe" &&
      (item.randomLikeName === true ||
       looksRandomExecutableName(item.name || item.path)) &&
      item.signed !== true &&
      isSuspiciousUserPath(item.path);

    if (isRandomExe) {
      await insertReviewFinding(
        analysisId,
        "Executável com nome aleatório em pasta de risco",
        "critical",
        "file",
        item.path || item.name || "EXE",
        {
          ...item,
          confidence: "high",
          note: "Nome com padrão de alta aleatoriedade, arquivo não assinado e localizado em Downloads/Desktop/Temp. Tratado como crítico para revisão manual.",
        }
      );
    }
  }

  for (const download of report.browserDownloads || []) {
    const name = download.fileName || download.targetPath || "";
    const ext = path.extname(name).toLowerCase();
    const originKind = downloadOriginKind(download);
    const doubleExtension = isDeceptiveDoubleExtensionExecutable(name);
    const randomExecutable =
      ext === ".exe" && looksRandomExecutableName(name);
    const danger = chromiumDangerInfo(download.dangerType);

    if (originKind && isRiskyDownloadName(name)) {
      const severity =
        randomExecutable ? "critical" :
        doubleExtension ? "high" :
        "medium";

      await insertReviewFinding(
        analysisId,
        "Arquivo baixado do " + originKind,
        severity,
        "browser_download",
        download.targetPath || download.fileName || "download",
        {
          ...download,
          originKind,
          doubleExtension,
          randomExecutable,
          confidence: severity === "critical" ? "high" : "medium",
          note: doubleExtension
            ? "Download originado do " + originKind + " usa dupla extensão que termina em .exe. Deve ser revisado."
            : "Download executável/compactado originado do " + originKind + ". Classificado no mínimo como ocorrência média para revisão.",
        }
      );
    }

    if (danger.suspicious) {
      const severity =
        randomExecutable ? "critical" :
        danger.severity;

      await insertReviewFinding(
        analysisId,
        "Download sinalizado pelo navegador",
        severity,
        "browser_download",
        download.targetPath || download.fileName || "download",
        {
          ...download,
          browserDanger: danger,
          confidence: severity === "critical" || severity === "high" ? "high" : "medium",
          note: "O histórico Chromium marcou este download com indicador de risco: " + danger.label + ".",
        }
      );
    }

    if (randomExecutable) {
      await insertReviewFinding(
        analysisId,
        "Executável baixado com nome aleatório",
        "critical",
        "browser_download",
        download.targetPath || download.fileName || "download",
        {
          ...download,
          originKind,
          browserDanger: danger,
          confidence: "high",
          note: "Nome do executável apresenta padrão de alta aleatoriedade. Tratado como crítico para revisão.",
        }
      );
    }

    if (doubleExtension) {
      await insertReviewFinding(
        analysisId,
        "Executável com dupla extensão disfarçada",
        originKind ? "high" : "medium",
        "browser_download",
        download.targetPath || download.fileName || "download",
        {
          ...download,
          originKind,
          confidence: originKind ? "high" : "medium",
          note: "O arquivo termina em .exe, mas usa extensão anterior de arquivo/documento (ex.: .zip.exe).",
        }
      );
    }

    if (download.fileMissing !== true)
      continue;

    if (ext === ".exe" && looksRandomExecutableName(name)) {
      await insertReviewFinding(
        analysisId,
        "Executável baixado com nome aleatório e depois não localizado",
        "critical",
        "browser_download",
        download.targetPath || download.fileName || "download",
        {
          ...download,
          confidence: "high",
          note: "O histórico do navegador preservou um EXE com nome aleatório que não está mais no destino original. Tratado como crítico para revisão.",
        }
      );
    }

    if ([".zip", ".rar", ".7z"].includes(ext)) {
      const archiveText = [
        download.fileName,
        download.targetPath,
        download.sourceUrl,
        download.finalUrl,
        download.pageUrl,
      ].join(" ").toLowerCase();

      const archiveTerms = archiveRiskTerms.filter((term) =>
        archiveText.includes(term));

      if (archiveTerms.length >= 2) {
        await insertReviewFinding(
          analysisId,
          ext === ".zip"
            ? "ZIP suspeito baixado e depois não localizado"
            : "Arquivo compactado suspeito baixado e depois não localizado",
          "high",
          "browser_download",
          download.targetPath || download.fileName || "arquivo compactado",
          {
            ...download,
            matchedTerms: archiveTerms,
            confidence: "high",
            note: "Arquivo compactado apagado/movido possui combinação forte de termos ligados a cheat/script no nome, caminho ou URL de origem.",
          }
        );
      }
    }
  }

  for (const execution of report.prefetchExecutions || []) {
    const executionPath =
      execution.resolvedExecutablePath ||
      execution.nativeExecutablePath ||
      execution.executableName ||
      "";

    if (
      looksRandomExecutableName(
        execution.executableName || executionPath
      ) &&
      execution.executablePresent !== true &&
      !isTrustedInstalledPath(executionPath) &&
      (
        isSuspiciousUserPath(executionPath) ||
        isVolumeRootExecutable(execution.nativeExecutablePath)
      )
    ) {
      await insertReviewFinding(
        analysisId,
        "EXE com nome aleatório executado e depois não localizado",
        "critical",
        "prefetch_execution",
        executionPath,
        {
          ...execution,
          confidence: "high",
          note: "O Prefetch registra execução de um EXE com nome de alta aleatoriedade; o arquivo não está mais presente em pasta de usuário/volume removido.",
        }
      );
    }
  }

  // HIGH-SIGNAL EXECUTION: confirmed removable drive, or a recent executable
  // from a detached non-system volume at the root/user-temporary location.
  // A generic unresolved Prefetch volume alone is NOT a finding.
  for (const execution of report.prefetchExecutions || []) {
    const lastAge = ageDays(execution.lastRunUtc);
    if (lastAge > 30) continue;

    const executionPath =
      execution.resolvedExecutablePath ||
      execution.nativeExecutablePath ||
      "";

    if (isTrustedInstalledPath(executionPath))
      continue;

    const confirmedRemovable =
      execution.currentRemovable === true;

    const strongDetachedEvidence =
      execution.volumeNotMounted === true &&
      execution.nonSystemVolume === true &&
      execution.executablePresent !== true &&
      (
        isVolumeRootExecutable(execution.nativeExecutablePath) ||
        isSuspiciousUserPath(executionPath)
      );

    if (!confirmedRemovable && !strongDetachedEvidence)
      continue;

    await insertReviewFinding(
      analysisId,
      confirmedRemovable
        ? "Execução recente em mídia removível"
        : "Execução recente em volume removido/não montado",
      confirmedRemovable || lastAge <= 7 ? "high" : "medium",
      "prefetch_execution",
      execution.executableName ||
        execution.nativeExecutablePath ||
        execution.prefetchFile,
      {
        ...execution,
        confidence: confirmedRemovable ? "high" : "medium",
        note: confirmedRemovable
          ? "O Prefetch registrou execução em uma unidade atualmente identificada como removível."
          : "O Prefetch registrou um executável recente em volume não montado, sem arquivo presente, em caminho compatível com execução portátil. Volume não resolvido sozinho não gera alerta.",
      }
    );
  }

  // BAM is useful as corroboration, but stale system/application entries are common.
  for (const item of report.bam || []) {
    const lastAge = ageDays(item.lastExecutionUtc);
    const p = item.path || "";

    if (lastAge > 7 ||
        item.fileExists !== false ||
        isTrustedInstalledPath(p) ||
        (!isSuspiciousUserPath(p) && !isVolumeRootExecutable(p))) {
      continue;
    }

    await insertReviewFinding(
      analysisId,
      "BAM: execução recente de arquivo não localizado",
      "medium",
      "bam",
      p || "BAM",
      {
        ...item,
        confidence: "medium",
        note: "BAM registrou execução recente em caminho temporário/usuário ou raiz de volume, e o arquivo não está mais presente.",
      }
    );
  }

  // Event 4688 is strong execution evidence when audit logging was enabled.
  for (const item of report.processCreationEvents || []) {
    const lastAge = ageDays(item.timeCreatedUtc);
    if (lastAge > 14) continue;

    const p = item.processPath || "";

    if (isTrustedInstalledPath(p))
      continue;

    const external =
      item.driveType === "Removable" ||
      item.driveType === "Network";

    const missingSuspicious =
      item.processPresent === false &&
      (
        isSuspiciousUserPath(p) ||
        isVolumeRootExecutable(p)
      );

    if (!external && !missingSuspicious)
      continue;

    await insertReviewFinding(
      analysisId,
      external
        ? (item.driveType === "Network"
            ? "Execução registrada a partir de recurso de rede"
            : "Execução registrada a partir de mídia removível")
        : "Processo executado recentemente e arquivo não localizado",
      external ? "high" : "medium",
      "process_history",
      p || item.processName || "processo",
      {
        ...item,
        confidence: external ? "high" : "medium",
        note: "Execução confirmada pelo Event Log 4688; caminhos normais do Windows e Program Files são ignorados.",
      }
    );
  }

  // Defense in depth: older agents may have sent legitimate PE-based
  // formats such as .node/.winmd. Only deceptive user-facing extensions count.
  const deceptiveExtensions = new Set([
    ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv", ".mov",
    ".html", ".htm", ".css", ".md"
  ]);

  for (const item of report.extensionMismatches || []) {
    const candidatePath = String(item.path || item.name || "");
    const extension = path.extname(candidatePath).toLowerCase();

    if (!deceptiveExtensions.has(extension))
      continue;

    await insertReviewFinding(
      analysisId,
      "Executável disfarçado com extensão não executável",
      "medium",
      "extension_mismatch",
      candidatePath || "arquivo",
      {
        ...item,
        confidence: "medium",
        note: "O arquivo possui cabeçalho PE/MZ, mas usa uma extensão normalmente associada a documento, mídia, arquivo compactado ou texto.",
      }
    );
  }

  // Browser download history is inventory by default. It becomes an
  // automatic finding only when a missing executable can be correlated with
  // actual execution evidence collected from Windows.
  const executionEvidence = [];

  for (const execution of report.prefetchExecutions || []) {
    executionEvidence.push({
      source: "Prefetch",
      name: String(execution.executableName || "").toLowerCase(),
      path: normalizePath(
        execution.resolvedExecutablePath ||
        execution.nativeExecutablePath ||
        ""),
      time: execution.lastRunUtc || null,
      evidence: execution,
    });
  }

  for (const item of report.bam || []) {
    executionEvidence.push({
      source: "BAM",
      name: fileName(item.path || "").toLowerCase(),
      path: normalizePath(item.path || ""),
      time: item.lastExecutionUtc || null,
      evidence: item,
    });
  }

  for (const item of report.processCreationEvents || []) {
    executionEvidence.push({
      source: "Event 4688",
      name: String(item.processName || "").toLowerCase(),
      path: normalizePath(item.processPath || ""),
      time: item.timeCreatedUtc || null,
      evidence: item,
    });
  }

  for (const download of report.browserDownloads || []) {
    if (download.fileMissing !== true)
      continue;

    const downloadedName = String(download.fileName || "").toLowerCase();
    if (!downloadedName)
      continue;

    const ext = path.extname(downloadedName).toLowerCase();
    const executableLike = new Set([
      ".exe", ".com", ".scr", ".dll", ".bat", ".cmd", ".ps1", ".msi"
    ]).has(ext);

    if (!executableLike)
      continue;

    const downloadTime = download.startTimeUtc
      ? new Date(download.startTimeUtc).getTime()
      : 0;

    const matches = executionEvidence
      .filter((candidate) => {
        if (!candidate.name ||
            candidate.name !== downloadedName)
          return false;

        if (!candidate.time || !downloadTime)
          return true;

        const executionTime = new Date(candidate.time).getTime();
        if (!Number.isFinite(executionTime))
          return true;

        // Allow small timestamp drift, but execution should normally occur
        // after the download and within 30 days.
        return executionTime >= downloadTime - 5 * 60 * 1000 &&
          executionTime <= downloadTime + 30 * 86400000;
      })
      .slice(0, 5);

    if (!matches.length)
      continue;

    await insertReviewFinding(
      analysisId,
      "Arquivo baixado, executado e depois não localizado",
      "high",
      "browser_download",
      download.targetPath || download.fileName || "download",
      {
        ...download,
        confidence: "high",
        executionEvidence: matches,
        note: "O histórico do navegador preserva a origem do download; o arquivo não está mais no caminho de destino e há evidência separada de execução pelo Windows.",
      }
    );
  }

  // Recycle Bin is inventory by default. Only escalate when the same
  // executable also has independent execution evidence.
  for (const deleted of report.recycleBin || []) {
    const deletedName = String(deleted.fileName || "").toLowerCase();
    if (!deletedName)
      continue;

    const ext = path.extname(deletedName).toLowerCase();
    const executableLike = new Set([
      ".exe", ".com", ".scr", ".dll", ".bat", ".cmd", ".ps1", ".msi"
    ]).has(ext);

    if (!executableLike)
      continue;

    const deletionTime = deleted.deletedAtUtc
      ? new Date(deleted.deletedAtUtc).getTime()
      : 0;

    const matches = executionEvidence
      .filter((candidate) => {
        if (!candidate.name || candidate.name !== deletedName)
          return false;

        if (!candidate.time || !deletionTime)
          return true;

        const executionTime = new Date(candidate.time).getTime();
        if (!Number.isFinite(executionTime))
          return true;

        return executionTime <= deletionTime + 5 * 60 * 1000 &&
          executionTime >= deletionTime - 30 * 86400000;
      })
      .slice(0, 5);

    if (!matches.length)
      continue;

    await insertReviewFinding(
      analysisId,
      "Executável executado e depois enviado para a Lixeira",
      "high",
      "recycle_bin",
      deleted.originalPath || deleted.fileName || "Lixeira",
      {
        ...deleted,
        confidence: "high",
        executionEvidence: matches,
        note: "A Lixeira preserva o caminho original e horário de exclusão; o mesmo nome possui evidência separada de execução.",
      }
    );
  }

  // The agent only sends browser-history rows that matched the
  // anti-cheat vocabulary. Keep low-score rows as context and create
  // automatic findings only for medium/high confidence matches.
  for (const item of report.browserHistorySignals || []) {
    const risk = String(item.riskLevel || "").toLowerCase();
    if (!["medium", "high"].includes(risk))
      continue;

    const isSearch = Boolean(String(item.searchQuery || "").trim());

    await insertReviewFinding(
      analysisId,
      isSearch
        ? "Pesquisa no navegador relacionada a cheat/script/hack"
        : "Site relacionado a cheat/script/hack",
      risk === "high" ? "high" : "medium",
      "browser_history",
      item.searchQuery || item.url || item.host || "Histórico do navegador",
      {
        ...item,
        confidence: risk,
        note: isSearch
          ? "A consulta foi preservada no histórico do navegador e bateu em termos relacionados a cheat/hack/script com contexto do jogo."
          : "A URL/título preservado no histórico bateu em termos relacionados a cheat/hack/script. Revise o domínio e o contexto antes de qualquer decisão.",
      }
    );
  }

  // Defender history is useful evidence, but still requires human review.
  for (const item of report.defenderDetections || []) {
    if (!item.threatName && !item.path) continue;

    await insertReviewFinding(
      analysisId,
      "Histórico de detecção do Microsoft Defender",
      "medium",
      "defender_detection",
      item.threatName || item.path || "Defender",
      {
        ...item,
        confidence: "medium",
        note: "Registro do Microsoft Defender. Confirme nome, caminho e horário; não é ban automático.",
      }
    );
  }

  const knownOverlayTokens = [
    "discord",
    "steam",
    "gameoverlayrenderer",
    "nvidia",
    "nvspcap",
    "amd",
    "radeon",
    "obs",
    "overwolf",
    "medal",
    "steelseries",
    "logitech",
    "razer",
    "microsoft"
  ];

  // Loaded modules become findings only when they are external, unsigned and
  // not a known overlay/vendor module.
  for (const item of report.rustModules || []) {
    const haystack = [
      item.path,
      item.moduleName,
      item.companyName,
      item.signerSubject
    ].join(" ").toLowerCase();

    const knownOverlay =
      knownOverlayTokens.some((token) => haystack.includes(token));

    const suspiciousExternal =
      !knownOverlay &&
      item.signed === false &&
      item.underGameDirectory === false &&
      item.underWindows === false &&
      (
        item.underTemp === true ||
        (
          item.underUserProfile === true &&
          !item.underProgramFiles &&
          !item.companyName
        )
      );

    if (!suspiciousExternal)
      continue;

    await insertReviewFinding(
      analysisId,
      "Módulo externo não assinado carregado no Rust",
      item.underTemp ? "high" : "medium",
      "rust_module",
      item.path || item.moduleName || "DLL",
      {
        ...item,
        confidence: item.underTemp ? "high" : "medium",
        note: "Módulos conhecidos de Steam/Discord/GPU/overlays são filtrados. Este módulo é externo, não assinado e veio de local de usuário/temporário.",
      }
    );
  }

  // Boot integrity changes are kept because they materially alter Windows
  // integrity guarantees, but they are not classified as cheat by themselves.
  for (const item of report.bootIntegrity || []) {
    const raw = String(item.raw || "").toLowerCase();
    const enabled =
      /\b(yes|sim|on|true|1)\b/.test(raw) &&
      !/\b(no|não|off|false|0)\b/.test(raw);

    if (!enabled) continue;

    await insertReviewFinding(
      analysisId,
      "Configuração de integridade de boot alterada",
      "medium",
      "boot_integrity",
      item.raw || item.setting || "BCD",
      {
        ...item,
        confidence: "context",
        note: "Test mode, debug ou nointegritychecks alteram garantias do Windows. É contexto técnico, não prova isolada de cheat.",
      }
    );
  }

  // Deliberately NOT added to 'findings' automatically:
  // - generic missing Amcache/ShimCache entries
  // - unresolved Prefetch volumes by themselves
  // - virtual disks
  // - Activity History policy
  // - USN Journal availability
  // - volumes without drive letters
  // - generic system time changes
  // These stay in the report as technical context without inflating detections.
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

  let relatedAnalyses = [];

  if (analysis.machine_fingerprint) {
    const relatedResult = await pool.query(
      `SELECT
         id,
         label,
         status,
         created_at,
         started_at,
         finished_at,
         machine_name,
         agent_version
       FROM analyses
       WHERE machine_fingerprint = $1
         AND id <> $2
       ORDER BY id DESC
       LIMIT 20`,
      [analysis.machine_fingerprint, id]
    );

    relatedAnalyses = relatedResult.rows;
  }

  res.json({
    analysis,
    report: reportResult.rows[0] || null,
    findings: findingsResult.rows,
    relatedAnalyses,
  });
});

app.post("/api/admin/analyses/:id/rebuild", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "invalid_id" });
  }

  const analysisResult = await pool.query(
    "SELECT id FROM analyses WHERE id=$1 LIMIT 1",
    [id]
  );

  if (!analysisResult.rows[0]) {
    return res.status(404).json({ error: "analysis_not_found" });
  }

  const reportResult = await pool.query(
    "SELECT payload FROM scan_reports WHERE analysis_id=$1 ORDER BY id DESC LIMIT 1",
    [id]
  );

  const report = reportResult.rows[0]?.payload;
  if (!report) {
    return res.status(404).json({
      error: "report_not_found",
      message: "Esta análise ainda não possui relatório."
    });
  }

  await rebuildFindings(id, report);

  const countResult = await pool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE severity IN ('high','critical'))::int AS high
     FROM scan_findings
     WHERE analysis_id=$1`,
    [id]
  );

  res.json({
    ok: true,
    findings: Number(countResult.rows[0]?.total || 0),
    highFindings: Number(countResult.rows[0]?.high || 0)
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
    "amcache_contains",
    "shimcache_contains",
    "setupapi_contains",
    "powershell_contains",
    "signer_contains",
    "prefetch_integrity",
    "volume_keyword",
    "log_clear_signal",
    "execution_name",
    "usb_event_keyword",
    "process_history_contains",
    "recent_link_contains",
    "download_url_contains",
    "download_name_contains",
    "browser_history_contains",
    "browser_recovery_contains",
    "deleted_name_contains",
    "recycle_name_contains",
    "rust_module_contains",
    "defender_history_contains",
    "defender_exclusion_contains",
    "pe_indicator_contains",
    "zone_url_contains",
    "ads_contains",
    "autorun_contains",
    "powershell_artifact_contains",
    "network_indicator_contains",
    "usn_activity_contains",
    "system_integrity_contains",
    "module_integrity_contains",
    "crash_contains",
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
    downloadUrl: "/api/public/analyses/" + token + "/download",
    packageUrl: "/api/public/analyses/" + token + "/download",
  });
});

app.get("/api/public/analyses/:token/download", async (req, res) => {
  const token = String(req.params.token || "");
  if (!validToken(token)) return res.status(404).send("Análise não encontrada.");

  const analysis = await getAnalysisByToken(token);
  if (!ensureAnalysisUsable(analysis, res)) return;

  if (!fs.existsSync(agentBinaryPath)) {
    return res.status(503).send(
      "O executável do Vorken Agent ainda não foi publicado no servidor."
    );
  }

  const binary = fs.readFileSync(agentBinaryPath);
  const sha256 = crypto
    .createHash("sha256")
    .update(binary)
    .digest("hex");

  const fileName =
    "Vorken-" + analysis.id + "--" + token + ".exe";

  res.setHeader(
    "Content-Type",
    "application/vnd.microsoft.portable-executable"
  );
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="' + fileName + '"'
  );
  res.setHeader("Content-Length", String(binary.length));
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Vorken-SHA256", sha256);
  res.end(binary);
});

app.get("/api/public/analyses/:token/package", (req, res) => {
  const token = String(req.params.token || "");
  if (!validToken(token)) return res.status(404).send("Análise não encontrada.");
  res.redirect(302, "/api/public/analyses/" + token + "/download");
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
    threatCatalog: rustThreatCatalog,
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
         agent_version=COALESCE($4, agent_version),
         machine_fingerprint=COALESCE($5, machine_fingerprint)
     WHERE id=$1`,
    [
      analysis.id,
      cleanText(req.body?.machineName, 180) || null,
      cleanText(req.body?.osVersion, 250) || null,
      cleanText(req.body?.agentVersion, 80) || null,
      cleanText(req.body?.machineFingerprint, 128) || null,
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
         agent_version=COALESCE($4, agent_version),
         machine_fingerprint=COALESCE($5, machine_fingerprint)
     WHERE id=$1`,
    [
      analysis.id,
      cleanText(report.machine?.machineName, 180) || null,
      cleanText(report.machine?.osVersion, 250) || null,
      cleanText(report.agentVersion, 80) || null,
      cleanText(report.machine?.fingerprint, 128) || null,
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
