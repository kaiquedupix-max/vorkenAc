import {buildProcessSessions} from './processSessions.js';
const array = value => Array.isArray(value) ? value : [];
const pathOf = item => String(item.path || item.processPath || "").replaceAll("/", "\\");
const nameOf = item => String(item.name || item.processName || pathOf(item).split("\\").pop() || "");
const normal = value => String(value || "").replaceAll("/", "\\").toLowerCase();
const systemNames = new Set(["svchost.exe", "services.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "dwm.exe", "sihost.exe", "fontdrvhost.exe", "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "ctfmon.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "audiodg.exe", "dllhost.exe", "conhost.exe", "explorer.exe", "backgroundtaskhost.exe", "tiworker.exe", "trustedinstaller.exe"]);
const appNames = new Set(["chrome.exe", "msedge.exe", "firefox.exe", "steam.exe", "steamwebhelper.exe", "discord.exe", "spotify.exe", "onedrive.exe", "teams.exe"]);
const scriptHosts = new Set(["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"]);

export function excludedGameActivity(item) {
  const name = nameOf(item).replace(/\.exe$/i, "");
  return /^(?:rust|rustclient|rustdedicated)$/i.test(name) || /^easyanticheat/i.test(name) ||
    /(?:^|\\)(?:steamapps|252490|facepunch studios|rust|rustclient|rustdedicated|rustclient_data|rustdedicated_data|rust_data|easyanticheat[^\\]*)(?:\\|$)/i.test(pathOf(item));
}

export function activityRelevance(item, knownPaths = new Set()) {
  const path = normal(pathOf(item)), rawName = nameOf(item).toLowerCase();
  const name = rawName.endsWith('.exe') ? rawName : rawName + '.exe';
  const signer = String(item.signerSubject || item.processSigner || "");
  const reasons = [];
  if (knownPaths.has(path)) reasons.push("Correlacionado a um achado do relatório");
  if (/(?:^|\\)(?:temp|downloads|desktop|public|recycle\.bin|\$recycle\.bin)(?:\\|$)/i.test(path)) reasons.push("Executável em pasta de interesse");
  if (!reasons.length && item.signed === true && /Microsoft/i.test(signer) &&
      /^[a-z]:\\windows\\(?:system32|syswow64)\\/i.test(path) &&
      (systemNames.has(name) || scriptHosts.has(name))) return [];
  if (scriptHosts.has(name)) reasons.push("Interpretador ou utilitário de execução");
  if (!path) reasons.push("Caminho indisponível; somente metadados");
  if (reasons.length) return reasons;
  const signed = item.signed === true;
  const windowsPath = /^[a-z]:\\windows\\(?:system32|syswow64|winsxs|systemapps|servicing)\\/i.test(path) || /^[a-z]:\\windows\\explorer\.exe$/i.test(path);
  if (signed && /Microsoft/i.test(signer) && windowsPath && systemNames.has(name)) return [];
  const installedPath = /^[a-z]:\\program files(?: \(x86\))?\\/i.test(path) || /\\appdata\\local\\(?:discord|spotify|microsoft)\\/i.test(path);
  if (signed && installedPath && appNames.has(name)) return ["Aplicativo em execução / registrado no histórico"];
  return [signed ? "Aplicativo fora da lista de componentes comuns" : "Assinatura não confirmada; revisão de contexto"];
}

export function buildProcessActivity(payload = {}, findings = []) {
  const systemDirectory=normal(payload.processJournal?.systemDirectory).replace(/\\+$/,'');
  const isRealSystem32=row=>/^[a-z]:\\/.test(systemDirectory) && !pathOf(row).split('\\').some(part=>part==='.'||part==='..') &&
    normal(pathOf(row)).startsWith(systemDirectory+'\\');
  const knownPaths = new Set(array(findings).filter(x => ["critical", "high", "medium"].includes(x.severity)).flatMap(x => [x.artifact_value, x.evidence?.path, x.evidence?.processPath, x.evidence?.fullPath]).filter(x => typeof x === "string" && /[\\/]/.test(x)).map(normal));
  function select(rows) {
    let excludedCount = 0, commonCount = 0;
    const items = [];
    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      if (excludedGameActivity(row)) { excludedCount++; continue; }
      if (isRealSystem32(row)) { commonCount++; continue; }
      const reasons = activityRelevance(row, knownPaths);
      if (!reasons.length) { commonCount++; continue; }
      // Whitelist fields; command lines and arbitrary raw event XML are never projected.
      items.push({ name: nameOf(row), path: pathOf(row), pid: row.pid ?? row.processId ?? "", timeUtc: row.timeCreatedUtc || row.startTimeUtc || null,
        parentName: excludedGameActivity({path:row.parentProcessPath,name:row.parentProcessName}) ? "" : row.parentProcessName || "", parentPath: excludedGameActivity({ path: row.parentProcessPath, name: row.parentProcessName }) ? "" : row.parentProcessPath || "",
        signed: row.signed === true, signer: row.signerSubject || "", sha256: row.sha256 || "",
        inspectionStatus: row.inspectionStatus || "legacy", source: row.source || "", eventId: row.eventId || null,
        action: [4689, 5].includes(Number(row.eventId)) ? "closed" : "opened", processGuid:row.processGuid||'', reasons });
    }
    return { items, commonCount, excludedCount, collectedCount: rows.length };
  }
  const open = select(array(payload.processes));
  open.capturedAtUtc = payload.processSnapshotUtc || payload.scannedAtUtc || payload.collectedAtUtc || null;
  const report = payload.processJournal && typeof payload.processJournal === "object" ? payload.processJournal : null;
  const boot = Date.parse(report?.bootTimeUtc), captured = Date.parse(report?.capturedAtUtc);
  // Old reports lack a boot boundary: never label their historic 4688 records as this boot.
  const events = report && Number.isFinite(boot) && Number.isFinite(captured) ? array(report.events).filter(row => {
    const time = Date.parse(row?.timeCreatedUtc);
    return Number.isFinite(time) && time >= boot && time <= captured;
  }) : [];
  const journal = select(events);
  journal.items.sort((a, b) => Date.parse(b.timeUtc) - Date.parse(a.timeUtc));
  journal.bootTimeUtc = report?.bootTimeUtc || null;
  journal.capturedAtUtc = report?.capturedAtUtc || null;
  journal.sources = array(report?.sources).map(s => ({channel:s.channel, eventId:s.eventId, state:s.state, eventsRead:s.eventsRead, limitReached:s.limitReached === true, error:s.error || ""}));
  journal.legacy = !report;
  journal.coverage = !report ? "legacy" : journal.sources.some(s => s.limitReached) ? "limited" : journal.sources.some(s => s.state === "available") ? "recorded-events" : "unavailable";
  const history=select(report?.collectionScope==='retained-history' ? array(report.events).filter(row=>Number.isFinite(Date.parse(row?.timeCreatedUtc))&&Date.parse(row.timeCreatedUtc)<=captured) : events);
  journal.sessions=buildProcessSessions(history.items,journal.bootTimeUtc);
  journal.fullHistory=report?.collectionScope==='retained-history';
  return { open, journal };
}
