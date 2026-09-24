const loginView = document.getElementById("loginView");
const dashboardView = document.getElementById("dashboardView");
const logoutBtn = document.getElementById("logoutBtn");
const analysesBody = document.getElementById("analysesBody");
const rulesList = document.getElementById("rulesList");
const reportCard = document.getElementById("reportCard");
let currentReportId = null;

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || data.error || "Não foi possível concluir.");
  }

  return data;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString("pt-BR");
}

function safeExternalUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function safeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

async function openReportSafe(id) {
  try {
    await openReport(id);
  } catch (error) {
    console.error("Falha ao abrir relatório", error);
    alert("Erro ao abrir relatório: " + (error?.message || "erro desconhecido"));
  }
}

function statusLabel(status) {
  const map = {
    waiting: "Aguardando",
    running: "Em execução",
    completed: "Concluído",
    expired: "Expirado",
  };
  return map[status] || status || "—";
}

function severityLabel(value) {
  const map = {
    info: "INFO",
    low: "BAIXA",
    medium: "MÉDIA",
    high: "ALTA",
    critical: "CRÍTICA",
  };
  return map[value] || String(value || "").toUpperCase();
}

function setLoggedIn(logged) {
  loginView.classList.toggle("hidden", logged);
  dashboardView.classList.toggle("hidden", !logged);
  logoutBtn.classList.toggle("hidden", !logged);
}

document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const message = document.getElementById("loginMessage");
  message.classList.add("hidden");

  try {
    await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({
        password: document.getElementById("adminPassword").value,
      }),
    });

    setLoggedIn(true);
    await refreshAll();
  } catch (error) {
    message.textContent = error.message;
    message.className = "message error";
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/admin/logout", { method: "POST" });
  } finally {
    setLoggedIn(false);
  }
});

document.getElementById("analysisForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const form = event.currentTarget;
  const box = document.getElementById("analysisCreated");
  box.classList.add("hidden");

  try {
    const data = await api("/api/admin/analyses", {
      method: "POST",
      body: JSON.stringify({
        label: document.getElementById("analysisLabel").value,
        ttlHours: Number(document.getElementById("analysisTtl").value),
      }),
    });

    box.innerHTML =
      '<strong>Análise #' + escapeHtml(data.analysis.id) + ' criada.</strong><br>' +
      '<span class="analysis-link">' + escapeHtml(data.publicLink) + '</span><br><br>' +
      '<button id="copyCreatedLink" class="button ghost" type="button">Copiar link</button>';

    box.className = "message ok";

    document.getElementById("copyCreatedLink").addEventListener("click", async () => {
      await navigator.clipboard.writeText(data.publicLink);
      document.getElementById("copyCreatedLink").textContent = "Copiado ✓";
    });

    form.reset();
    document.getElementById("analysisTtl").value = "24";
    await loadAnalyses();
  } catch (error) {
    box.textContent = error.message;
    box.className = "message error";
  }
});

document.getElementById("ruleForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const form = event.currentTarget;

  try {
    await api("/api/admin/rules", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("ruleName").value,
        type: document.getElementById("ruleType").value,
        pattern: document.getElementById("rulePattern").value,
        severity: document.getElementById("ruleSeverity").value,
        description: document.getElementById("ruleDescription").value,
      }),
    });

    form.reset();
    document.getElementById("ruleSeverity").value = "medium";
    await loadRules();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("refreshBtn").addEventListener("click", refreshAll);
document.getElementById("closeReportBtn").addEventListener("click", () => {
  reportCard.classList.add("hidden");
  currentReportId = null;
});

document.getElementById("rebuildFindingsBtn").addEventListener("click", async () => {
  if (!currentReportId) return;

  const button = document.getElementById("rebuildFindingsBtn");
  const original = button.textContent;

  try {
    button.disabled = true;
    button.textContent = "Recalculando...";

    await api(
      "/api/admin/analyses/" + encodeURIComponent(currentReportId) + "/rebuild",
      { method: "POST" }
    );

    await loadAnalyses();
    await openReport(currentReportId);
  } catch (error) {
    alert(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

async function loadAnalyses() {
  const data = await api("/api/admin/analyses");
  analysesBody.innerHTML = "";

  if (!data.analyses.length) {
    analysesBody.innerHTML =
      '<tr><td colspan="6" class="muted">Nenhuma análise criada.</td></tr>';
    return;
  }

  for (const item of data.analyses) {
    const row = document.createElement("tr");
    const findings =
      Number(item.total_findings || 0) === 0
        ? '<span class="tag low">0</span>'
        : Number(item.high_findings || 0) > 0
          ? '<span class="tag high">' + Number(item.total_findings) + '</span>'
          : '<span class="tag medium">' + Number(item.total_findings) + '</span>';

    row.innerHTML = `
      <td>#${escapeHtml(item.id)}</td>
      <td>
        <strong>${escapeHtml(item.label)}</strong><br>
        <small class="muted">${escapeHtml(item.machine_name || "Aguardando PC")}</small>
      </td>
      <td><span class="tag ${escapeHtml(item.status)}">${escapeHtml(statusLabel(item.status))}</span></td>
      <td>${findings}</td>
      <td>${escapeHtml(formatDate(item.created_at))}</td>
      <td><button class="button ghost open-report" data-id="${item.id}">Abrir relatório</button></td>
    `;

    analysesBody.appendChild(row);
  }

  document.querySelectorAll(".open-report").forEach((button) => {
    button.addEventListener("click", async () => {
      await openReportSafe(button.dataset.id);
    });
  });
}

async function openReport(id) {
  currentReportId = id;

  const data = await api("/api/admin/analyses/" + encodeURIComponent(id));
  const analysis = data.analysis || {};
  const report = data.report || null;
  const findings = safeArray(data.findings);
  const relatedAnalyses = safeArray(data.relatedAnalyses);
  const payload = report?.payload && typeof report.payload === "object"
    ? report.payload
    : {};

  // Abre o cartão antes de montar as seções pesadas. Assim um erro em uma
  // seção específica não faz o botão parecer que "não funciona".
  reportCard.classList.remove("hidden");

  document.getElementById("reportTitle").textContent =
    "#" + analysis.id + " · " + analysis.label;

  const arrays = {
    usbCurrent: safeArray(payload.usbCurrent),
    usbHistory: safeArray(payload.usbHistory),
    usbTimeline: safeArray(payload.usbTimeline),
    serialDevices: safeArray(payload.serialDevices),
    processes: safeArray(payload.processes),
    prefetch: safeArray(payload.prefetch),
    prefetchExecutions: safeArray(payload.prefetchExecutions),
    services: safeArray(payload.services),
    drivers: safeArray(payload.drivers),
    startup: safeArray(payload.startup),
    files: safeArray(payload.files),
    bam: safeArray(payload.bam),
    userAssist: safeArray(payload.userAssist),
    muiCache: safeArray(payload.muiCache),
    pca: safeArray(payload.pca),
    amcache: safeArray(payload.amcache),
    shimCache: safeArray(payload.shimCache),
    setupApiUsb: safeArray(payload.setupApiUsb),
    powerShellHits: safeArray(payload.powerShellHits),
    prefetchIntegrity: safeArray(payload.prefetchIntegrity),
    hiddenVolumes: safeArray(payload.hiddenVolumes),
    logClearSignals: safeArray(payload.logClearSignals),
    processCreationEvents: safeArray(payload.processCreationEvents),
    defenderDetections: safeArray(payload.defenderDetections),
    recentShortcuts: safeArray(payload.recentShortcuts),
    recycleBin: safeArray(payload.recycleBin),
    browserDownloads: safeArray(payload.browserDownloads),
    browserHistorySignals: safeArray(payload.browserHistorySignals),
    extensionMismatches: safeArray(payload.extensionMismatches),
    defenderExclusions: safeArray(payload.defenderExclusions),
    bootIntegrity: safeArray(payload.bootIntegrity),
    systemTimeChanges: safeArray(payload.systemTimeChanges),
    virtualDisks: safeArray(payload.virtualDisks),
    rustModules: safeArray(payload.rustModules),
    usnJournalState: safeArray(payload.usnJournalState),
  };

  const disconnectedUsb =
    arrays.usbHistory.filter((item) => item.present === false).length;

  const high =
    findings.filter((item) => ["high", "critical"].includes(item.severity)).length;

  document.getElementById("reportMetrics").innerHTML = `
    <div class="metric"><small>STATUS</small><strong>${escapeHtml(statusLabel(analysis.status))}</strong></div>
    <div class="metric"><small>ACHADOS</small><strong>${findings.length}</strong></div>
    <div class="metric"><small>ALTO RISCO</small><strong>${high}</strong></div>
    <div class="metric"><small>USB DESCONECTADOS</small><strong>${disconnectedUsb}</strong></div>
  `;

  document.getElementById("reportMeta").innerHTML = `
    <div class="kv"><span>Computador</span><span>${escapeHtml(analysis.machine_name || "—")}</span></div>
    <div class="kv"><span>Sistema</span><span>${escapeHtml(analysis.os_version || "—")}</span></div>
    <div class="kv"><span>Agente</span><span>${escapeHtml(analysis.agent_version || "—")}</span></div>
    <div class="kv"><span>Início</span><span>${escapeHtml(formatDate(analysis.started_at))}</span></div>
    <div class="kv"><span>Conclusão</span><span>${escapeHtml(formatDate(analysis.finished_at))}</span></div>
  `;

  const findingsList = document.getElementById("findingsList");
  findingsList.innerHTML = "";

  if (!findings.length) {
    findingsList.innerHTML =
      '<div class="message ok">Nenhum indício correspondente às regras atuais foi encontrado.</div>';
  } else {
    for (const finding of findings) {
      const element = document.createElement("article");
      element.className = "finding";

      element.innerHTML = `
        <div class="finding-head">
          <h4>${escapeHtml(finding.title)}</h4>
          <span class="tag ${escapeHtml(finding.severity)}">${escapeHtml(severityLabel(finding.severity))}</span>
        </div>
        <code>${escapeHtml(finding.artifact_value)}</code>
        <pre>${escapeHtml(JSON.stringify(finding.evidence || {}, null, 2))}</pre>
      `;

      findingsList.appendChild(element);
    }
  }

  document.getElementById("artifactSummary").innerHTML = `
    <div class="kv"><span>USB conectados</span><span>${arrays.usbCurrent.length}</span></div>
    <div class="kv"><span>USB no histórico</span><span>${arrays.usbHistory.length} (${disconnectedUsb} desconectados)</span></div>
    <div class="kv"><span>Eventos USB</span><span>${arrays.usbTimeline.length}</span></div>
    <div class="kv"><span>Placas / Serial</span><span>${payload.hardwareSummary?.totalRelevantDevices ?? arrays.serialDevices.length}</span></div>
    <div class="kv"><span>Arduino</span><span>${payload.hardwareSummary?.arduinoCount ?? 0}</span></div>
    <div class="kv"><span>MAKCU / Moku</span><span>${payload.hardwareSummary?.makcuCount ?? 0}</span></div>
    <div class="kv"><span>Execuções Prefetch</span><span>${arrays.prefetchExecutions.length}</span></div>
    <div class="kv"><span>Arquivos analisados</span><span>${arrays.files.length}</span></div>
    <div class="kv"><span>Processos</span><span>${arrays.processes.length}</span></div>
    <div class="kv"><span>Prefetch</span><span>${arrays.prefetch.length}</span></div>
    <div class="kv"><span>Serviços</span><span>${arrays.services.length}</span></div>
    <div class="kv"><span>Drivers</span><span>${arrays.drivers.length}</span></div>
    <div class="kv"><span>Inicialização</span><span>${arrays.startup.length}</span></div>
    <div class="kv"><span>BAM/DAM</span><span>${arrays.bam.length}</span></div>
    <div class="kv"><span>UserAssist</span><span>${arrays.userAssist.length}</span></div>
    <div class="kv"><span>MUICache</span><span>${arrays.muiCache.length}</span></div>
    <div class="kv"><span>PCA Store</span><span>${arrays.pca.length}</span></div>
    <div class="kv"><span>Amcache</span><span>${arrays.amcache.length}</span></div>
    <div class="kv"><span>ShimCache</span><span>${arrays.shimCache.length}</span></div>
    <div class="kv"><span>SetupAPI USB</span><span>${arrays.setupApiUsb.length}</span></div>
    <div class="kv"><span>PowerShell por regra</span><span>${arrays.powerShellHits.length}</span></div>
    <div class="kv"><span>Anomalias Prefetch</span><span>${arrays.prefetchIntegrity.length}</span></div>
    <div class="kv"><span>Volumes sem letra</span><span>${arrays.hiddenVolumes.length}</span></div>
    <div class="kv"><span>Limpezas de log (24h)</span><span>${arrays.logClearSignals.length}</span></div>
    <div class="kv"><span>Processos históricos (4688)</span><span>${arrays.processCreationEvents.length}</span></div>
    <div class="kv"><span>Defender</span><span>${arrays.defenderDetections.length} detecções · ${arrays.defenderExclusions.length} exclusões</span></div>
    <div class="kv"><span>Atalhos recentes</span><span>${arrays.recentShortcuts.length}</span></div>
    <div class="kv"><span>Downloads no histórico</span><span>${arrays.browserDownloads.length}</span></div>
    <div class="kv"><span>Downloads não localizados</span><span>${arrays.browserDownloads.filter((x) => x.fileMissing === true).length}</span></div>
    <div class="kv"><span>Histórico suspeito do navegador</span><span>${arrays.browserHistorySignals.length}</span></div>
    <div class="kv"><span>Lixeira</span><span>${arrays.recycleBin.length}</span></div>
    <div class="kv"><span>Ambiente virtual</span><span>${payload.vmEnvironment?.isVirtualMachine ? escapeHtml(payload.vmEnvironment?.detectedPlatform || "Sim") : "Não detectado"}</span></div>
    <div class="kv"><span>Extensões modificadas</span><span>${arrays.extensionMismatches.length}</span></div>
    <div class="kv"><span>Módulos do Rust</span><span>${arrays.rustModules.length}</span></div>
    <div class="kv"><span>Discos virtuais</span><span>${arrays.virtualDisks.length}</span></div>
    <div class="kv"><span>Prefetch habilitado</span><span>${payload.systemArtifacts?.enablePrefetcher ?? "—"}</span></div>
    <div class="kv"><span>Amcache presente</span><span>${payload.systemArtifacts?.amcacheExists ? "Sim" : "Não"}</span></div>
    <div class="kv"><span>Erros parciais</span><span>${(payload.errors || []).length}</span></div>
  `;

  const hw = payload.hardwareSummary || {};
  const connectedStorage = arrays.usbCurrent.filter((item) => {
    const haystack = [item.name, item.deviceId, item.pnpDeviceId, item.manufacturer]
      .join(" ").toLowerCase();
    return haystack.includes("disk") ||
      haystack.includes("mass storage") ||
      haystack.includes("usbstor") ||
      haystack.includes("storage");
  }).length;

  document.getElementById("deviceOverviewList").innerHTML = `
    <div class="metric-grid">
      <div class="metric"><small>PENDRIVES CONECTADOS</small><strong>${connectedStorage}</strong></div>
      <div class="metric"><small>USB DESCONECTADOS</small><strong>${disconnectedUsb}</strong></div>
      <div class="metric"><small>ARDUINO</small><strong>${Number(hw.arduinoCount ?? 0)}</strong></div>
      <div class="metric"><small>MAKCU / MOKU</small><strong>${Number(hw.makcuCount ?? 0)}</strong></div>
      <div class="metric"><small>CH34X</small><strong>${Number(hw.ch34xCount ?? 0)}</strong></div>
      <div class="metric"><small>CP210X</small><strong>${Number(hw.cp210xCount ?? 0)}</strong></div>
      <div class="metric"><small>FTDI</small><strong>${Number(hw.ftdiCount ?? 0)}</strong></div>
      <div class="metric"><small>OUTROS SERIAIS</small><strong>${Number(hw.otherSerialCount ?? 0)}</strong></div>
    </div>
    <div class="message">CH34x/CP210x/FTDI são bridges USB-Serial. Eles aparecem separados de Arduino/MAKCU para evitar afirmar um modelo de placa sem evidência suficiente.</div>
  `;
  document.getElementById("relatedAnalysesList").innerHTML = relatedAnalyses.length
    ? relatedAnalyses.map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>#${escapeHtml(item.id)} · ${escapeHtml(item.label || "Análise")}</h4>
            <span class="tag ${escapeHtml(item.status || "info")}">${escapeHtml(statusLabel(item.status))}</span>
          </div>
          <div class="kv"><span>Data</span><span>${escapeHtml(formatDate(item.created_at))}</span></div>
          <div class="kv"><span>Computador</span><span>${escapeHtml(item.machine_name || "—")}</span></div>
          <div class="kv"><span>Agente</span><span>${escapeHtml(item.agent_version || "—")}</span></div>
          <button class="button ghost open-related-report" data-id="${escapeHtml(item.id)}">Abrir relatório</button>
        </div>
      `).join("")
    : '<div class="message">Nenhuma análise anterior associada a este fingerprint.</div>';

  document.querySelectorAll(".open-related-report").forEach((button) => {
    button.addEventListener("click", async () => {
      await openReportSafe(button.dataset.id);
    });
  });

  const disconnected = arrays.usbHistory.filter((item) => item.present === false);
  document.getElementById("disconnectedUsbList").innerHTML = disconnected.length
    ? disconnected
        .sort((a, b) =>
          new Date(b.lastDisconnectedUtc || b.lastConnectedUtc || 0) -
          new Date(a.lastDisconnectedUtc || a.lastConnectedUtc || 0))
        .map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.friendlyName || item.deviceDescription || item.deviceClass || "Dispositivo USB")}</h4>
            <span class="tag medium">DESCONECTADO</span>
          </div>
          <div class="kv"><span>Fabricante</span><span>${escapeHtml(item.manufacturer || "—")}</span></div>
          <div class="kv"><span>Instância / serial</span><span>${escapeHtml(item.instanceId || "—")}</span></div>
          <div class="kv"><span>Última conexão</span><span>${escapeHtml(formatDate(item.lastConnectedUtc))}</span></div>
          <div class="kv"><span>Última desconexão</span><span>${escapeHtml(formatDate(item.lastDisconnectedUtc))}</span></div>
          <div class="kv"><span>Fonte do horário</span><span>${escapeHtml(item.timelineSource || "Não registrado pelo Windows")}</span></div>
          <code>${escapeHtml(item.deviceClass || "")}</code>
        </div>
      `).join("")
    : '<div class="message ok">Nenhum dispositivo USB histórico marcado como desconectado.</div>';

  document.getElementById("serialDeviceList").innerHTML = `
    <div class="metric-grid">
      <div class="metric"><small>DISPOSITIVOS</small><strong>${Number(hw.totalRelevantDevices ?? arrays.serialDevices.length)}</strong></div>
      <div class="metric"><small>ARDUINO</small><strong>${Number(hw.arduinoCount ?? 0)}</strong></div>
      <div class="metric"><small>MAKCU / MOKU</small><strong>${Number(hw.makcuCount ?? 0)}</strong></div>
      <div class="metric"><small>CH34X</small><strong>${Number(hw.ch34xCount ?? 0)}</strong></div>
    </div>
    <div class="kv"><span>CP210x</span><span>${Number(hw.cp210xCount ?? 0)}</span></div>
    <div class="kv"><span>FTDI</span><span>${Number(hw.ftdiCount ?? 0)}</span></div>
    <div class="kv"><span>Outros seriais</span><span>${Number(hw.otherSerialCount ?? 0)}</span></div>
    <div class="message">A contagem identifica famílias/bridges por VID/PID, descritor e fabricante. CH34x/CP210x/FTDI isoladamente não provam qual placa está atrás do bridge.</div>
  `;

  const priorityFiles = [];

  for (const item of arrays.browserDownloads) {
    if (item.fileMissing !== true) continue;
    const name = item.fileName || item.targetPath || "";
    if (!/\.(exe|com|scr|dll|bat|cmd|ps1|msi)$/i.test(name)) continue;

    priorityFiles.push({
      priority: 5,
      status: "BAIXADO E APAGADO / MOVIDO",
      tag: "high",
      name: item.fileName || "Executável",
      path: item.targetPath || item.currentPath || "—",
      time: item.startTimeUtc,
      source: item.browser || "Navegador",
      url: item.sourceUrl || item.finalUrl || item.pageUrl || "",
      detail: "Histórico de download preservado; arquivo não está mais no destino original."
    });
  }

  for (const item of arrays.prefetchExecutions) {
    if (item.likelyDetachedOrRemovable !== true) continue;
    const pathValue = item.resolvedExecutablePath || item.nativeExecutablePath || "";
    const lower = String(pathValue).replaceAll("/", "\\").toLowerCase();
    if (lower.includes("\\windows\\") ||
        lower.includes("\\program files\\") ||
        lower.includes("\\program files (x86)\\") ||
        lower.includes("\\steamapps\\common\\")) continue;

    priorityFiles.push({
      priority: 6,
      status: "EXECUTADO / VOLUME REMOVIDO",
      tag: "high",
      name: item.executableName || item.prefetchFile || "Executável",
      path: pathValue || "—",
      time: item.lastRunUtc,
      source: "Prefetch",
      url: "",
      detail: "Execução recente registrada em mídia removível ou volume não montado."
    });
  }

  for (const item of arrays.recycleBin) {
    const name = item.fileName || item.originalPath || "";
    if (!/\.(exe|com|scr|dll|bat|cmd|ps1|msi)$/i.test(name)) continue;

    priorityFiles.push({
      priority: 4,
      status: "ARQUIVO EXCLUÍDO",
      tag: "medium",
      name: item.fileName || "Executável",
      path: item.originalPath || "—",
      time: item.deletedAtUtc,
      source: "Lixeira do Windows",
      url: "",
      detail: item.recycledDataPresent ? "Ainda existe conteúdo na Lixeira." : "Metadado de exclusão preservado; conteúdo não localizado."
    });
  }

  for (const item of arrays.bam) {
    const pathValue = item.path || "";
    const lower = String(pathValue).replaceAll("/", "\\").toLowerCase();
    if (item.fileExists !== false) continue;
    if (!/\.(exe|com|scr|dll)$/i.test(pathValue)) continue;
    if (!lower.includes("\\downloads\\") &&
        !lower.includes("\\desktop\\") &&
        !lower.includes("\\temp\\")) continue;

    priorityFiles.push({
      priority: 3,
      status: "EXECUTADO / ARQUIVO AUSENTE",
      tag: "medium",
      name: pathValue.split("\\").filter(Boolean).at(-1) || "Executável",
      path: pathValue,
      time: item.lastExecutionUtc,
      source: "BAM",
      url: "",
      detail: "O Windows registrou execução, mas o arquivo não foi localizado no caminho original."
    });
  }

  const prioritySeen = new Set();
  const priorityUnique = priorityFiles
    .sort((a, b) => b.priority - a.priority || new Date(b.time || 0) - new Date(a.time || 0))
    .filter((item) => {
      const key = String(item.name || item.path || "").toLowerCase();
      if (!key || prioritySeen.has(key)) return false;
      prioritySeen.add(key);
      return true;
    })
    .slice(0, 150);

  document.getElementById("priorityFilesList").innerHTML = priorityUnique.length
    ? priorityUnique.map((item) => {
        const sourceUrl = safeExternalUrl(item.url);
        return `
          <div class="finding">
            <div class="finding-head">
              <h4>${escapeHtml(item.name || "Arquivo")}</h4>
              <span class="tag ${escapeHtml(item.tag)}">${escapeHtml(item.status)}</span>
            </div>
            <div class="kv"><span>Caminho</span><span>${escapeHtml(item.path || "—")}</span></div>
            <div class="kv"><span>Data / horário</span><span>${escapeHtml(formatDate(item.time))}</span></div>
            <div class="kv"><span>Fonte</span><span>${escapeHtml(item.source || "—")}</span></div>
            ${sourceUrl ? `<div class="kv"><span>Origem do download</span><span><a href="${escapeHtml(sourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.url)}</a></span></div>` : ""}
            <div class="kv"><span>Motivo</span><span>${escapeHtml(item.detail || "—")}</span></div>
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhum arquivo apagado/executado de alta prioridade foi identificado.</div>';

  const historyRiskOrder = { high: 3, medium: 2, low: 1 };
  const browserHistorySignals = [...arrays.browserHistorySignals]
    .sort((a, b) =>
      (historyRiskOrder[String(b.riskLevel || "").toLowerCase()] || 0) -
      (historyRiskOrder[String(a.riskLevel || "").toLowerCase()] || 0) ||
      new Date(b.visitTimeUtc || 0) - new Date(a.visitTimeUtc || 0))
    .slice(0, 300);

  document.getElementById("browserHistorySignalsList").innerHTML = browserHistorySignals.length
    ? browserHistorySignals.map((item) => {
        const risk = String(item.riskLevel || "low").toLowerCase();
        const safeUrl = safeExternalUrl(item.url);
        const label = item.searchQuery ? "PESQUISA" : "SITE / PÁGINA";
        return `
          <div class="finding">
            <div class="finding-head">
              <h4>${escapeHtml(item.searchQuery || item.host || item.title || "Histórico do navegador")}</h4>
              <span class="tag ${escapeHtml(risk === "high" ? "high" : risk === "medium" ? "medium" : "info")}">${label}</span>
            </div>
            <div class="kv"><span>Navegador</span><span>${escapeHtml((item.browser || "—") + " · " + (item.profile || "perfil"))}</span></div>
            <div class="kv"><span>Visitado em</span><span>${escapeHtml(formatDate(item.visitTimeUtc))}</span></div>
            <div class="kv"><span>Título</span><span>${escapeHtml(item.title || "—")}</span></div>
            ${item.searchQuery ? `<div class="kv"><span>Pesquisa</span><span>${escapeHtml(item.searchQuery)}</span></div>` : ""}
            <div class="kv"><span>Termos encontrados</span><span>${escapeHtml((item.matchedTerms || []).join(", ") || "—")}</span></div>
            <div class="kv"><span>Motivo</span><span>${escapeHtml(item.reason || "—")}</span></div>
            ${safeUrl ? `<div class="kv"><span>URL</span><span><a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.url)}</a></span></div>` : `<code>${escapeHtml(item.url || "—")}</code>`}
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhuma pesquisa/site com os termos anti-cheat configurados foi preservado no histórico.</div>';
  const missingDownloads = [...arrays.browserDownloads]
    .filter((item) => item.fileMissing === true)
    .sort((a, b) =>
      new Date(b.startTimeUtc || 0) - new Date(a.startTimeUtc || 0))
    .slice(0, 500);

  document.getElementById("browserDownloadsList").innerHTML = missingDownloads.length
    ? missingDownloads.map((item) => {
        const sourceUrl = safeExternalUrl(item.sourceUrl);
        const finalUrl = safeExternalUrl(item.finalUrl);
        const pageUrl = safeExternalUrl(item.pageUrl || item.referrerUrl || item.siteUrl);

        const linkRow = (label, url, fallback) => {
          const safeUrl = safeExternalUrl(url);
          if (!safeUrl) {
            return `<div class="kv"><span>${escapeHtml(label)}</span><span>${escapeHtml(fallback || "—")}</span></div>`;
          }

          return `<div class="kv"><span>${escapeHtml(label)}</span><span><a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></span></div>`;
        };

        const executableLike = /\.(exe|com|scr|dll|bat|cmd|ps1|msi)$/i
          .test(item.fileName || item.targetPath || "");

        return `
          <div class="finding">
            <div class="finding-head">
              <h4>${escapeHtml(item.fileName || "Download")}</h4>
              <span class="tag ${executableLike ? "medium" : "info"}">APAGADO / MOVIDO</span>
            </div>
            <div class="kv"><span>Navegador</span><span>${escapeHtml((item.browser || "—") + " · " + (item.profile || "perfil"))}</span></div>
            <div class="kv"><span>Baixado em</span><span>${escapeHtml(formatDate(item.startTimeUtc))}</span></div>
            <div class="kv"><span>Destino original</span><span>${escapeHtml(item.targetPath || "—")}</span></div>
            <div class="kv"><span>Tamanho</span><span>${Number(item.totalBytes || 0).toLocaleString("pt-BR")} bytes</span></div>
            <div class="kv"><span>MIME</span><span>${escapeHtml(item.mimeType || "—")}</span></div>
            ${linkRow("URL original", sourceUrl, item.sourceUrl)}
            ${linkRow("URL final", finalUrl, item.finalUrl)}
            ${linkRow("Página / referrer", pageUrl, item.pageUrl || item.referrerUrl || item.siteUrl)}
            <div class="kv"><span>Fonte forense</span><span>${escapeHtml(item.databaseSource || "Histórico do navegador")}</span></div>
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhum download apagado/movido foi preservado no histórico dos navegadores suportados.</div>';

  const timeline = [];

  for (const item of arrays.browserHistorySignals) {
    if (!item.visitTimeUtc) continue;
    timeline.push({
      time: item.visitTimeUtc,
      action: item.searchQuery ? "PESQUISA SUSPEITA" : "SITE SUSPEITO",
      tag: item.riskLevel === "high" ? "high" : item.riskLevel === "medium" ? "medium" : "info",
      path: item.searchQuery || item.host || item.url || "Navegador",
      detail: [item.browser, safeArray(item.matchedTerms).join(", ")].filter(Boolean).join(" · ")
    });
  }

  for (const item of arrays.browserDownloads) {
    if (!item.startTimeUtc) continue;
    timeline.push({
      time: item.startTimeUtc,
      action: "BAIXADO",
      tag: item.fileMissing ? "medium" : "info",
      path: item.targetPath || item.fileName || "Download",
      detail: [item.browser, item.sourceUrl || item.finalUrl].filter(Boolean).join(" · ")
    });
  }

  for (const item of arrays.prefetchExecutions) {
    if (!item.lastRunUtc) continue;
    timeline.push({
      time: item.lastRunUtc,
      action: "EXECUTADO",
      tag: item.likelyDetachedOrRemovable ? "high" : "info",
      path: item.resolvedExecutablePath || item.nativeExecutablePath || item.executableName || "Executável",
      detail: "Prefetch · " + Number(item.runCount || 0) + " execução(ões)"
    });
  }

  for (const item of arrays.recycleBin) {
    if (!item.deletedAtUtc) continue;
    timeline.push({
      time: item.deletedAtUtc,
      action: "EXCLUÍDO",
      tag: /\.(exe|dll|com|scr|bat|cmd|ps1|msi)$/i.test(item.fileName || "") ? "medium" : "info",
      path: item.originalPath || item.fileName || "Lixeira",
      detail: item.recycledDataPresent ? "Ainda presente na Lixeira" : "Dados reciclados não localizados"
    });
  }

  for (const item of arrays.usbTimeline) {
    if (!item.timeCreatedUtc) continue;
    timeline.push({
      time: item.timeCreatedUtc,
      action: item.eventType === "disconnect" ? "USB DESCONECTADO" : item.eventType === "connect" ? "USB CONECTADO" : "USB",
      tag: item.eventType === "disconnect" ? "medium" : "info",
      path: item.deviceId || item.evidence || "Dispositivo USB",
      detail: (item.provider || "Windows") + (item.eventId ? " · Event " + item.eventId : "")
    });
  }

  for (const item of arrays.processCreationEvents) {
    if (!item.timeCreatedUtc) continue;
    timeline.push({
      time: item.timeCreatedUtc,
      action: "PROCESSO",
      tag: item.processPresent === false ? "medium" : "info",
      path: item.processPath || item.processName || "Processo",
      detail: item.parentProcessName ? "Pai: " + item.parentProcessName : "Event 4688"
    });
  }

  timeline.sort((a, b) => new Date(b.time) - new Date(a.time));

  document.getElementById("forensicTimelineList").innerHTML = timeline.length
    ? timeline.slice(0, 300).map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.action)}</h4>
            <span class="tag ${escapeHtml(item.tag)}">${escapeHtml(formatDate(item.time))}</span>
          </div>
          <code>${escapeHtml(item.path || "—")}</code>
          <div class="kv"><span>Fonte / detalhe</span><span>${escapeHtml(item.detail || "—")}</span></div>
        </div>
      `).join("")
    : '<div class="message">Nenhum evento suficiente para montar a linha do tempo.</div>';

  const recycleEntries = [...arrays.recycleBin]
    .sort((a, b) => new Date(b.deletedAtUtc || 0) - new Date(a.deletedAtUtc || 0))
    .slice(0, 500);

  document.getElementById("recycleBinList").innerHTML = recycleEntries.length
    ? recycleEntries.map((item) => {
        const executable = /\.(exe|dll|com|scr|bat|cmd|ps1|msi)$/i.test(item.fileName || "");
        return `
          <div class="finding">
            <div class="finding-head">
              <h4>${escapeHtml(item.fileName || "Arquivo excluído")}</h4>
              <span class="tag ${executable ? "medium" : "info"}">LIXEIRA</span>
            </div>
            <div class="kv"><span>Excluído em</span><span>${escapeHtml(formatDate(item.deletedAtUtc))}</span></div>
            <div class="kv"><span>Caminho original</span><span>${escapeHtml(item.originalPath || "—")}</span></div>
            <div class="kv"><span>Tamanho original</span><span>${Number(item.originalSize || 0).toLocaleString("pt-BR")} bytes</span></div>
            <div class="kv"><span>Dados ainda na Lixeira</span><span>${item.recycledDataPresent ? "Sim" : "Não"}</span></div>
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhum metadado de arquivo excluído foi encontrado na Lixeira.</div>';

  const processStarts = [...arrays.processes]
    .filter((item) => item.startTimeUtc)
    .sort((a, b) => new Date(b.startTimeUtc) - new Date(a.startTimeUtc))
    .slice(0, 250);

  document.getElementById("processStartList").innerHTML = processStarts.length
    ? processStarts.map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.name || "Processo")}</h4>
            <span class="tag info">PID ${Number(item.pid || 0)}</span>
          </div>
          <div class="kv"><span>Iniciado em</span><span>${escapeHtml(formatDate(item.startTimeUtc))}</span></div>
          <div class="kv"><span>Caminho</span><span>${escapeHtml(item.path || "—")}</span></div>
          <div class="kv"><span>Assinado</span><span>${item.signed ? "Sim" : "Não"}${item.signerSubject ? " · " + escapeHtml(item.signerSubject) : ""}</span></div>
        </div>
      `).join("")
    : '<div class="message">Nenhum horário de início de processo disponível.</div>';

  const compileTimes = [];

  for (const item of arrays.files) {
    if (!item.compilationTimeUtc) continue;
    compileTimes.push({
      path: item.path || item.name,
      time: item.compilationTimeUtc,
      source: "PE Header",
      signer: item.signerSubject || ""
    });
  }

  for (const item of arrays.amcache) {
    if (!item.linkDateUtc) continue;
    compileTimes.push({
      path: item.fullPath || item.name,
      time: item.linkDateUtc,
      source: "Amcache LinkDate",
      signer: item.publisher || ""
    });
  }

  compileTimes.sort((a, b) => new Date(b.time) - new Date(a.time));

  document.getElementById("compilationTimesList").innerHTML = compileTimes.length
    ? compileTimes.slice(0, 300).map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.source)}</h4>
            <span class="tag info">${escapeHtml(formatDate(item.time))}</span>
          </div>
          <code>${escapeHtml(item.path || "—")}</code>
          ${item.signer ? '<div class="kv"><span>Publisher / assinante</span><span>' + escapeHtml(item.signer) + '</span></div>' : ""}
        </div>
      `).join("")
    : '<div class="message">Nenhum timestamp de compilação PE disponível.</div>';

  const reviewFiles = [...arrays.files]
    .sort((a, b) => {
      const aExec = a.prefetchEvidenceUtc ? 1 : 0;
      const bExec = b.prefetchEvidenceUtc ? 1 : 0;
      if (aExec !== bExec) return bExec - aExec;
      return new Date(b.lastWriteUtc || 0) - new Date(a.lastWriteUtc || 0);
    })
    .slice(0, 250);

  document.getElementById("candidateFilesList").innerHTML = reviewFiles.length
    ? reviewFiles.map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.name || "Arquivo")}</h4>
            <span class="tag ${item.prefetchEvidenceUtc ? "medium" : "info"}">
              ${item.prefetchEvidenceUtc ? "EXECUÇÃO INDICADA" : "INVENTÁRIO"}
            </span>
          </div>
          <div class="kv"><span>Caminho</span><span>${escapeHtml(item.path || "—")}</span></div>
          <div class="kv"><span>Última modificação</span><span>${escapeHtml(formatDate(item.lastWriteUtc))}</span></div>
          <div class="kv"><span>Evidência de execução</span><span>${escapeHtml(formatDate(item.prefetchEvidenceUtc))}</span></div>
          <div class="kv"><span>Unidade</span><span>${escapeHtml(item.driveType || "—")}</span></div>
          <div class="kv"><span>Assinado</span><span>${item.signed ? "Sim" : "Não"}${item.signerSubject ? " · " + escapeHtml(item.signerSubject) : ""}</span></div>
          <code>SHA-256: ${escapeHtml(item.sha256 || "não disponível")}</code>
        </div>
      `).join("")
    : '<div class="message">Nenhum arquivo executável candidato foi coletado.</div>';

  const recentExecutions = [...arrays.prefetchExecutions]
    .filter((item) => {
      if (!item.lastRunUtc || item.likelyDetachedOrRemovable !== true) return false;

      const p = String(item.resolvedExecutablePath || item.nativeExecutablePath || "")
        .replaceAll("/", "\\").toLowerCase();

      const trusted =
        p.includes("\\windows\\") ||
        p.includes("\\program files\\") ||
        p.includes("\\program files (x86)\\") ||
        p.includes("\\steamapps\\common\\");

      return !trusted;
    })
    .sort((a, b) => new Date(b.lastRunUtc) - new Date(a.lastRunUtc))
    .slice(0, 100);

  document.getElementById("recentExecutionList").innerHTML = recentExecutions.length
    ? recentExecutions.map((item) => {
        const risky = item.likelyDetachedOrRemovable === true;
        const unresolved = item.volumeNotMounted === true && !risky;
        const status = risky
          ? "VOLUME REMOVÍVEL / NÃO MONTADO"
          : unresolved
            ? "VOLUME NÃO CORRELACIONADO"
            : item.executablePresent === false
              ? "ARQUIVO NÃO LOCALIZADO"
              : "EXECUÇÃO REGISTRADA";

        return `
          <div class="finding">
            <div class="finding-head">
              <h4>${escapeHtml(item.executableName || item.prefetchFile || "Executável")}</h4>
              <span class="tag ${risky ? "high" : "info"}">${escapeHtml(status)}</span>
            </div>
            <div class="kv"><span>Última execução</span><span>${escapeHtml(formatDate(item.lastRunUtc))}</span></div>
            <div class="kv"><span>Quantidade de execuções</span><span>${Number(item.runCount || 0)}</span></div>
            <div class="kv"><span>Caminho nativo</span><span>${escapeHtml(item.nativeExecutablePath || "—")}</span></div>
            <div class="kv"><span>Caminho atual</span><span>${escapeHtml(item.resolvedExecutablePath || "Não montado / não resolvido")}</span></div>
            <div class="kv"><span>Arquivo presente</span><span>${item.executablePresent === true ? "Sim" : item.executablePresent === false ? "Não" : "Indeterminado"}</span></div>
            <code>${escapeHtml(item.prefetchFile || "")}</code>
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhuma execução suspeita em mídia removível/não montada foi identificada.</div>';

  const integritySignals = [];

  const deceptiveExtensions = new Set([
    ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv", ".mov",
    ".html", ".htm", ".css", ".md"
  ]);

  for (const item of arrays.extensionMismatches.slice(0, 100)) {
    const candidate = String(item.path || item.name || "");
    const dot = candidate.lastIndexOf(".");
    const ext = dot >= 0 ? candidate.slice(dot).toLowerCase() : "";

    if (!deceptiveExtensions.has(ext)) continue;

    integritySignals.push({
      title: "Executável com extensão disfarçada",
      value: candidate,
      detail: item.reason || "Cabeçalho PE/MZ em extensão normalmente usada por documento/mídia.",
      tag: "medium"
    });
  }

  for (const item of arrays.defenderDetections.slice(0, 100)) {
    integritySignals.push({
      title: "Microsoft Defender",
      value: item.threatName || item.path || "Detecção",
      detail: [formatDate(item.timeCreatedUtc), item.path, item.action].filter(Boolean).join(" · "),
      tag: "medium"
    });
  }

  for (const item of arrays.bootIntegrity.slice(0, 50)) {
    integritySignals.push({
      title: "Boot / BCD",
      value: item.raw || item.setting,
      detail: "Configuração de integridade do Windows",
      tag: "medium"
    });
  }

  const importantServices = ["PcaSvc", "DiagTrack", "EventLog"];

  for (const serviceName of importantServices) {
    const service = arrays.services.find((item) =>
      String(item.name || "").toLowerCase() === serviceName.toLowerCase());

    if (!service) continue;

    const disabled =
      String(service.startMode || "").toLowerCase() === "disabled";

    if (!disabled) continue;

    integritySignals.push({
      title: "Recurso do Windows desativado",
      value: service.name + " · " + (service.displayName || ""),
      detail: "StartMode: " + (service.startMode || "—") + " · Estado: " + (service.state || "—"),
      tag: "medium"
    });
  }

  const explorer = arrays.processes.find((item) =>
    String(item.name || "").toLowerCase() === "explorer");

  if (explorer?.startTimeUtc && arrays.pca.length === 0) {
    const explorerAgeMinutes =
      (Date.now() - new Date(explorer.startTimeUtc).getTime()) / 60000;

    if (Number.isFinite(explorerAgeMinutes) &&
        explorerAgeMinutes >= 0 &&
        explorerAgeMinutes <= 20) {
      integritySignals.push({
        title: "Explorer reiniciado recentemente",
        value: "explorer.exe",
        detail: "Início: " + formatDate(explorer.startTimeUtc) + " · PCA Store vazio nesta coleta.",
        tag: "medium"
      });
    }
  }

  if (payload.vmEnvironment?.isVirtualMachine) {
    integritySignals.push({
      title: "Ambiente virtual detectado",
      value: payload.vmEnvironment.detectedPlatform || "Máquina virtual",
      detail: [
        payload.vmEnvironment.manufacturer,
        payload.vmEnvironment.model
      ].filter(Boolean).join(" · "),
      tag: "info"
    });
  }

  document.getElementById("integritySignalsList").innerHTML = integritySignals.length
    ? integritySignals.slice(0, 250).map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.title)}</h4>
            <span class="tag ${escapeHtml(item.tag)}">REVISAR</span>
          </div>
          <code>${escapeHtml(item.value || "—")}</code>
          <div class="kv"><span>Detalhe</span><span>${escapeHtml(item.detail || "—")}</span></div>
        </div>
      `).join("")
    : '<div class="message ok">Nenhum contexto adicional de integridade/anti-forense coletado.</div>';

  const knownOverlayTokens = [
    "discord", "steam", "gameoverlayrenderer", "nvidia", "nvspcap",
    "amd", "radeon", "obs", "overwolf", "medal", "steelseries",
    "logitech", "razer", "microsoft"
  ];

  const suspiciousRustModules = arrays.rustModules.filter((item) => {
    const haystack = [
      item.path,
      item.moduleName,
      item.companyName,
      item.signerSubject
    ].join(" ").toLowerCase();

    const knownOverlay = knownOverlayTokens.some((token) =>
      haystack.includes(token));

    return !knownOverlay &&
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
  });

  document.getElementById("rustModulesList").innerHTML = suspiciousRustModules.length
    ? suspiciousRustModules.slice(0, 100).map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.moduleName || "DLL")}</h4>
            <span class="tag high">EXTERNO / NÃO ASSINADO</span>
          </div>
          <div class="kv"><span>Processo</span><span>${escapeHtml((item.processName || "Rust") + " #" + (item.processId || ""))}</span></div>
          <div class="kv"><span>Caminho</span><span>${escapeHtml(item.path || "—")}</span></div>
          <div class="kv"><span>Empresa</span><span>${escapeHtml(item.companyName || "—")}</span></div>
          <div class="kv"><span>Assinante</span><span>${escapeHtml(item.signerSubject || "—")}</span></div>
        </div>
      `).join("")
    : '<div class="message ok">Nenhum módulo suspeito carregado no Rust. Módulos normais de Steam/Discord/GPU ficam apenas no inventário bruto.</div>';
  const execArtifacts = [];

  for (const item of arrays.bam.slice(0, 300)) {
    execArtifacts.push({
      source: "BAM/DAM",
      value: item.path,
      detail: item.lastExecutionUtc ? "Última execução: " + formatDate(item.lastExecutionUtc) : "Timestamp indisponível",
      state: item.fileExists ? "Arquivo presente" : "Arquivo ausente"
    });
  }

  for (const item of arrays.pca.slice(0, 300)) {
    execArtifacts.push({
      source: item.source || "PCA",
      value: item.path,
      detail: item.fileExists ? "Arquivo presente" : "Arquivo ausente",
      state: ""
    });
  }

  for (const item of arrays.amcache.slice(0, 300)) {
    execArtifacts.push({
      source: "Amcache",
      value: item.fullPath || item.name,
      detail: "Registro: " + formatDate(item.fileKeyLastWriteUtc),
      state: item.filePresent ? "Arquivo presente" : "Arquivo ausente"
    });
  }

  for (const item of arrays.shimCache.slice(0, 300)) {
    execArtifacts.push({
      source: "ShimCache",
      value: item.path,
      detail: item.lastModifiedUtc ? "Última modificação: " + formatDate(item.lastModifiedUtc) : "Timestamp não disponível",
      state: item.filePresent ? "Arquivo presente" : "Arquivo ausente"
    });
  }

  for (const item of arrays.userAssist.slice(0, 300)) {
    execArtifacts.push({
      source: "UserAssist",
      value: item.decodedName,
      detail: "Registro de uso da interface do Windows",
      state: ""
    });
  }

  for (const item of arrays.powerShellHits.slice(0, 200)) {
    execArtifacts.push({
      source: "PowerShell",
      value: item.matchedLine,
      detail: "Regra: " + (item.ruleName || item.pattern || "custom"),
      state: item.sourceFile || ""
    });
  }

  document.getElementById("executionArtifactsList").innerHTML = execArtifacts.length
    ? execArtifacts.slice(0, 500).map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.source)}</h4>
            <span class="tag info">EVIDÊNCIA</span>
          </div>
          <code>${escapeHtml(item.value || "—")}</code>
          <div class="kv"><span>Detalhe</span><span>${escapeHtml(item.detail || "—")}</span></div>
          ${item.state ? '<div class="kv"><span>Estado</span><span>' + escapeHtml(item.state) + '</span></div>' : ""}
        </div>
      `).join("")
    : '<div class="message">Nenhum artefato adicional de execução foi coletado.</div>';

  document.getElementById("rawReport").textContent =
    JSON.stringify(payload, null, 2);

  reportCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadRules() {
  const data = await api("/api/admin/rules");
  rulesList.innerHTML = "";

  for (const rule of data.rules) {
    const item = document.createElement("div");
    item.className = "rule";

    item.innerHTML = `
      <div>
        <strong>${escapeHtml(rule.name)}</strong>
        <small>
          ${escapeHtml(rule.type)} ·
          <span class="tag ${escapeHtml(rule.severity)}">${escapeHtml(severityLabel(rule.severity))}</span>
          · ${rule.enabled ? "ATIVA" : "DESATIVADA"}
        </small><br>
        <code>${escapeHtml(rule.pattern)}</code>
        ${rule.description ? '<small><br>' + escapeHtml(rule.description) + '</small>' : ""}
      </div>
      <button class="button ghost toggle-rule" data-id="${rule.id}">
        ${rule.enabled ? "Desativar" : "Ativar"}
      </button>
    `;

    rulesList.appendChild(item);
  }

  document.querySelectorAll(".toggle-rule").forEach((button) => {
    button.addEventListener("click", async () => {
      await api("/api/admin/rules/" + button.dataset.id + "/toggle", {
        method: "POST",
      });
      await loadRules();
    });
  });
}

async function refreshAll() {
  await Promise.all([loadAnalyses(), loadRules()]);
}

async function boot() {
  try {
    await api("/api/admin/me");
    setLoggedIn(true);
    await refreshAll();
  } catch {
    setLoggedIn(false);
  }
}

boot();
