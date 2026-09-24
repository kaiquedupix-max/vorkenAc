const loginView = document.getElementById("loginView");
const dashboardView = document.getElementById("dashboardView");
const logoutBtn = document.getElementById("logoutBtn");
const analysesBody = document.getElementById("analysesBody");
const rulesList = document.getElementById("rulesList");
const reportCard = document.getElementById("reportCard");
let currentReportId = null;
let showWithoutAiResult = false;
let dashboardPollTimer = null;
let lastOpenReportProcessing = null;

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

function downloadUrlCandidatesClient(item) {
  return [
    item?.sourceUrl,
    item?.finalUrl,
    item?.referrerUrl,
    item?.siteUrl,
    item?.pageUrl,
    ...safeArray(item?.urlChain)
  ].filter(Boolean);
}

function isOfficialDiscordInstallerOrUpdateClient(item) {
  const name = String(
    item?.fileName ||
    item?.targetPath ||
    ""
  ).split(/[\\/]/).at(-1)?.toLowerCase() || "";

  const target = String(
    item?.targetPath ||
    item?.currentPath ||
    ""
  )
    .replaceAll("/", "\\")
    .toLowerCase();

  if (
    target.includes("\\appdata\\local\\discord\\") &&
    ["update.exe", "discord.exe", "discordsetup.exe", "squirrel.exe"].includes(name)
  ) {
    return true;
  }

  return downloadUrlCandidatesClient(item).some((value) => {
    try {
      const url = new URL(String(value || ""));
      const host = url.hostname.toLowerCase();
      const pathname = url.pathname.toLowerCase();

      const officialHost =
        host === "discord.com" ||
        host === "www.discord.com" ||
        host === "discordapp.com" ||
        host === "www.discordapp.com" ||
        host === "dl.discordapp.net" ||
        host === "stable.dl2.discordapp.net";

      return officialHost && (
        pathname.includes("/api/download") ||
        pathname.includes("/apps/") ||
        pathname.includes("/download")
      );
    } catch {
      return false;
    }
  });
}

function isDiscordAttachmentDownloadClient(item) {
  if (isOfficialDiscordInstallerOrUpdateClient(item))
    return false;

  return downloadUrlCandidatesClient(item).some((value) => {
    try {
      const url = new URL(String(value || ""));
      const host = url.hostname.toLowerCase();
      const pathname = url.pathname.toLowerCase();

      return (
        (
          host === "cdn.discordapp.com" ||
          host === "media.discordapp.net" ||
          host.endsWith(".discordattachments.com")
        ) &&
        (
          pathname.includes("/attachments/") ||
          host.endsWith(".discordattachments.com")
        )
      );
    } catch {
      return false;
    }
  });
}

function downloadOriginKind(item) {
  const urls = [
    item?.sourceUrl,
    item?.finalUrl,
    item?.referrerUrl,
    item?.siteUrl,
    item?.pageUrl,
    ...safeArray(item?.urlChain)
  ].filter(Boolean).map((value) => String(value).toLowerCase());

  const joined = urls.join(" ");

  if (
    joined.includes("discord.com/") ||
    joined.includes("discord.gg/") ||
    joined.includes("discordapp.com/") ||
    joined.includes("cdn.discordapp.com/") ||
    joined.includes("media.discordapp.net/") ||
    joined.includes("discordattachments.com/")
  ) {
    return "Discord";
  }

  if (
    joined.includes("t.me/") ||
    joined.includes("telegram.me/") ||
    joined.includes("telegram.org/") ||
    joined.includes("web.telegram.org/") ||
    joined.includes("telegram-cdn.org/") ||
    joined.includes("cdn-telegram.org/")
  ) {
    return "Telegram";
  }

  return "";
}

function browserDangerInfo(value) {
  const code = Number(value ?? 0);
  const map = {
    1: ["Arquivo perigoso", "high"],
    2: ["URL perigosa", "high"],
    3: ["Conteúdo perigoso", "high"],
    4: ["Conteúdo possivelmente perigoso", "medium"],
    5: ["Download incomum", "medium"],
    6: ["Alerta validado/ignorado pelo usuário", "medium"],
    7: ["Host perigoso", "high"],
    8: ["Software potencialmente indesejado", "high"],
    16: ["Deep Scan: perigoso", "high"],
    19: ["Risco de comprometimento de conta", "high"],
  };

  const hit = map[code];
  return hit
    ? { code, label: hit[0], severity: hit[1], suspicious: true }
    : { code, label: code ? "DangerType " + code : "Sem alerta", severity: "info", suspicious: false };
}

function isDeceptiveDoubleExtension(value) {
  return /\.(zip|rar|7z|pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx|ppt|pptx)\.exe$/i
    .test(String(value || ""));
}

function isRiskyDownloadName(value) {
  const name = String(value || "");
  return /\.(exe|com|scr|dll|msi|bat|cmd|ps1|zip|rar|7z)$/i.test(name) ||
    isDeceptiveDoubleExtension(name);
}

function looksRandomExecutableNameClient(value) {
  const name = String(value || "").split(/[\\/]/).at(-1) || "";
  if (!/\.exe$/i.test(name)) return false;

  let stem = name.replace(/\.exe$/i, "");
  stem = stem.replace(/\.(zip|rar|7z|pdf|jpg|jpeg|png|txt)$/i, "");

  if (stem.length < 4 || stem.length > 28 || !/^[a-z0-9]+$/i.test(stem))
    return false;

  const chars = [...stem];
  const letters = chars.filter((ch) => /[a-z]/i.test(ch));
  const digits = chars.filter((ch) => /[0-9]/.test(ch));
  const vowels = letters.filter((ch) => /[aeiou]/i.test(ch));
  const distinct = new Set(stem.toUpperCase()).size;
  const allUpperOrDigits = /^[A-Z0-9]+$/.test(stem);
  const vowelRatio = letters.length ? vowels.length / letters.length : 0;

  if (stem.length <= 5) {
    return allUpperOrDigits &&
      distinct >= Math.max(4, stem.length - 1) &&
      (digits.length >= 1 || vowels.length === 0) &&
      vowelRatio <= 0.25;
  }

  return (
    (
      allUpperOrDigits &&
      distinct >= Math.min(6, stem.length - 1) &&
      vowelRatio <= 0.35 &&
      (digits.length >= 1 || letters.length >= 5)
    ) ||
    (
      stem.length >= 8 &&
      stem.length <= 18 &&
      digits.length === 0 &&
      letters.length === stem.length &&
      distinct >= 7 &&
      vowelRatio <= 0.22
    ) ||
    (
      stem.length >= 10 &&
      letters.length >= 6 &&
      digits.length >= 2 &&
      distinct >= 8
    )
  );
}

async function openReportSafe(id, options = {}) {
  try {
    if (options.resetAiView !== false)
      showWithoutAiResult = false;

    await openReport(id);
  } catch (error) {
    console.error("Falha ao abrir relatório", error);
    alert("Erro ao abrir relatório: " + (error?.message || "erro desconhecido"));
  }
}

function processingStageLabel(stage, status) {
  const map = {
    waiting: "Aguardando cliente",
    collecting: "Coletando evidências",
    preparing: "Preparando análise",
    normal_filter: "Aplicando filtro técnico",
    ai_filter: "Filtrando falsos positivos com Gemini",
    finalizing: "Preparando resultado final",
    completed: "Concluído com Gemini",
    needs_ai: "Pendente de filtro Gemini",
    ai_error: "Gemini indisponível · resultado técnico",
  };

  return map[stage] || statusLabel(status);
}

function processingStageTag(stage, status) {
  if (stage === "completed") return "low";
  if (stage === "needs_ai") return "medium";
  if (stage === "ai_error") return "high";
  if (stage === "ai_filter") return "medium";
  if (
    ["collecting", "preparing", "normal_filter", "finalizing"]
      .includes(stage)
  ) {
    return "info";
  }

  if (status === "completed") return "low";
  if (status === "waiting") return "medium";
  return "info";
}

function isProcessingStage(stage) {
  return [
    "collecting",
    "preparing",
    "normal_filter",
    "ai_filter",
    "finalizing",
  ].includes(String(stage || ""));
}

function updateAnalysisProcessingBanner(status) {
  const banner = document.getElementById("analysisProcessingBanner");
  if (!banner) return;

  const stage = status?.processingStage || status?.processing_stage || "waiting";
  const message =
    status?.processingMessage ||
    status?.processing_message ||
    processingStageLabel(stage, status?.status);

  if (showWithoutAiResult) {
    banner.className = "message";
    banner.textContent =
      "Visualizando o resultado técnico SEM o filtro do Gemini. " +
      (isProcessingStage(stage) ? message : "");
    return;
  }

  if (isProcessingStage(stage)) {
    banner.className = "message";
    banner.textContent = message;
    return;
  }

  if (stage === "needs_ai") {
    banner.className = "message";
    banner.textContent =
      message ||
      "Esta análise ainda não passou pela segunda camada Gemini. Use Recalcular com Gemini.";
    return;
  }

  if (stage === "ai_error") {
    banner.className = "message error";
    banner.textContent =
      message ||
      "A revisão pelo Gemini não foi concluída. O resultado técnico continua disponível.";
    return;
  }

  if (stage === "completed") {
    banner.className = "message ok";
    banner.textContent =
      message ||
      "Análise concluída. O resultado abaixo já passou pelo filtro do Gemini.";
    return;
  }

  banner.className = "message hidden";
  banner.textContent = "";
}

async function pollAdminProgress() {
  if (dashboardView.classList.contains("hidden"))
    return;

  try {
    await loadAnalyses();

    if (!currentReportId)
      return;

    const status = await api(
      "/api/admin/analyses/" +
      encodeURIComponent(currentReportId) +
      "/rebuild-status"
    );

    updateAnalysisProcessingBanner(status);

    if (
      lastOpenReportProcessing === true &&
      status.processing === false
    ) {
      await openReport(currentReportId);
    }

    lastOpenReportProcessing = status.processing === true;
  } catch (error) {
    console.debug("Polling do painel temporariamente indisponível", error);
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

  document.getElementById("adminMainNav")?.classList.toggle("hidden", !logged);
  document.getElementById("adminReadyState")?.classList.toggle("hidden", !logged);
  document.getElementById("refreshBtn")?.classList.toggle("hidden", !logged);

  if (logged && !dashboardPollTimer) {
    dashboardPollTimer =
      setInterval(
        () => pollAdminProgress(),
        4000
      );
  }

  if (!logged && dashboardPollTimer) {
    clearInterval(dashboardPollTimer);
    dashboardPollTimer = null;
  }
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
  document.getElementById("reportEmptyState")?.classList.remove("hidden");
  currentReportId = null;
  showWithoutAiResult = false;
  lastOpenReportProcessing = null;
});

document.getElementById("toggleAiViewBtn").addEventListener("click", async () => {
  if (!currentReportId) return;

  showWithoutAiResult =
    !showWithoutAiResult;

  await openReport(currentReportId);
});

document.getElementById("rebuildFindingsBtn").addEventListener("click", async () => {
  if (!currentReportId) return;

  const button = document.getElementById("rebuildFindingsBtn");
  const original = button.textContent;
  const analysisId = currentReportId;

  try {
    button.disabled = true;
    button.textContent = "Iniciando...";

    await api(
      "/api/admin/analyses/" + encodeURIComponent(analysisId) + "/rebuild",
      { method: "POST" }
    );

    const startedAt = Date.now();
    const timeoutMs = 5 * 60 * 1000;

    while (Date.now() - startedAt < timeoutMs) {
      button.textContent = "Recalculando + Gemini...";

      const status = await api(
        "/api/admin/analyses/" +
        encodeURIComponent(analysisId) +
        "/rebuild-status"
      );

      if (!status.processing) {
        await loadAnalyses();
        await openReport(analysisId);

        if (status.aiReviewStatus === "error") {
          alert(
            "O filtro normal foi recalculado, mas a revisão pelo Gemini encontrou um erro. " +
            (status.aiReviewError || "O resultado normal foi mantido.")
          );
        }

        return;
      }

      await new Promise((resolve) => setTimeout(resolve, 2200));
    }

    throw new Error(
      "O recálculo continua sendo processado no servidor. Aguarde alguns instantes e abra o relatório novamente."
    );
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

    const stage =
      item.processing_stage || "waiting";

    const stageLabel =
      processingStageLabel(
        stage,
        item.status
      );

    const stageClass =
      processingStageTag(
        stage,
        item.status
      );

    const stageMessage =
      item.processing_message
        ? '<br><small class="muted">' +
          escapeHtml(item.processing_message) +
          '</small>'
        : "";

    const sessionKind =
      Number(item.high_findings || 0) > 0
        ? "critical"
        : Number(item.total_findings || 0) > 0
          ? "review"
          : item.status === "completed"
            ? "clean"
            : "review";

    row.dataset.sessionKind = sessionKind;
    row.dataset.searchText = [
      item.id,
      item.label,
      item.machine_name,
      item.status,
      stageLabel
    ].filter(Boolean).join(" ").toLowerCase();

    const resultTag =
      sessionKind === "critical"
        ? '<span class="tag high">CRÍTICO</span>'
        : sessionKind === "review"
          ? '<span class="tag medium">REVISAR</span>'
          : '<span class="tag low">LIMPO</span>';

    row.innerHTML = `
      <td><span class="session-check"></span></td>
      <td><code>VKN-${escapeHtml(String(item.id).padStart(6, "0"))}</code></td>
      <td>
        <strong>${escapeHtml(item.label)}</strong><br>
        <small class="muted">${escapeHtml(item.machine_name || "Aguardando PC")}</small>
      </td>
      <td>${escapeHtml(formatDate(item.created_at))}</td>
      <td>
        ${item.status === "completed" ? resultTag : '<span class="tag ' + escapeHtml(stageClass) + '">' + escapeHtml(stageLabel) + '</span>'}
        ${item.status === "completed" ? '<br><small class="muted">' + Number(item.total_findings || 0) + ' achados</small>' : stageMessage}
      </td>
      <td><button class="button ghost open-report" data-id="${item.id}" aria-label="Abrir relatório">›</button></td>
    `;

    analysesBody.appendChild(row);
  }

  document.querySelectorAll(".open-report").forEach((button) => {
    button.addEventListener("click", async () => {
      document.querySelectorAll("#analysesBody tr").forEach((row) =>
        row.classList.remove("active-session")
      );
      button.closest("tr")?.classList.add("active-session");
      await openReportSafe(button.dataset.id);
    });
  });

  applySessionFilters();
}

async function openReport(id) {
  currentReportId = id;

  const data = await api("/api/admin/analyses/" + encodeURIComponent(id));
  const analysis = data.analysis || {};
  const report = data.report || null;
  const aiFilteredFindings = safeArray(data.aiFilteredFindings);
  const postAiFindings = safeArray(data.findings);
  const findings = showWithoutAiResult
    ? [
        ...postAiFindings,
        ...aiFilteredFindings.filter(
          (item) => !postAiFindings.some(
            (base) => String(base.id) === String(item.id)
          )
        ),
      ]
    : postAiFindings;
  const aiReview = data.aiReview || {};
  const relatedAnalyses = safeArray(data.relatedAnalyses);
  const payload = report?.payload && typeof report.payload === "object"
    ? report.payload
    : {};

  // Abre o cartão antes de montar as seções pesadas. Assim um erro em uma
  // seção específica não faz o botão parecer que "não funciona".
  reportCard.classList.remove("hidden");
  document.getElementById("reportEmptyState")?.classList.add("hidden");

  document.getElementById("reportTitle").textContent =
    "#" + analysis.id + " · " + analysis.label;

  const toggleAiViewBtn =
    document.getElementById("toggleAiViewBtn");

  toggleAiViewBtn.textContent =
    showWithoutAiResult
      ? "Ver resultado com Gemini"
      : "Ver resultado sem Gemini";

  updateAnalysisProcessingBanner({
    status: analysis.status,
    processingStage: analysis.processing_stage,
    processingMessage: analysis.processing_message,
  });

  lastOpenReportProcessing =
    isProcessingStage(
      analysis.processing_stage
    );

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
    peInspections: safeArray(payload.peInspections),
    zoneIdentifiers: safeArray(payload.zoneIdentifiers),
    alternateDataStreams: safeArray(payload.alternateDataStreams),
    autorunIntegrity: safeArray(payload.autorunIntegrity),
    processModuleIntegrity: safeArray(payload.processModuleIntegrity),
    processMemoryIntegrity: safeArray(payload.processMemoryIntegrity),
    protectedWindows: safeArray(payload.protectedWindows),
    bam: safeArray(payload.bam),
    userAssist: safeArray(payload.userAssist),
    muiCache: safeArray(payload.muiCache),
    pca: safeArray(payload.pca),
    amcache: safeArray(payload.amcache),
    shimCache: safeArray(payload.shimCache),
    setupApiUsb: safeArray(payload.setupApiUsb),
    powerShellHits: safeArray(payload.powerShellHits),
    powerShellArtifacts: safeArray(payload.powerShellArtifacts),
    prefetchIntegrity: safeArray(payload.prefetchIntegrity),
    hiddenVolumes: safeArray(payload.hiddenVolumes),
    logClearSignals: safeArray(payload.logClearSignals),
    processCreationEvents: safeArray(payload.processCreationEvents),
    defenderDetections: safeArray(payload.defenderDetections),
    recentShortcuts: safeArray(payload.recentShortcuts),
    crashArtifacts: safeArray(payload.crashArtifacts),
    securityProducts: safeArray(payload.securityProducts),
    recycleBin: safeArray(payload.recycleBin),
    browserDownloads: safeArray(payload.browserDownloads),
    browserHistorySignals: safeArray(payload.browserHistorySignals),
    browserRecoveredArtifacts: safeArray(payload.browserRecoveredArtifacts),
    networkIndicators: safeArray(payload.networkIndicators),
    deletedUsnRecords: safeArray(payload.deletedUsnRecords),
    extensionMismatches: safeArray(payload.extensionMismatches),
    defenderExclusions: safeArray(payload.defenderExclusions),
    bootIntegrity: safeArray(payload.bootIntegrity),
    systemTimeChanges: safeArray(payload.systemTimeChanges),
    virtualDisks: safeArray(payload.virtualDisks),
    rustModules: safeArray(payload.rustModules),
    usnJournalState: safeArray(payload.usnJournalState),
    usnActivity: safeArray(payload.usnActivity),
    systemIntegrityExpansion: safeArray(payload.systemIntegrityExpansion),
  };

  const disconnectedUsb =
    arrays.usbHistory.filter((item) => item.present === false).length;

  const criticalFindings =
    findings
      .filter((item) => ["critical", "high"].includes(item.severity))
      .sort((a, b) => {
        const aPriority = a.evidence?.priorityMaximum === true ? 1 : 0;
        const bPriority = b.evidence?.priorityMaximum === true ? 1 : 0;

        if (aPriority !== bPriority)
          return bPriority - aPriority;

        const rank = { critical: 2, high: 1 };
        return (rank[b.severity] || 0) - (rank[a.severity] || 0);
      });

  const mediumFindings =
    findings.filter((item) => item.severity === "medium");

  const infoFindings =
    findings.filter((item) => ["low", "info"].includes(item.severity));

  const hardwareCount =
    disconnectedUsb +
    Number(payload.hardwareSummary?.totalRelevantDevices ?? arrays.serialDevices.length);

  const advancedForensicsCount =
    arrays.peInspections.length +
    arrays.zoneIdentifiers.length +
    arrays.alternateDataStreams.length +
    arrays.autorunIntegrity.filter((x) => x.suspicious === true).length +
    arrays.processModuleIntegrity.filter((x) => x.suspicious === true).length +
    arrays.processMemoryIntegrity.length +
    arrays.protectedWindows.length +
    arrays.powerShellArtifacts.length +
    arrays.crashArtifacts.length +
    arrays.securityProducts.length +
    arrays.networkIndicators.length +
    arrays.usnActivity.length +
    arrays.systemIntegrityExpansion.length;

  const informationalCount =
    infoFindings.length +
    arrays.files.length +
    arrays.browserDownloads.length +
    arrays.recycleBin.length +
    arrays.browserRecoveredArtifacts.length +
    arrays.deletedUsnRecords.length;

  const currentStageLabel =
    processingStageLabel(
      analysis.processing_stage,
      analysis.status
    );

  document.getElementById("reportMetrics").innerHTML = `
    <div class="metric"><small>STATUS</small><strong>${escapeHtml(currentStageLabel)}</strong></div>
    <div class="metric"><small>VISUALIZAÇÃO</small><strong>${showWithoutAiResult ? "SEM GEMINI" : aiReview.status === "completed" ? "COM GEMINI" : aiReview.status === "partial_error" ? "GEMINI PARCIAL" : "TÉCNICO"}</strong><span>${showWithoutAiResult ? "Filtro técnico original" : aiReview.status === "completed" ? "Resultado final filtrado" : aiReview.status === "partial_error" ? "Filtro parcial; revise o aviso" : "Gemini ainda não concluiu"}</span></div>
    <div class="metric danger-metric"><small>VERMELHO · CRÍTICO/ALTO</small><strong>${criticalFindings.length}</strong><span>${showWithoutAiResult ? "Filtro técnico original" : aiReview.status === "completed" ? "Resultado final pós-Gemini" : aiReview.status === "partial_error" ? "Resultado parcialmente revisado" : "Resultado técnico atual"}</span></div>
    <div class="metric warning-metric"><small>AMARELO · REVISAR</small><strong>${mediumFindings.length}</strong><span>${showWithoutAiResult ? "Filtro técnico original" : aiReview.status === "completed" ? "Resultado final pós-Gemini" : aiReview.status === "partial_error" ? "Resultado parcialmente revisado" : "Resultado técnico atual"}</span></div>
    <div class="metric info-metric"><small>GEMINI FILTROU</small><strong>${aiFilteredFindings.length}</strong><span>Prováveis falsos positivos</span></div>
    <div class="metric hardware-metric"><small>HARDWARE / USB</small><strong>${hardwareCount}</strong><span>Pendrives e placas separados</span></div>
    <div class="metric priority-metric"><small>ARQUIVOS PRIORITÁRIOS</small><strong id="summaryPriorityCount">0</strong><span>EXE/ZIP/RAR/7Z suspeitos</span></div>
    <div class="metric"><small>MÓDULOS FORENSES</small><strong>${advancedForensicsCount}</strong><span>PE · USN · rede · PowerShell · WER</span></div>
    <div class="metric info-metric"><small>AZUL · INVENTÁRIO</small><strong>${informationalCount}</strong><span>Oculto até você abrir</span></div>
  `;

  const resultFinalLabel = document.getElementById("resultFinalLabel");
  if (resultFinalLabel) {
    resultFinalLabel.textContent =
      criticalFindings.length > 0
        ? "Indícios de trapaça"
        : mediumFindings.length > 0
          ? "Revisão necessária"
          : "Sem indício crítico";
    resultFinalLabel.style.color =
      criticalFindings.length > 0
        ? "#ff5769"
        : mediumFindings.length > 0
          ? "#f4b72c"
          : "#2bf0c9";
  }

  const sideStatsMirror = document.getElementById("sideStatsMirror");
  if (sideStatsMirror) {
    sideStatsMirror.innerHTML =
      '<div>◈ <strong>' + findings.length + '</strong> evidências classificadas</div>' +
      '<div>◈ <strong>' + criticalFindings.length + '</strong> itens críticos / altos</div>' +
      '<div>◈ <strong>' + mediumFindings.length + '</strong> itens para revisão</div>' +
      '<div>◈ <strong>' + hardwareCount + '</strong> itens de hardware / USB</div>' +
      '<div>◈ <strong>' + advancedForensicsCount + '</strong> sinais forenses</div>';
  }

  document.getElementById("criticalCountBadge").textContent = criticalFindings.length;
  document.getElementById("mediumCountBadge").textContent = mediumFindings.length;
  document.getElementById("hardwareCountBadge").textContent = hardwareCount;
  document.getElementById("infoCountBadge").textContent = informationalCount;

  const aiStatusLabel = {
    completed: "Concluída",
    running: "Em andamento",
    partial_error: "Parcial · alguns lotes falharam",
    disabled: "Desativada",
    not_configured: "Não configurada",
    error: "Falhou · usando filtro normal",
    pending: "Pendente",
  }[aiReview.status] || aiReview.status || "Pendente";

  document.getElementById("reportMeta").innerHTML = `
    <div class="kv"><span>Computador</span><span>${escapeHtml(analysis.machine_name || "—")}</span></div>
    <div class="kv"><span>Sistema</span><span>${escapeHtml(analysis.os_version || "—")}</span></div>
    <div class="kv"><span>Agente</span><span>${escapeHtml(analysis.agent_version || "—")}</span></div>
    <div class="kv"><span>Filtro Gemini</span><span>${escapeHtml(aiStatusLabel)}</span></div>
    <div class="kv"><span>Modelo Gemini</span><span>${escapeHtml(aiReview.model || "—")}</span></div>
    <div class="kv"><span>Revisão Gemini</span><span>${escapeHtml(formatDate(aiReview.reviewedAt))}</span></div>
    <div class="kv"><span>Início</span><span>${escapeHtml(formatDate(analysis.started_at))}</span></div>
    <div class="kv"><span>Conclusão</span><span>${escapeHtml(formatDate(analysis.finished_at))}</span></div>
  `;

  const renderFindings = (elementId, rows, emptyMessage) => {
    const target = document.getElementById(elementId);
    target.innerHTML = "";

    if (!rows.length) {
      target.innerHTML = '<div class="message ok">' + escapeHtml(emptyMessage) + '</div>';
      return;
    }

    for (const finding of rows) {
      const element = document.createElement("article");
      element.className = "finding severity-card " + escapeHtml(finding.severity || "info");

      const evidence = finding.evidence || {};
      const ai = finding.ai_review || null;
      const filteredByAi =
        !showWithoutAiResult &&
        ai?.verdict === "likely_false_positive";
      const displaySeverity =
        filteredByAi
          ? "info"
          : (finding.severity || "info");
      element.className = "finding severity-card " + escapeHtml(displaySeverity);

      const catalogName = evidence.catalogMatch?.name
        ? '<div class="kv"><span>Catálogo</span><span>' + escapeHtml(evidence.catalogMatch.name) + '</span></div>'
        : "";

      const aiLabel = ai
        ? ai.verdict === "likely_cheat"
          ? "GEMINI CONFIRMOU"
          : ai.verdict === "likely_false_positive"
            ? "GEMINI FILTROU"
            : "GEMINI · REVISAR"
        : "";

      const aiBlock = evidence.priorityMaximum === true ||
        evidence.protectedByTechnicalEngine === true
        ? '<div class="kv"><span>Motor técnico</span><span>PROTEGIDO · execução/evidência forte confirmada · Gemini não pode remover nem rebaixar</span></div>'
        : ai
          ? '<div class="kv"><span>' + escapeHtml(aiLabel) + '</span><span>' +
              escapeHtml(ai.reason || "Sem justificativa.") +
            '</span></div>'
          : '<div class="kv"><span>Revisão</span><span>Revisão necessária / aguardando Gemini</span></div>';

      element.innerHTML = `
        <div class="finding-head">
          <h4>${escapeHtml(finding.title)}</h4>
          <span class="tag ${escapeHtml(displaySeverity)}">${escapeHtml(filteredByAi ? "FILTRADO GEMINI" : severityLabel(finding.severity))}</span>
        </div>
        <code>${escapeHtml(finding.artifact_value)}</code>
        ${catalogName}
        ${aiBlock}
        ${evidence.note ? '<div class="kv"><span>Motivo</span><span>' + escapeHtml(evidence.note) + '</span></div>' : ""}
        <details class="evidence-details">
          <summary>Ver evidência completa</summary>
          <pre>${escapeHtml(JSON.stringify(evidence, null, 2))}</pre>
        </details>
      `;

      target.appendChild(element);
    }
  };

  renderFindings(
    "criticalFindingsList",
    criticalFindings,
    "Nenhum achado crítico ou alto."
  );

  renderFindings(
    "mediumFindingsList",
    mediumFindings,
    "Nenhum achado médio."
  );

  renderFindings(
    "infoFindingsList",
    infoFindings,
    "Nenhum achado informativo/baixo."
  );

  document.getElementById("aiFilteredCountBadge").textContent =
    aiFilteredFindings.length;

  const aiStatusBox = document.getElementById("aiReviewStatus");
  aiStatusBox.className =
    "message " +
    (aiReview.status === "completed"
      ? "ok"
      : aiReview.status === "error"
        ? "error"
        : "");

  aiStatusBox.textContent =
    showWithoutAiResult
      ? "Modo sem Gemini ativo: a lista principal mostra o resultado original do filtro técnico."
      : aiReview.status === "completed"
        ? "Segunda camada concluída. A lista principal já está filtrada pelo Gemini."
        : aiReview.status === "partial_error"
          ? "O Gemini revisou parte dos achados, mas alguns lotes falharam. Os itens não revisados continuam visíveis."
          : aiReview.status === "error"
            ? "A revisão pelo Gemini falhou nesta análise. O Vorken manteve o resultado do filtro normal."
            : aiReview.status === "disabled"
              ? "Filtro Gemini desativado. Resultado exibido somente pelo motor normal."
              : aiReview.status === "not_configured"
                ? "Filtro Gemini ainda não está configurado no servidor."
                : "Revisão pelo Gemini pendente ou em andamento.";

  renderFindings(
    "aiFilteredFindingsList",
    aiFilteredFindings,
    "O Gemini não removeu nenhum provável falso positivo desta análise."
  );

  const unknownAppFindings = findings.filter((item) =>
    item.artifact_type === "unknown_app"
  );

  document.getElementById("unknownAppsCountBadge").textContent =
    unknownAppFindings.length;

  renderFindings(
    "unknownAppsList",
    unknownAppFindings,
    "Nenhum aplicativo desconhecido ou aplicativo conhecido com assinatura/origem inválida."
  );

  const recoveredHistoryFindings = findings.filter((item) =>
    item.artifact_type === "browser_recovery"
  );

  document.getElementById("recoveredHistoryCountBadge").textContent =
    recoveredHistoryFindings.length;

  renderFindings(
    "recoveredHistoryList",
    recoveredHistoryFindings,
    "Nenhum vestígio recuperado passou pelos filtros de relevância."
  );

  const deletedUsnFindings = findings.filter((item) =>
    item.artifact_type === "usn_delete"
  );

  document.getElementById("deletedUsnCountBadge").textContent =
    deletedUsnFindings.length;

  renderFindings(
    "deletedUsnList",
    deletedUsnFindings,
    "Nenhum arquivo apagado passou pelos filtros de relevância do USN."
  );

  document.getElementById("advancedForensicsCountBadge").textContent =
    advancedForensicsCount;

  document.getElementById("advancedForensicsSummary").innerHTML = `
    <div class="metric"><small>PE / PACKERS</small><strong>${arrays.peInspections.length}</strong></div>
    <div class="metric"><small>ZONE.IDENTIFIER</small><strong>${arrays.zoneIdentifiers.length}</strong></div>
    <div class="metric"><small>POWERSHELL</small><strong>${arrays.powerShellArtifacts.length}</strong></div>
    <div class="metric"><small>AUTORUNS SUSPEITOS</small><strong>${arrays.autorunIntegrity.filter((x) => x.suspicious === true).length}</strong></div>
    <div class="metric"><small>ADS</small><strong>${arrays.alternateDataStreams.length}</strong></div>
    <div class="metric"><small>DLL / MÓDULOS</small><strong>${arrays.processModuleIntegrity.length}</strong></div>
    <div class="metric"><small>MEMÓRIA PRIVADA EXEC</small><strong>${arrays.processMemoryIntegrity.length}</strong></div>
    <div class="metric"><small>STREAMPROOF</small><strong>${arrays.protectedWindows.length}</strong></div>
    <div class="metric"><small>REDE / DNS</small><strong>${arrays.networkIndicators.length}</strong></div>
    <div class="metric"><small>JOURNALTRACE</small><strong>${arrays.usnActivity.length}</strong></div>
    <div class="metric"><small>WER / CRASH</small><strong>${arrays.crashArtifacts.length}</strong></div>
    <div class="metric"><small>ANTIVÍRUS / FIREWALL</small><strong>${arrays.securityProducts.length}</strong></div>
    <div class="metric"><small>INTEGRIDADE WINDOWS</small><strong>${arrays.systemIntegrityExpansion.length}</strong></div>
  `;

  const compactJson = (value) =>
    escapeHtml(JSON.stringify(value, null, 2));

  const advancedGroup = (title, rows, mapper, emptyText = "Nenhum registro.") => `
    <details class="evidence-details">
      <summary>${escapeHtml(title)} · ${rows.length}</summary>
      <div>
        ${rows.length
          ? rows.slice(0, 400).map(mapper).join("")
          : '<div class="message ok">' + escapeHtml(emptyText) + '</div>'}
      </div>
    </details>
  `;

  const advancedHtml = [];

  advancedHtml.push(
    advancedGroup(
      "PE / entropia / packers",
      arrays.peInspections.filter((x) =>
        x.packedLike === true ||
        x.highEntropy === true ||
        x.randomLikeName === true ||
        safeArray(x.suspiciousApis).length > 0),
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.name || "PE")}</h4><span class="tag ${item.randomLikeName ? "critical" : "info"}">${item.randomLikeName ? "ALEATÓRIO" : item.packedLike ? "PACKER · INVENTÁRIO" : item.highEntropy ? "ENTROPIA · INVENTÁRIO" : "PE · INVENTÁRIO"}</span></div>
          <code>${escapeHtml(item.path || "—")}</code>
          <div class="kv"><span>Entropia</span><span>${escapeHtml(item.entropy ?? "—")}</span></div>
          <div class="kv"><span>Assinado</span><span>${item.signed ? "Sim" : "Não"}</span></div>
          <div class="kv"><span>Packers</span><span>${escapeHtml(safeArray(item.packerIndicators).join(", ") || "—")}</span></div>
          <div class="kv"><span>APIs</span><span>${escapeHtml(safeArray(item.suspiciousApis).join(", ") || "—")}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Origem de arquivos / Zone.Identifier",
      arrays.zoneIdentifiers.filter((x) => x.hostUrl || x.referrerUrl),
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.fileName || "Arquivo")}</h4><span class="tag info">ZONE ${escapeHtml(item.zoneId ?? "—")}</span></div>
          <code>${escapeHtml(item.path || "—")}</code>
          <div class="kv"><span>HostUrl</span><span>${escapeHtml(item.hostUrl || "—")}</span></div>
          <div class="kv"><span>Referrer</span><span>${escapeHtml(item.referrerUrl || "—")}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "PowerShell / PSReadLine / eventos",
      arrays.powerShellArtifacts,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.source || "PowerShell")}</h4><span class="tag info">POWERSHELL · INVENTÁRIO</span></div>
          <code>${escapeHtml(item.command || "—")}</code>
          <div class="kv"><span>Indicadores</span><span>${escapeHtml(safeArray(item.matchedIndicators).join(", ") || "—")}</span></div>
          <div class="kv"><span>Data</span><span>${escapeHtml(formatDate(item.timestampUtc))}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Autoruns / tarefas agendadas",
      arrays.autorunIntegrity.filter((x) => x.suspicious === true),
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.name || item.source || "Autorun")}</h4><span class="tag ${item.fileExists && !item.signed ? "high" : "medium"}">AUTORUN</span></div>
          <code>${escapeHtml(item.command || item.executablePath || "—")}</code>
          <div class="kv"><span>Fonte</span><span>${escapeHtml(item.source || "—")}</span></div>
          <div class="kv"><span>Assinado</span><span>${item.signed ? "Sim" : "Não"}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Alternate Data Streams",
      arrays.alternateDataStreams,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.streamName || "ADS")}</h4><span class="tag ${item.suspicious ? "high" : "info"}">ADS</span></div>
          <code>${escapeHtml(item.path || "—")}</code>
          <div class="kv"><span>Tamanho</span><span>${escapeHtml(item.streamSize ?? 0)} bytes</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "DLLs / módulos em processos críticos",
      arrays.processModuleIntegrity.filter((x) => x.suspicious === true),
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml((item.processName || "processo") + " → " + (item.moduleName || "módulo"))}</h4><span class="tag high">DLL</span></div>
          <code>${escapeHtml(item.modulePath || "—")}</code>
          <div class="kv"><span>Assinado</span><span>${item.moduleSigned ? "Sim" : "Não"}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Memória executável privada / manual-map",
      arrays.processMemoryIntegrity,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.processName || "Processo")}</h4><span class="tag ${item.potentialManualMap ? "critical" : "info"}">${item.potentialManualMap ? "POSSÍVEL MANUAL MAP" : "MEM_PRIVATE EXEC"}</span></div>
          <code>${escapeHtml((item.baseAddress || "—") + " · " + (item.regionSize || 0) + " bytes")}</code>
          <div class="kv"><span>Processo</span><span>${escapeHtml(item.processPath || "—")}</span></div>
          <div class="kv"><span>Cabeçalho MZ</span><span>${item.mzHeader ? "SIM" : "Não"}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Janelas protegidas / streamproof",
      arrays.protectedWindows,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.processName || "Processo")}</h4><span class="tag ${item.signed ? "medium" : "high"}">CAPTURE EXCLUSION</span></div>
          <code>${escapeHtml(item.processPath || "—")}</code>
          <div class="kv"><span>Classe</span><span>${escapeHtml(item.windowClass || "—")}</span></div>
          <div class="kv"><span>Assinado</span><span>${item.signed ? "Sim" : "Não"}</span></div>
        </div>
      `
    )
  );

  const networkInteresting = arrays.networkIndicators.filter((x) =>
    safeArray(x.matchedIndicators).length > 0 ||
    (x.source === "TCP" && x.processSigned === false && x.processPath)
  );

  advancedHtml.push(
    advancedGroup(
      "Rede / DNS / conexões",
      networkInteresting,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.domain || item.processName || item.remoteAddress || "Rede")}</h4><span class="tag ${safeArray(item.matchedIndicators).length ? "high" : "medium"}">${escapeHtml(item.source || "REDE")}</span></div>
          <div class="kv"><span>Processo</span><span>${escapeHtml(item.processPath || item.processName || "—")}</span></div>
          <div class="kv"><span>Destino</span><span>${escapeHtml(item.domain || ((item.remoteAddress || "—") + ":" + (item.remotePort || "")))}</span></div>
          <div class="kv"><span>Indicadores</span><span>${escapeHtml(safeArray(item.matchedIndicators).join(", ") || "—")}</span></div>
        </div>
      `
    )
  );

  const usnInteresting = arrays.usnActivity.filter((x) =>
    x.deleted === true ||
    x.underPrefetchDirectory === true ||
    x.browserDatabase === true ||
    x.windowsForensicArtifact === true
  );

  advancedHtml.push(
    advancedGroup(
      "JournalTrace / USN",
      usnInteresting,
      (item) => {
        const informationalForensic =
          item.underPrefetchDirectory === true ||
          item.windowsForensicArtifact === true;

        const tagClass = informationalForensic
          ? "info"
          : item.deleted
            ? "high"
            : "info";

        const tagText = informationalForensic
          ? "INVENTÁRIO"
          : item.deleted
            ? "DELETE"
            : "USN";

        return `
          <div class="finding">
            <div class="finding-head"><h4>${escapeHtml(item.fileName || "USN")}</h4><span class="tag ${tagClass}">${tagText}</span></div>
            <div class="kv"><span>Data</span><span>${escapeHtml(formatDate(item.timestampUtc))}</span></div>
            <div class="kv"><span>Motivos</span><span>${escapeHtml(safeArray(item.reasons).join(", ") || "—")}</span></div>
            <div class="kv"><span>Volume</span><span>${escapeHtml(item.volume || "—")}</span></div>
          </div>
        `;
      }
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Windows Error Reporting / crashes",
      arrays.crashArtifacts,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.appName || item.eventType || "Crash")}</h4><span class="tag info">WER</span></div>
          <code>${escapeHtml(item.appPath || item.faultingModulePath || item.artifactPath || "—")}</code>
          <div class="kv"><span>Data</span><span>${escapeHtml(formatDate(item.timestampUtc))}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Antivírus / firewall registrados",
      arrays.securityProducts,
      (item) => `
        <div class="finding">
          <div class="finding-head"><h4>${escapeHtml(item.displayName || "Produto de segurança")}</h4><span class="tag info">${escapeHtml(item.category || "SECURITY")}</span></div>
          <div class="kv"><span>Estado</span><span>${escapeHtml(item.productState || "—")}</span></div>
        </div>
      `
    )
  );

  advancedHtml.push(
    advancedGroup(
      "Integridade do Windows / BCD / serviços / SRUM",
      arrays.systemIntegrityExpansion,
      (item) => {
        const pcaSvc =
          String(item.name || item.kind || "").toLowerCase() === "pcasvc";
        const rawSeverity =
          String(item.severityHint || "").toLowerCase();
        const tag = pcaSvc
          ? "info"
          : ["high","critical"].includes(rawSeverity)
            ? "high"
            : rawSeverity === "medium"
              ? "medium"
              : "info";

        return `
          <div class="finding">
            <div class="finding-head"><h4>${escapeHtml(item.name || item.kind || "Integridade")}</h4><span class="tag ${tag}">${escapeHtml(pcaSvc ? "WINDOWS · INFO" : String(item.kind || "INTEGRITY").toUpperCase())}</span></div>
            <code>${escapeHtml(item.detail || "—")}</code>
            <div class="kv"><span>Data</span><span>${escapeHtml(formatDate(item.timestampUtc))}</span></div>
          </div>
        `;
      }
    )
  );

  document.getElementById("advancedForensicsList").innerHTML =
    advancedHtml.join("");

  document.getElementById("artifactSummary").innerHTML = `
    <div class="kv"><span>USB conectados</span><span>${arrays.usbCurrent.length}</span></div>
    <div class="kv"><span>USB no histórico</span><span>${arrays.usbHistory.length} (${disconnectedUsb} desconectados)</span></div>
    <div class="kv"><span>Eventos USB</span><span>${arrays.usbTimeline.length}</span></div>
    <div class="kv"><span>Placas / Serial</span><span>${payload.hardwareSummary?.totalRelevantDevices ?? arrays.serialDevices.length}</span></div>
    <div class="kv"><span>Arduino</span><span>${payload.hardwareSummary?.arduinoCount ?? 0}</span></div>
    <div class="kv"><span>MAKCU / Moku</span><span>${payload.hardwareSummary?.makcuCount ?? 0}</span></div>
    <div class="kv"><span>Execuções Prefetch</span><span>${arrays.prefetchExecutions.length}</span></div>
    <div class="kv"><span>Arquivos analisados</span><span>${arrays.files.length}</span></div>
    <div class="kv"><span>PE / packers</span><span>${arrays.peInspections.length}</span></div>
    <div class="kv"><span>Zone.Identifier</span><span>${arrays.zoneIdentifiers.length}</span></div>
    <div class="kv"><span>ADS</span><span>${arrays.alternateDataStreams.length}</span></div>
    <div class="kv"><span>Autoruns avançados</span><span>${arrays.autorunIntegrity.length}</span></div>
    <div class="kv"><span>Processos</span><span>${arrays.processes.length}</span></div>
    <div class="kv"><span>Módulos em processos críticos</span><span>${arrays.processModuleIntegrity.length}</span></div>
    <div class="kv"><span>Memória privada executável</span><span>${arrays.processMemoryIntegrity.length}</span></div>
    <div class="kv"><span>Janelas excluídas de captura</span><span>${arrays.protectedWindows.length}</span></div>
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
    <div class="kv"><span>PowerShell avançado</span><span>${arrays.powerShellArtifacts.length}</span></div>
    <div class="kv"><span>Anomalias Prefetch</span><span>${arrays.prefetchIntegrity.length}</span></div>
    <div class="kv"><span>Volumes sem letra</span><span>${arrays.hiddenVolumes.length}</span></div>
    <div class="kv"><span>Limpezas de log (24h)</span><span>${arrays.logClearSignals.length}</span></div>
    <div class="kv"><span>Processos históricos (4688)</span><span>${arrays.processCreationEvents.length}</span></div>
    <div class="kv"><span>Defender</span><span>${arrays.defenderDetections.length} detecções · ${arrays.defenderExclusions.length} exclusões</span></div>
    <div class="kv"><span>Atalhos recentes</span><span>${arrays.recentShortcuts.length}</span></div>
    <div class="kv"><span>WER / crashes</span><span>${arrays.crashArtifacts.length}</span></div>
    <div class="kv"><span>Produtos de segurança</span><span>${arrays.securityProducts.length}</span></div>
    <div class="kv"><span>Downloads no histórico</span><span>${arrays.browserDownloads.length}</span></div>
    <div class="kv"><span>Downloads não localizados</span><span>${arrays.browserDownloads.filter((x) => x.fileMissing === true).length}</span></div>
    <div class="kv"><span>Histórico suspeito do navegador</span><span>${arrays.browserHistorySignals.length}</span></div>
    <div class="kv"><span>Vestígios de histórico apagado</span><span>${arrays.browserRecoveredArtifacts.length}</span></div>
    <div class="kv"><span>Arquivos apagados no USN</span><span>${arrays.deletedUsnRecords.length}</span></div>
    <div class="kv"><span>JournalTrace / USN</span><span>${arrays.usnActivity.length}</span></div>
    <div class="kv"><span>Rede / DNS</span><span>${arrays.networkIndicators.length}</span></div>
    <div class="kv"><span>Integridade Windows ampliada</span><span>${arrays.systemIntegrityExpansion.length}</span></div>
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

  const socialDownloads = arrays.browserDownloads
    .map((item) => ({
      item,
      origin: downloadOriginKind(item),
      name: item.fileName || item.targetPath || "",
      officialDiscordUpdate: isOfficialDiscordInstallerOrUpdateClient(item),
      discordAttachmentExe:
        /\.exe$/i.test(item.fileName || item.targetPath || "") &&
        isDiscordAttachmentDownloadClient(item)
    }))
    .filter((entry) =>
      entry.origin &&
      isRiskyDownloadName(entry.name) &&
      !entry.officialDiscordUpdate)
    .sort((a, b) => new Date(b.item.startTimeUtc || 0) - new Date(a.item.startTimeUtc || 0))
    .slice(0, 300);

  document.getElementById("socialDownloadsCountBadge").textContent = socialDownloads.length;
  document.getElementById("socialDownloadsList").innerHTML = socialDownloads.length
    ? socialDownloads.map(({ item, origin, name, discordAttachmentExe }) => {
        const sourceUrl =
          safeExternalUrl(item.sourceUrl) ||
          safeExternalUrl(item.finalUrl) ||
          safeExternalUrl(item.pageUrl) ||
          safeExternalUrl(item.referrerUrl);

        const doubleExtension = isDeceptiveDoubleExtension(name);
        const tag = discordAttachmentExe
          ? "critical"
          : doubleExtension
            ? "high"
            : "medium";

        return `
          <div class="finding severity-card ${tag}">
            <div class="finding-head">
              <h4>${escapeHtml(item.fileName || "Download")}</h4>
              <span class="tag ${tag}">${escapeHtml(origin.toUpperCase())}</span>
            </div>
            <div class="kv"><span>Baixado em</span><span>${escapeHtml(formatDate(item.startTimeUtc))}</span></div>
            <div class="kv"><span>Destino</span><span>${escapeHtml(item.targetPath || item.currentPath || "—")}</span></div>
            <div class="kv"><span>Arquivo presente</span><span>${item.fileExists ? "Sim" : "Não / movido"}</span></div>
            <div class="kv"><span>Dupla extensão</span><span>${doubleExtension ? "SIM" : "Não"}</span></div>
            ${sourceUrl ? `<div class="kv"><span>Origem</span><span><a href="${escapeHtml(sourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(sourceUrl)}</a></span></div>` : ""}
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhum executável/script/arquivo compactado originado de Discord ou Telegram foi encontrado.</div>';

  const browserDangerDownloads = arrays.browserDownloads
    .map((item) => ({ item, danger: browserDangerInfo(item.dangerType) }))
    .filter((entry) => entry.danger.suspicious)
    .sort((a, b) => new Date(b.item.startTimeUtc || 0) - new Date(a.item.startTimeUtc || 0))
    .slice(0, 300);

  document.getElementById("browserDangerCountBadge").textContent = browserDangerDownloads.length;
  document.getElementById("browserDangerDownloadsList").innerHTML = browserDangerDownloads.length
    ? browserDangerDownloads.map(({ item, danger }) => {
        const sourceUrl =
          safeExternalUrl(item.sourceUrl) ||
          safeExternalUrl(item.finalUrl) ||
          safeExternalUrl(item.pageUrl) ||
          safeExternalUrl(item.referrerUrl);

        return `
          <div class="finding severity-card ${escapeHtml(danger.severity)}">
            <div class="finding-head">
              <h4>${escapeHtml(item.fileName || "Download")}</h4>
              <span class="tag ${escapeHtml(danger.severity)}">${escapeHtml(danger.label)}</span>
            </div>
            <div class="kv"><span>DangerType</span><span>${Number(danger.code)}</span></div>
            <div class="kv"><span>Baixado em</span><span>${escapeHtml(formatDate(item.startTimeUtc))}</span></div>
            <div class="kv"><span>Destino</span><span>${escapeHtml(item.targetPath || item.currentPath || "—")}</span></div>
            <div class="kv"><span>Navegador</span><span>${escapeHtml(item.browser || "—")}</span></div>
            ${sourceUrl ? `<div class="kv"><span>Origem</span><span><a href="${escapeHtml(sourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(sourceUrl)}</a></span></div>` : ""}
          </div>
        `;
      }).join("")
    : '<div class="message ok">Nenhum download sinalizado como perigoso/incomum pelo navegador foi preservado no histórico.</div>';

  const aiFilteredNames = new Set();

  for (const finding of aiFilteredFindings) {
    const candidates = [
      finding.artifact_value,
      finding.evidence?.fileName,
      finding.evidence?.name,
      finding.evidence?.path,
      finding.evidence?.targetPath,
      finding.evidence?.currentPath,
      finding.evidence?.originalPath,
      finding.evidence?.recoveredFileName
    ].filter(Boolean);

    for (const value of candidates) {
      const normalized = String(value || "")
        .replaceAll("/", "\\")
        .toLowerCase()
        .trim();

      const name = normalized.split("\\").filter(Boolean).at(-1);
      if (name) aiFilteredNames.add(name);
    }
  }

  const wasFilteredByAi = (...values) =>
    values
      .flat(Infinity)
      .filter(Boolean)
      .some((value) => {
        const normalized = String(value || "")
          .replaceAll("/", "\\")
          .toLowerCase()
          .trim();

        const name = normalized.split("\\").filter(Boolean).at(-1);
        return Boolean(name && aiFilteredNames.has(name));
      });

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

  for (const item of arrays.deletedUsnRecords) {
    const lower = String(item.fileName || "").toLowerCase();
    const highInterest =
      item.randomLikeName === true ||
      item.deceptiveDoubleExtension === true ||
      ["loader", "injector", "cheat", "hack", "script", "aimbot", "recoil", "spoofer", "bypass", "eac"]
        .some((term) => lower.includes(term));

    if (!highInterest) continue;

    priorityFiles.push({
      priority: item.randomLikeName || item.deceptiveDoubleExtension ? 10 : 8,
      status: item.randomLikeName || item.deceptiveDoubleExtension
        ? "APAGADO · CRÍTICO"
        : "APAGADO · ALTO INTERESSE",
      tag: item.randomLikeName || item.deceptiveDoubleExtension ? "critical" : "high",
      name: item.fileName || "Arquivo apagado",
      path: item.volume || "NTFS",
      time: item.timestampUtc,
      source: "USN Journal",
      url: "",
      detail: "O NTFS registrou a exclusão mesmo sem haver execução do arquivo."
    });
  }

  for (const item of arrays.browserRecoveredArtifacts) {
    const critical =
      item.randomLikeName === true ||
      item.deceptiveDoubleExtension === true ||
      safeArray(item.catalogMatches).length > 0;

    if (!critical && Number(item.riskScore || 0) < 4)
      continue;

    priorityFiles.push({
      priority: critical ? 10 : 7,
      status: critical ? "HISTÓRICO APAGADO · CRÍTICO" : "HISTÓRICO APAGADO",
      tag: critical ? "critical" : "high",
      name: item.recoveredFileName || item.recoveredUrl || "Vestígio recuperado",
      path: item.sourceArtifact || "SQLite",
      time: null,
      source: item.recoveryKind || "SQLite",
      url: item.recoveredUrl || "",
      detail: item.note || "Vestígio recuperado do banco do navegador."
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

  for (const item of arrays.files) {
    const ext = String(item.extension || "").toLowerCase();
    if (![".zip", ".rar", ".7z"].includes(ext)) continue;

    const zipText = [
      item.name,
      item.path,
      ...safeArray(item.archiveEntries)
    ].join(" ").toLowerCase();

    const zipTerms = [
      "rust", "cheat", "hack", "script", "loader", "injector",
      "aimbot", "recoil", "macro", "spoofer", "bypass", "eac"
    ].filter((term) => zipText.includes(term));

    const randomExeInside = ext === ".zip" && safeArray(item.archiveEntries)
      .some((entry) => looksRandomExecutableNameClient(entry));

    if (zipTerms.length < 2 && !randomExeInside) continue;

    priorityFiles.push({
      priority: randomExeInside ? 7 : 5,
      status: ext === ".zip" ? "ZIP SUSPEITO" : "ARQUIVO COMPACTADO SUSPEITO",
      tag: randomExeInside ? "high" : "medium",
      name: item.name || "Arquivo ZIP",
      path: item.path || "—",
      time: item.lastWriteUtc || item.createdUtc,
      source: ext === ".zip" ? "Análise interna do ZIP" : "Nome/caminho do arquivo compactado",
      url: "",
      detail: randomExeInside
        ? "ZIP contém executável com nome aleatório."
        : "Arquivo compactado contém combinação de termos associados a cheat/script: " + zipTerms.join(", ")
    });
  }

  for (const finding of [...criticalFindings, ...mediumFindings]) {
    const maximumPriority =
      finding.evidence?.priorityMaximum === true;

    if (
      !maximumPriority &&
      ![
        "archive",
        "file",
        "browser_download",
        "browser_recovery",
        "usn_delete",
        "unknown_app",
        "prefetch_execution",
        "process_history",
        "browser_history",
        "bam",
        "recycle_bin"
      ].includes(finding.artifact_type)
    ) {
      continue;
    }

    priorityFiles.push({
      priority: maximumPriority
        ? 100
        : finding.severity === "critical"
          ? 10
          : finding.severity === "high"
            ? 8
            : 4,
      status: maximumPriority
        ? "PRIORIDADE MÁXIMA"
        : finding.severity === "critical"
          ? "CATÁLOGO / CRÍTICO"
          : finding.severity === "high"
            ? "ALTO RISCO"
            : "REVISAR",
      tag: finding.severity === "critical" ? "critical" :
        finding.severity === "high" ? "high" : "medium",
      name: finding.title || "Arquivo suspeito",
      path: finding.artifact_value || "—",
      time: finding.created_at,
      source: finding.evidence?.catalogMatch?.name || finding.artifact_type,
      url: finding.evidence?.sourceUrl || finding.evidence?.finalUrl || "",
      detail: finding.evidence?.note || "Achado priorizado pelo motor de detecção."
    });
  }

  const prioritySeen = new Set();
  const priorityUnique = priorityFiles
    .filter((item) =>
      showWithoutAiResult ||
      !wasFilteredByAi(
        item.name,
        item.path
      ))
    .sort((a, b) => b.priority - a.priority || new Date(b.time || 0) - new Date(a.time || 0))
    .filter((item) => {
      const key = String(item.name || item.path || "").toLowerCase();
      if (!key || prioritySeen.has(key)) return false;
      prioritySeen.add(key);
      return true;
    })
    .slice(0, 150);

  document.getElementById("priorityCountBadge").textContent = priorityUnique.length;
  const summaryPriorityCount = document.getElementById("summaryPriorityCount");
  if (summaryPriorityCount) summaryPriorityCount.textContent = priorityUnique.length;

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
    .filter((item) =>
      ["high", "medium"].includes(
        String(item.riskLevel || "").toLowerCase()
      ))
    .sort((a, b) =>
      (historyRiskOrder[String(b.riskLevel || "").toLowerCase()] || 0) -
      (historyRiskOrder[String(a.riskLevel || "").toLowerCase()] || 0) ||
      new Date(b.visitTimeUtc || 0) - new Date(a.visitTimeUtc || 0))
    .slice(0, 300);

  document.getElementById("historyCountBadge").textContent = browserHistorySignals.length;

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


let activeSessionFilter = "all";

function switchAdminTab(name) {
  const panels = {
    sessions: document.getElementById("sessionsPanel"),
    scanner: document.getElementById("scannerPanel"),
    settings: document.getElementById("settingsPanel"),
  };

  const panelName =
    name === "home"
      ? "sessions"
      : name;

  for (const [key, panel] of Object.entries(panels)) {
    panel?.classList.toggle("hidden", key !== panelName);
  }

  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.adminTab === name);
  });
}

function applySessionFilters() {
  const query =
    String(document.getElementById("sessionSearch")?.value || "")
      .trim()
      .toLowerCase();

  document.querySelectorAll("#analysesBody tr").forEach((row) => {
    if (!row.dataset.sessionKind) return;

    const matchesKind =
      activeSessionFilter === "all" ||
      row.dataset.sessionKind === activeSessionFilter;

    const matchesQuery =
      !query ||
      String(row.dataset.searchText || row.textContent || "")
        .toLowerCase()
        .includes(query);

    row.classList.toggle("hidden", !(matchesKind && matchesQuery));
  });
}

function setupVorkenAdminUi() {
  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      switchAdminTab(button.dataset.adminTab || "sessions");
    });
  });

  document.getElementById("sessionSearch")?.addEventListener(
    "input",
    applySessionFilters
  );

  document.querySelectorAll(".session-filter").forEach((button) => {
    button.addEventListener("click", () => {
      activeSessionFilter = button.dataset.sessionFilter || "all";
      document.querySelectorAll(".session-filter").forEach((item) =>
        item.classList.toggle("active", item === button)
      );
      applySessionFilters();
    });
  });

  document.querySelectorAll("[data-report-anchor]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-report-anchor]").forEach((item) =>
        item.classList.toggle("active", item === button)
      );

      const target =
        document.getElementById(button.dataset.reportAnchor || "");

      target?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  });

  document.getElementById("exportReportBtn")?.addEventListener("click", () => {
    window.print();
  });

  document.getElementById("hashReportBtn")?.addEventListener("click", async () => {
    const raw =
      document.getElementById("rawReport")?.textContent || "";

    if (!raw) {
      alert("Abra um relatório antes de gerar o hash.");
      return;
    }

    if (!window.crypto?.subtle) {
      alert("O navegador não disponibilizou o gerador SHA-256.");
      return;
    }

    const bytes =
      new TextEncoder().encode(raw);

    const digest =
      await crypto.subtle.digest("SHA-256", bytes);

    const hash =
      Array.from(new Uint8Array(digest))
        .map((value) => value.toString(16).padStart(2, "0"))
        .join("");

    try {
      await navigator.clipboard.writeText(hash);
      alert("SHA-256 copiado para a área de transferência:\n" + hash);
    } catch {
      alert("SHA-256 do relatório:\n" + hash);
    }
  });

  switchAdminTab("sessions");
}

setupVorkenAdminUi();

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
