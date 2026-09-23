const loginView = document.getElementById("loginView");
const dashboardView = document.getElementById("dashboardView");
const logoutBtn = document.getElementById("logoutBtn");
const analysesBody = document.getElementById("analysesBody");
const rulesList = document.getElementById("rulesList");
const reportCard = document.getElementById("reportCard");

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
    button.addEventListener("click", () => openReport(button.dataset.id));
  });
}

async function openReport(id) {
  const data = await api("/api/admin/analyses/" + encodeURIComponent(id));
  const { analysis, report, findings } = data;
  const payload = report?.payload || {};

  document.getElementById("reportTitle").textContent =
    "#" + analysis.id + " · " + analysis.label;

  const arrays = {
    usbCurrent: payload.usbCurrent || [],
    usbHistory: payload.usbHistory || [],
    serialDevices: payload.serialDevices || [],
    processes: payload.processes || [],
    prefetch: payload.prefetch || [],
    services: payload.services || [],
    drivers: payload.drivers || [],
    startup: payload.startup || [],
    files: payload.files || [],
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
    <div class="kv"><span>Arduino / Serial</span><span>${arrays.serialDevices.length}</span></div>
    <div class="kv"><span>Arquivos analisados</span><span>${arrays.files.length}</span></div>
    <div class="kv"><span>Processos</span><span>${arrays.processes.length}</span></div>
    <div class="kv"><span>Prefetch</span><span>${arrays.prefetch.length}</span></div>
    <div class="kv"><span>Serviços</span><span>${arrays.services.length}</span></div>
    <div class="kv"><span>Drivers</span><span>${arrays.drivers.length}</span></div>
    <div class="kv"><span>Inicialização</span><span>${arrays.startup.length}</span></div>
    <div class="kv"><span>Erros parciais</span><span>${(payload.errors || []).length}</span></div>
  `;

  const disconnected = arrays.usbHistory.filter((item) => item.present === false);
  document.getElementById("disconnectedUsbList").innerHTML = disconnected.length
    ? disconnected.map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.friendlyName || item.deviceDescription || item.deviceClass || "Dispositivo USB")}</h4>
            <span class="tag medium">DESCONECTADO</span>
          </div>
          <div class="kv"><span>Fabricante</span><span>${escapeHtml(item.manufacturer || "—")}</span></div>
          <div class="kv"><span>Instância</span><span>${escapeHtml(item.instanceId || "—")}</span></div>
          <code>${escapeHtml(item.deviceClass || "")}</code>
        </div>
      `).join("")
    : '<div class="message ok">Nenhum dispositivo USB histórico marcado como desconectado.</div>';

  document.getElementById("serialDeviceList").innerHTML = arrays.serialDevices.length
    ? arrays.serialDevices.map((item) => `
        <div class="finding">
          <div class="finding-head">
            <h4>${escapeHtml(item.name || "Dispositivo serial")}</h4>
            <span class="tag info">SERIAL</span>
          </div>
          <div class="kv"><span>Fabricante</span><span>${escapeHtml(item.manufacturer || "—")}</span></div>
          <div class="kv"><span>Status</span><span>${escapeHtml(item.status || "—")}</span></div>
          <code>${escapeHtml(item.pnpDeviceId || item.deviceId || "")}</code>
        </div>
      `).join("")
    : '<div class="message">Nenhum Arduino/CH340/CP210/FTDI ou porta serial correspondente foi listado.</div>';

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
              ${item.prefetchEvidenceUtc ? "EXECUÇÃO INDICADA" : "REVISAR"}
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

  document.getElementById("rawReport").textContent =
    JSON.stringify(payload, null, 2);

  reportCard.classList.remove("hidden");
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
