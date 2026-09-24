const loading = document.getElementById("loading");
const analysisView = document.getElementById("analysisView");
const errorView = document.getElementById("errorView");
const token = location.pathname.split("/").filter(Boolean).pop();

function formatDate(value) {
  return value ? new Date(value).toLocaleString("pt-BR") : "—";
}

function statusText(status) {
  const map = {
    waiting: "Aguardando execução do Vorken.",
    running: "O scanner está executando neste momento.",
    completed: "Análise concluída. O relatório já foi enviado ao responsável.",
  };
  return map[status] || "Status: " + status;
}

async function load() {
  try {
    const response = await fetch("/api/public/analyses/" + encodeURIComponent(token), {
      cache: "no-store",
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.message || "Link inválido ou expirado.");
    }

    loading.classList.add("hidden");
    errorView.classList.add("hidden");
    analysisView.classList.remove("hidden");

    document.getElementById("analysisLabel").textContent = data.analysis.label;
    document.getElementById("analysisText").textContent =
      "Esta sessão é válida até " + formatDate(data.analysis.expiresAt) +
      ". Baixe o Vorken em .EXE e execute-o como administrador. Não é necessário extrair ZIP nem copiar arquivo de configuração.";

    const button = document.getElementById("downloadBtn");
    button.href = data.downloadUrl || data.packageUrl;
    button.textContent = "Baixar Vorken.exe";

    const verification = document.getElementById("agentVerification");
    const sha256 = String(data.agentVerification?.sha256 || "");
    const sizeBytes = Number(data.agentVerification?.sizeBytes || 0);

    if (sha256) {
      verification.classList.remove("hidden");
      verification.innerHTML =
        "<strong>Verificação do executável</strong><br>" +
        "SHA-256: <code>" + sha256 + "</code>" +
        (sizeBytes ? "<br>Tamanho: " + (sizeBytes / 1024 / 1024).toFixed(1) + " MB" : "");
    } else {
      verification.classList.add("hidden");
      verification.textContent = "";
    }

    const status = document.getElementById("analysisStatus");
    status.textContent = statusText(data.analysis.status);
    status.className =
      "message " + (data.analysis.status === "completed" ? "ok" : "");

    if (data.analysis.status === "completed") {
      button.textContent = "Análise concluída";
      button.classList.add("hidden");
    }
  } catch (error) {
    loading.classList.add("hidden");
    analysisView.classList.add("hidden");
    errorView.classList.remove("hidden");
    document.getElementById("errorText").textContent = error.message;
  }
}

load();
setInterval(load, 8000);
