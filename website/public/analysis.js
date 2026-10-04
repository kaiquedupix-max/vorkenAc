const loading = document.getElementById("loading");
const analysisView = document.getElementById("analysisView");
const errorView = document.getElementById("errorView");
const token = location.pathname.split("/").filter(Boolean).pop();

const COPY = {
  pt: {
    verification: "VERIFICAÇÃO",
    privateSession: "Sessão privada",
    protected: "PROTEGIDO",
    loading: "Preparando sua verificação...",
    loadingHint: "Validando o link exclusivo e os dados da sessão.",
    authorized: "SESSÃO AUTORIZADA",
    steam: "Steam",
    waitingBadge: "AGUARDANDO",
    runningBadge: "EM ANDAMENTO",
    completedBadge: "CONCLUÍDA",
    stepAuthorized: "Autorizada",
    stepAuthorizedHint: "Link validado",
    stepScanner: "Vorken",
    stepScannerHint: "Execução",
    stepAnalysis: "Análise",
    stepAnalysisHint: "Processamento",
    stepDecision: "Decisão",
    stepDecisionHint: "Administração",
    nextStep: "PRÓXIMO PASSO",
    downloadTitle: "Baixe e execute o Vorken",
    downloadDescription: "Baixe o executável exclusivo desta verificação e execute como administrador. Mantenha o Rust aberto até a coleta terminar.",
    validUntil: "Link válido até",
    downloadButton: "Baixar Vorken.exe",
    windowsExecutable: "Executável para Windows",
    privacyTitle: "Privacidade por padrão",
    privacyText: "O Vorken coleta somente artefatos técnicos necessários à verificação. Senhas, mensagens, fotos e documentos pessoais não fazem parte da análise.",
    consentTitle: "Consentimento antes da coleta",
    consentText: "O aplicativo mostra as categorias analisadas e exige sua confirmação antes de iniciar.",
    legalPrefix: "Ao continuar, consulte os",
    terms: "Termos",
    and: "e a",
    privacy: "Política de Privacidade",
    currentStatus: "STATUS ATUAL",
    waitingTitle: "Aguardando execução",
    waitingText: "Baixe o Vorken e execute o arquivo como administrador para iniciar a coleta.",
    runningTitle: "Coleta em andamento",
    runningText: "O Vorken está coletando os artefatos técnicos autorizados. Mantenha o Rust e o Vorken abertos.",
    completedTitle: "Coleta finalizada",
    completedText: "O relatório foi enviado. Aguarde a decisão da administração no ticket privado do Discord.",
    integrity: "INTEGRIDADE DO ARQUIVO",
    size: "Tamanho",
    important: "IMPORTANTE",
    supportText: "Não feche o Rust nem interrompa a verificação. Quando a coleta terminar, aguarde a decisão da administração no ticket privado do Discord.",
    unavailable: "LINK INDISPONÍVEL",
    errorTitle: "Não foi possível abrir esta verificação.",
    invalidLink: "Link inválido ou expirado.",
    player: "Jogador",
  },
  en: {
    verification: "VERIFICATION",
    privateSession: "Private session",
    protected: "PROTECTED",
    loading: "Preparing your verification...",
    loadingHint: "Validating the exclusive link and session information.",
    authorized: "AUTHORIZED SESSION",
    steam: "Steam",
    waitingBadge: "WAITING",
    runningBadge: "IN PROGRESS",
    completedBadge: "COMPLETED",
    stepAuthorized: "Authorized",
    stepAuthorizedHint: "Link validated",
    stepScanner: "Vorken",
    stepScannerHint: "Execution",
    stepAnalysis: "Analysis",
    stepAnalysisHint: "Processing",
    stepDecision: "Decision",
    stepDecisionHint: "Administration",
    nextStep: "NEXT STEP",
    downloadTitle: "Download and run Vorken",
    downloadDescription: "Download the executable created for this verification and run it as administrator. Keep Rust open until collection finishes.",
    validUntil: "Link valid until",
    downloadButton: "Download Vorken.exe",
    windowsExecutable: "Windows executable",
    privacyTitle: "Privacy by default",
    privacyText: "Vorken collects only the technical artifacts required for verification. Passwords, messages, photos, and personal documents are not part of the analysis.",
    consentTitle: "Consent before collection",
    consentText: "The application shows the categories that will be analyzed and requires your confirmation before it starts.",
    legalPrefix: "Before continuing, read the",
    terms: "Terms",
    and: "and the",
    privacy: "Privacy Policy",
    currentStatus: "CURRENT STATUS",
    waitingTitle: "Waiting for execution",
    waitingText: "Download Vorken and run the file as administrator to begin collection.",
    runningTitle: "Collection in progress",
    runningText: "Vorken is collecting the authorized technical artifacts. Keep Rust and Vorken open.",
    completedTitle: "Collection completed",
    completedText: "The report was sent. Wait for the administration's decision in your private Discord ticket.",
    integrity: "FILE INTEGRITY",
    size: "Size",
    important: "IMPORTANT",
    supportText: "Do not close Rust or interrupt the verification. When collection finishes, wait for the administration's decision in the private Discord ticket.",
    unavailable: "LINK UNAVAILABLE",
    errorTitle: "This verification could not be opened.",
    invalidLink: "Invalid or expired link.",
    player: "Player",
  },
  es: {
    verification: "VERIFICACIÓN",
    privateSession: "Sesión privada",
    protected: "PROTEGIDO",
    loading: "Preparando tu verificación...",
    loadingHint: "Validando el enlace exclusivo y los datos de la sesión.",
    authorized: "SESIÓN AUTORIZADA",
    steam: "Steam",
    waitingBadge: "ESPERANDO",
    runningBadge: "EN PROGRESO",
    completedBadge: "FINALIZADA",
    stepAuthorized: "Autorizada",
    stepAuthorizedHint: "Enlace validado",
    stepScanner: "Vorken",
    stepScannerHint: "Ejecución",
    stepAnalysis: "Análisis",
    stepAnalysisHint: "Procesamiento",
    stepDecision: "Decisión",
    stepDecisionHint: "Administración",
    nextStep: "SIGUIENTE PASO",
    downloadTitle: "Descarga y ejecuta Vorken",
    downloadDescription: "Descarga el ejecutable exclusivo de esta verificación y ejecútalo como administrador. Mantén Rust abierto hasta que termine la recopilación.",
    validUntil: "Enlace válido hasta",
    downloadButton: "Descargar Vorken.exe",
    windowsExecutable: "Ejecutable para Windows",
    privacyTitle: "Privacidad por defecto",
    privacyText: "Vorken recopila únicamente los artefactos técnicos necesarios para la verificación. Contraseñas, mensajes, fotos y documentos personales no forman parte del análisis.",
    consentTitle: "Consentimiento antes de recopilar",
    consentText: "La aplicación muestra las categorías que serán analizadas y exige tu confirmación antes de comenzar.",
    legalPrefix: "Antes de continuar, consulta los",
    terms: "Términos",
    and: "y la",
    privacy: "Política de Privacidad",
    currentStatus: "ESTADO ACTUAL",
    waitingTitle: "Esperando ejecución",
    waitingText: "Descarga Vorken y ejecuta el archivo como administrador para iniciar la recopilación.",
    runningTitle: "Recopilación en progreso",
    runningText: "Vorken está recopilando los artefactos técnicos autorizados. Mantén Rust y Vorken abiertos.",
    completedTitle: "Recopilación finalizada",
    completedText: "El informe fue enviado. Espera la decisión de la administración en tu ticket privado de Discord.",
    integrity: "INTEGRIDAD DEL ARCHIVO",
    size: "Tamaño",
    important: "IMPORTANTE",
    supportText: "No cierres Rust ni interrumpas la verificación. Cuando termine la recopilación, espera la decisión de la administración en el ticket privado de Discord.",
    unavailable: "ENLACE NO DISPONIBLE",
    errorTitle: "No fue posible abrir esta verificación.",
    invalidLink: "Enlace inválido o expirado.",
    player: "Jugador",
  },
};

let language = localStorage.getItem("vorken-analysis-language") || "pt";
if (!COPY[language]) language = "pt";
let lastData = null;

function t(key) {
  return COPY[language]?.[key] || COPY.pt[key] || key;
}

function formatDate(value) {
  if (!value) return "—";
  const locale = language === "en" ? "en-US" : language === "es" ? "es-ES" : "pt-BR";
  return new Date(value).toLocaleString(locale);
}

function parseIdentity(label) {
  const raw = String(label || "").trim();
  const steamMatch = raw.match(/7656119\d{10}/);
  const steamId = steamMatch?.[0] || "—";
  let playerName = raw
    .replace(steamId === "—" ? "" : steamId, "")
    .replace(/\bGuerra\s*Fria\b/gi, "")
    .replace(/[·|—•:-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!playerName || /^vorken$/i.test(playerName)) playerName = t("player");
  return { playerName, steamId };
}

function setLanguage(next) {
  if (!COPY[next]) return;
  language = next;
  localStorage.setItem("vorken-analysis-language", next);
  document.documentElement.lang = next === "pt" ? "pt-BR" : next;
  document.querySelectorAll("[data-language]").forEach(button => {
    button.classList.toggle("active", button.dataset.language === next);
  });
  document.querySelectorAll("[data-i18n]").forEach(node => {
    node.textContent = t(node.dataset.i18n);
  });
  if (lastData) render(lastData);
}

function setProgress(status) {
  const order = status === "completed" ? 4 : status === "running" ? 2 : 1;
  const steps = ["authorized", "scanner", "analysis", "decision"];
  document.querySelectorAll(".progress-step").forEach((node, index) => {
    node.classList.toggle("done", index + 1 < order || (status === "completed" && index < 3));
    node.classList.toggle("active", index + 1 === Math.min(order, 4));
  });
  document.querySelectorAll(".progress-line").forEach((line, index) => {
    line.classList.toggle("done", index + 1 < order);
  });
}

function renderStatus(status) {
  const badge = document.getElementById("statusBadge");
  const title = document.getElementById("statusTitle");
  const text = document.getElementById("analysisStatus");
  const icon = document.getElementById("statusIcon");

  badge.className = "status-badge " + (status || "waiting");
  if (status === "running") {
    badge.textContent = t("runningBadge");
    title.textContent = t("runningTitle");
    text.textContent = t("runningText");
    icon.textContent = "◌";
  } else if (status === "completed") {
    badge.textContent = t("completedBadge");
    title.textContent = t("completedTitle");
    text.textContent = t("completedText");
    icon.textContent = "✓";
  } else {
    badge.textContent = t("waitingBadge");
    title.textContent = t("waitingTitle");
    text.textContent = t("waitingText");
    icon.textContent = "⏱";
  }
  setProgress(status);
}

function render(data) {
  lastData = data;
  const analysis = data.analysis || {};
  const identity = parseIdentity(analysis.label);
  document.getElementById("playerName").textContent = identity.playerName;
  document.getElementById("steamId").textContent = identity.steamId;
  document.getElementById("analysisText").textContent = t("downloadDescription");
  document.getElementById("expiresAt").textContent = formatDate(analysis.expiresAt);

  const button = document.getElementById("downloadBtn");
  button.href = data.downloadUrl || data.packageUrl || "#";
  button.classList.toggle("disabled", analysis.status === "completed");
  button.setAttribute("aria-disabled", analysis.status === "completed" ? "true" : "false");
  if (analysis.status === "completed") button.removeAttribute("href");

  const verification = document.getElementById("agentVerification");
  const sha256 = String(data.agentVerification?.sha256 || "");
  const sizeBytes = Number(data.agentVerification?.sizeBytes || 0);
  if (sha256) {
    verification.classList.remove("hidden");
    document.getElementById("sha256Value").textContent = sha256;
    document.getElementById("sizeValue").textContent = sizeBytes ? (sizeBytes / 1024 / 1024).toFixed(1) + " MB" : "—";
  } else {
    verification.classList.add("hidden");
  }
  renderStatus(analysis.status);
}

async function load() {
  try {
    const response = await fetch("/api/public/analyses/" + encodeURIComponent(token), { cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || t("invalidLink"));

    loading.classList.add("hidden");
    errorView.classList.add("hidden");
    analysisView.classList.remove("hidden");
    render(data);
  } catch (error) {
    loading.classList.add("hidden");
    analysisView.classList.add("hidden");
    errorView.classList.remove("hidden");
    document.getElementById("errorText").textContent = error instanceof Error ? error.message : t("invalidLink");
  }
}

document.querySelectorAll("[data-language]").forEach(button => {
  button.addEventListener("click", () => setLanguage(button.dataset.language));
});

setLanguage(language);
load();
setInterval(load, 8000);
