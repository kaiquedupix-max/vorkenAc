const STRONG_INJECTION_APIS = new Set([
  "virtualallocex",
  "writeprocessmemory",
  "createremotethread",
  "ntwritevirtualmemory",
  "ntcreatethreadex",
  "queueuserapc"
]);

const INPUT_APIS = new Set([
  "mouse_event",
  "sendinput"
]);

const GENERIC_EXECUTABLE_NAMES = new Set([
  "setup.exe",
  "installer.exe",
  "install.exe",
  "update.exe",
  "updater.exe",
  "uninstall.exe",
  "uninstaller.exe"
]);

const KNOWN_OVERLAY_TOKENS = [
  "steam",
  "discord",
  "nvidia",
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

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizePath(value) {
  return String(value || "")
    .replaceAll("/", "\\")
    .trim()
    .toLowerCase();
}

function baseName(value) {
  const normalized = normalizePath(value)
    .replace(/[?#].*$/, "");
  const parts = normalized
    .split("\\")
    .filter(Boolean);
  return parts.at(-1) || "";
}

function extName(value) {
  const name = baseName(value);
  const index = name.lastIndexOf(".");
  return index >= 0 ? name.slice(index) : "";
}

function validDateMs(value) {
  const ms = new Date(value || 0).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function rustSessionWindow(report) {
  const rustStarts = [];

  for (const item of safeArray(report?.processes)) {
    const name =
      String(item?.name || item?.path || "")
        .toLowerCase();

    if (
      name.includes("rustclient") ||
      /(^|\\)rust(?:client)?(?:\.exe)?$/i
        .test(name)
    ) {
      const ms =
        validDateMs(item?.startTimeUtc);

      if (ms)
        rustStarts.push(ms);
    }
  }

  for (const item of safeArray(report?.processCreationEvents)) {
    const value =
      String(
        item?.processPath ||
        item?.processName ||
        ""
      ).toLowerCase();

    if (
      value.includes("rustclient") ||
      /(^|\\)rust(?:client)?\.exe$/i
        .test(value)
    ) {
      const ms =
        validDateMs(
          item?.timestampUtc ||
          item?.timeCreatedUtc ||
          item?.createdAtUtc
        );

      if (ms)
        rustStarts.push(ms);
    }
  }

  if (rustStarts.length === 0) {
    return {
      known: false,
      startMs: 0,
      endMs:
        validDateMs(report?.collectedAtUtc) ||
        Date.now()
    };
  }

  const startMs =
    Math.max(...rustStarts);

  const endMs =
    validDateMs(report?.collectedAtUtc) ||
    Date.now();

  return {
    known: true,
    startMs,
    endMs:
      Math.max(endMs, startMs)
  };
}

function executionTimestamp(source) {
  const raw =
    source?.raw || {};

  return (
    validDateMs(raw?.lastExecutionUtc) ||
    validDateMs(raw?.lastRunUtc) ||
    validDateMs(raw?.startTimeUtc) ||
    validDateMs(raw?.timestampUtc) ||
    validDateMs(raw?.timeCreatedUtc) ||
    validDateMs(raw?.createdAtUtc)
  );
}

function classifyExecutionScope(
  execution,
  session
) {
  const timestamps =
    safeArray(execution?.sources)
      .map(executionTimestamp)
      .filter((ms) => ms > 0);

  if (
    !session?.known ||
    timestamps.length === 0
  ) {
    return {
      scope: "unknown",
      inSession: false,
      outOfSession: false,
      timestamps
    };
  }

  const toleranceBefore =
    2 * 60 * 1000;

  const inSession =
    timestamps.some((ms) =>
      ms >= session.startMs - toleranceBefore &&
      ms <= session.endMs + 5 * 60 * 1000
    );

  return {
    scope:
      inSession
        ? "in_session"
        : "out_of_session",
    inSession,
    outOfSession: !inSession,
    timestamps
  };
}

function timestampIso(ms) {
  try {
    return new Date(ms).toISOString();
  } catch {
    return "";
  }
}

function suspiciousUserPath(value) {
  const p = normalizePath(value);
  return (
    p.includes("\\downloads\\") ||
    p.includes("\\desktop\\") ||
    p.includes("\\appdata\\local\\temp\\") ||
    p.includes("\\temp\\")
  );
}

function isKnownVersionedOneDriveComponent(value) {
  const p = normalizePath(value);

  if (!p)
    return false;

  return (
    /\\appdata\\local\\microsoft\\onedrive\\\d{2,3}\.\d{3}\.\d{4}\.\d{4}\\filecoauth\.exe$/i
      .test(p) ||
    /\\program files(?: \(x86\))?\\microsoft onedrive\\\d{2,3}\.\d{3}\.\d{4}\.\d{4}\\filecoauth\.exe$/i
      .test(p)
  );
}

function executableToken(value) {
  const raw =
    String(value || "")
      .replaceAll("/", "\\")
      .trim();

  const matches =
    [...raw.matchAll(/([A-Za-z0-9._-]+\.exe)\b/gi)];

  if (matches.length > 0)
    return matches.at(-1)?.[1] || "";

  return baseName(raw);
}

function loaderNameScore(value, evidence = {}) {
  if (evidence?.randomLikeName === true)
    return 4;

  const file =
    executableToken(value);

  const stem =
    file
      .replace(/\.exe$/i, "");

  if (
    stem.length < 7 ||
    stem.length > 36 ||
    !/^[A-Za-z0-9_-]+$/.test(stem)
  ) {
    return 0;
  }

  const lower =
    stem.toLowerCase();

  if (
    /(setup|install|update|updater|uninstall|chrome|discord|steam|windows|microsoft|nvidia|amd|opera|spotify|notepad|powershell|runtime|service|helper|launcher|client|server|directx|vcredist|edge|onedrive|visual|studio|code)/i
      .test(lower)
  ) {
    return 0;
  }

  let score = 0;

  const hasUpper = /[A-Z]/.test(stem);
  const hasLower = /[a-z]/.test(stem);
  const hasDigit = /\d/.test(stem);

  if (hasUpper && hasLower)
    score += 2;

  if (hasDigit && (hasUpper || hasLower))
    score += 1;

  if (/^[A-Z0-9]{8,24}$/.test(stem))
    score += 2;

  const transitions =
    [...stem]
      .slice(1)
      .reduce((count, ch, i) => {
        const prev = stem[i];
        const caseFlip =
          /[A-Z]/.test(ch) !==
          /[A-Z]/.test(prev) &&
          /[A-Za-z]/.test(ch) &&
          /[A-Za-z]/.test(prev);

        return count + (caseFlip ? 1 : 0);
      }, 0);

  if (transitions >= 3)
    score += 2;

  const uniqueRatio =
    new Set(stem.toLowerCase()).size /
    Math.max(stem.length, 1);

  if (
    stem.length >= 9 &&
    uniqueRatio >= 0.55
  ) {
    score += 1;
  }

  return score;
}

function looksLikeUnknownLoaderName(
  value,
  evidence = {}
) {
  return loaderNameScore(
    value,
    evidence
  ) >= 3;
}

function isGenericInstaller(value) {
  const name = baseName(value);
  return (
    GENERIC_EXECUTABLE_NAMES.has(name) ||
    /(?:setup|installer|install|update|updater|uninstall)[^\\]*\.exe$/i
      .test(name)
  );
}

function isSearchEngineUrl(value) {
  const raw = String(value || "").toLowerCase();
  return (
    raw.includes("google.") && raw.includes("/search") ||
    raw.includes("bing.com/search") ||
    raw.includes("duckduckgo.com/") ||
    raw.includes("search.yahoo.com/")
  );
}

function hostOf(value) {
  try {
    return new URL(String(value || "")).hostname
      .toLowerCase()
      .replace(/^www\./, "");
  } catch {
    return "";
  }
}

function hasStrongRustIntent(value) {
  const text = String(value || "").toLowerCase();
  if (!text) return false;

  const rust =
    /(^|[^a-z0-9])rust([^a-z0-9]|$)/i.test(text);

  const strong =
    /(^|[^a-z0-9])(cheat|aimbot|wallhack|flyhack|recoil|macro|script|loader|spoofer|injector|no[ -]?recoil)([^a-z0-9]|$)/i
      .test(text);

  return rust && strong;
}

function hasActionableRustCheatPageIntent(value) {
  const text = String(value || "").toLowerCase();
  if (!text) return false;

  const rust =
    /(^|[^a-z0-9])rust([^a-z0-9]|$)/i.test(text);

  if (!rust)
    return false;

  const actionable =
    /(^|[^a-z0-9])(cheat|aimbot|wallhack|flyhack|no[ -]?recoil|recoil[ -]?script|macro|script|loader|spoofer|injector|undetected|free[ -]?download)([^a-z0-9]|$)/i
      .test(text);

  const moderationOnly =
    /banindo|banning|banido|banned|pegando hacker|catching hacker|verificando hack|anti[ -]?cheat/i
      .test(text) &&
    !/(aimbot|wallhack|no[ -]?recoil|recoil[ -]?script|loader|spoofer|injector|undetected|free[ -]?download)/i
      .test(text);

  return actionable && !moderationOnly;
}

function apiList(item) {
  return safeArray(item?.suspiciousApis)
    .map((api) => String(api || "").trim())
    .filter(Boolean);
}

function injectionApis(item) {
  return apiList(item).filter((api) =>
    STRONG_INJECTION_APIS.has(api.toLowerCase())
  );
}

function inputApis(item) {
  return apiList(item).filter((api) =>
    INPUT_APIS.has(api.toLowerCase())
  );
}

function buildRecentUsb(report) {
  return safeArray(report?.usbHistory)
    .filter((item) => item?.present === false)
    .map((item) => ({
      item,
      when:
        validDateMs(item?.lastDisconnectedUtc) ||
        validDateMs(item?.lastConnectedUtc)
    }))
    .filter((entry) => entry.when > 0);
}

function usbCorrelatesExecution(execution, recentUsb) {
  if (execution?.currentRemovable === true)
    return {
      confirmed: true,
      reason: "current_removable",
      device: null
    };

  const strongDetached =
    execution?.volumeNotMounted === true &&
    execution?.nonSystemVolume === true &&
    execution?.likelyDetachedOrRemovable === true;

  if (!strongDetached) {
    return {
      confirmed: false,
      reason: "",
      device: null
    };
  }

  const runMs =
    validDateMs(execution?.lastRunUtc);

  if (!runMs) {
    return {
      confirmed: false,
      reason: "detached_without_time",
      device: null
    };
  }

  const match =
    recentUsb
      .map((entry) => ({
        ...entry,
        delta: Math.abs(entry.when - runMs)
      }))
      .filter((entry) =>
        runMs <= entry.when + 15 * 60 * 1000 &&
        runMs >= entry.when - 24 * 60 * 60 * 1000
      )
      .sort((a, b) => a.delta - b.delta)[0];

  return {
    confirmed: Boolean(match),
    reason: match
      ? "detached_correlated_usb"
      : "detached_unconfirmed",
    device: match?.item || null
  };
}

function buildExecutionIndex(report) {
  const byName = new Map();
  const recentUsb = buildRecentUsb(report);

  const remember = (
    rawPath,
    source,
    details = {}
  ) => {
    const name = baseName(rawPath);
    if (!/\.exe$/i.test(name))
      return;

    if (!byName.has(name)) {
      byName.set(name, {
        name,
        paths: new Set(),
        sources: [],
        executed: false,
        missing: false,
        usbConfirmed: false,
        usbContext: null
      });
    }

    const entry = byName.get(name);
    const normalized = normalizePath(rawPath);

    if (normalized)
      entry.paths.add(normalized);

    entry.executed = true;
    entry.sources.push({
      source,
      path: rawPath,
      ...details
    });

    if (details.missing === true)
      entry.missing = true;

    if (details.usb?.confirmed === true) {
      entry.usbConfirmed = true;
      entry.usbContext = details.usb;
    }
  };

  for (const item of safeArray(report?.processes)) {
    remember(
      item?.path || item?.name,
      "process_snapshot",
      {
        missing: false,
        raw: item
      }
    );
  }

  for (const item of safeArray(report?.prefetchExecutions)) {
    const pathValue =
      item?.resolvedExecutablePath ||
      item?.nativeExecutablePath ||
      item?.executableName;

    remember(
      pathValue,
      "prefetch",
      {
        missing:
          item?.executablePresent === false,
        usb:
          usbCorrelatesExecution(
            item,
            recentUsb
          ),
        raw: item
      }
    );
  }

  for (const item of safeArray(report?.bam)) {
    remember(
      item?.path,
      "bam",
      {
        missing:
          item?.fileExists === false,
        raw: item
      }
    );
  }

  for (const item of safeArray(report?.processCreationEvents)) {
    remember(
      item?.processPath ||
      item?.processName,
      "event_4688",
      {
        missing:
          item?.processPresent === false,
        usb: {
          confirmed:
            String(item?.driveType || "")
              .toLowerCase() === "removable",
          reason:
            String(item?.driveType || "")
              .toLowerCase() === "removable"
              ? "event_4688_removable"
              : "",
          device: null
        },
        raw: item
      }
    );
  }

  // UserAssist is strong evidence that a GUI application was launched by the
  // interactive user. It does not by itself prove malicious behavior.
  for (const item of safeArray(report?.userAssist)) {
    remember(
      item?.decodedName,
      "userassist",
      {
        missing: false,
        raw: item
      }
    );
  }

  // ShimCache/AppCompat entries explicitly marked as executed are independent
  // historical execution evidence. Do not treat entries marked "No" as execution.
  for (const item of safeArray(report?.shimCache)) {
    const executed =
      item?.executed === true ||
      String(item?.executed || "")
        .toLowerCase() === "yes";

    if (!executed)
      continue;

    remember(
      item?.path,
      "shimcache",
      {
        missing:
          item?.filePresent === false,
        raw: item
      }
    );
  }

  // PCA/MuiCache are corroboration only. PCA can tell us that a file observed
  // by Windows is no longer present, but PCA alone is not treated as execution.
  for (const item of safeArray(report?.pca)) {
    const name =
      baseName(item?.path);

    if (!name || !byName.has(name))
      continue;

    const entry =
      byName.get(name);

    entry.sources.push({
      source: "pca_context",
      path: item?.path,
      corroborationOnly: true,
      raw: item
    });

    if (item?.fileExists === false)
      entry.missing = true;
  }

  return byName;
}

function buildDeletedIndex(report) {
  const deleted = new Map();

  const remember = (value, source, raw) => {
    const name = baseName(value);
    if (!/\.exe$/i.test(name))
      return;

    if (!deleted.has(name))
      deleted.set(name, []);

    deleted.get(name).push({
      source,
      value,
      raw
    });
  };

  for (const item of safeArray(report?.deletedUsnRecords)) {
    remember(
      item?.fileName ||
      item?.path ||
      item?.originalPath,
      "usn_delete",
      item
    );
  }

  for (const item of safeArray(report?.recycleBin)) {
    remember(
      item?.originalPath ||
      item?.fileName,
      "recycle_bin",
      item
    );
  }

  return deleted;
}

function buildPeIndex(report) {
  const index = new Map();

  for (const item of safeArray(report?.peInspections)) {
    const value =
      item?.path ||
      item?.name;
    const name = baseName(value);

    if (!/\.exe$/i.test(name))
      continue;

    if (!index.has(name))
      index.set(name, []);

    index.get(name).push(item);
  }

  return index;
}

function strongestPe(peItems) {
  const sorted =
    [...peItems].sort((a, b) => {
      const aScore =
        injectionApis(a).length * 10 +
        inputApis(a).length * 5 +
        (a?.signed === false ? 2 : 0);
      const bScore =
        injectionApis(b).length * 10 +
        inputApis(b).length * 5 +
        (b?.signed === false ? 2 : 0);
      return bScore - aScore;
    });

  return sorted[0] || null;
}

function buildFileEvidence(report, name) {
  const wanted = String(name || "").toLowerCase();

  return safeArray(report?.files)
    .filter((item) =>
      baseName(item?.path || item?.name) === wanted
    );
}

function fileLooksTrusted(
  value,
  evidence,
  helpers
) {
  const knownCheat =
    helpers.knownCheatExecutableMatch?.(
      value,
      evidence || {}
    );

  if (knownCheat?.matched === true) {
    return false;
  }

  if (
    helpers.isKnownBenignPeNoise?.(value)
  ) {
    return true;
  }

  if (
    helpers.isAbsoluteTrustedCatalogArtifact?.(
      "file",
      value,
      evidence || {}
    )
  ) {
    return true;
  }

  if (
    helpers.isTrustedCommonAppArtifact?.(
      value,
      evidence || {}
    )
  ) {
    return true;
  }

  if (
    helpers.isTrustedPortableExecutableName?.(
      baseName(value)
    )
  ) {
    return true;
  }

  return false;
}

function catalogMatchesForFile(
  value,
  evidence,
  helpers
) {
  return helpers.findRustCatalogMatches?.(
    value,
    evidence?.name,
    evidence?.path,
    evidence?.fileName,
    evidence?.originalPath,
    evidence?.targetPath
  ) || [];
}

function findingEvidence(base = {}) {
  return {
    baselineV2: true,
    classifierVersion:
      "echo-inspired-v3",
    ...base
  };
}

async function addFinding(
  insertFinding,
  analysisId,
  title,
  severity,
  type,
  value,
  evidence
) {
  await insertFinding(
    analysisId,
    title,
    severity,
    type,
    value,
    findingEvidence(evidence)
  );
}

function explicitSearchIntent(item, helpers) {
  const query =
    String(item?.searchQuery || "")
      .trim();

  if (!query)
    return false;

  if (hasStrongRustIntent(query))
    return true;

  const matches =
    helpers.findRustCatalogMatches?.(
      query
    ) || [];

  return matches.length > 0;
}

function directCatalogWebMatch(item, helpers) {
  const matches =
    helpers.findRustCatalogMatches?.(
      item?.url,
      item?.sourceUrl,
      item?.finalUrl,
      item?.pageUrl,
      item?.siteUrl,
      item?.referrerUrl,
      item?.recoveredUrl
    ) || [];

  const direct =
    matches.find((match) =>
      helpers.isDirectCatalogWebMatch?.(
        match,
        item
      )
    );

  return direct
    ? { direct, matches }
    : null;
}

export async function runCalibratedFilterV2({
  analysisId,
  report,
  insertFinding,
  helpers
}) {
  const rustSession =
    rustSessionWindow(report);

  const executionIndex =
    buildExecutionIndex(report);

  const deletedIndex =
    buildDeletedIndex(report);

  const peIndex =
    buildPeIndex(report);

  const candidateNames =
    new Set([
      ...executionIndex.keys(),
      ...deletedIndex.keys(),
      ...peIndex.keys()
    ]);

  // 1. Executable correlation. Presence alone is not guilt.
  for (const name of candidateNames) {
    const execution =
      executionIndex.get(name) || {
        executed: false,
        missing: false,
        usbConfirmed: false,
        sources: [],
        paths: new Set()
      };

    const deleted =
      deletedIndex.get(name) || [];

    const peItems =
      peIndex.get(name) || [];

    const pe =
      strongestPe(peItems);

    const fileEvidence =
      buildFileEvidence(report, name);

    const representative =
      pe?.path ||
      pe?.name ||
      execution.sources?.[0]?.path ||
      deleted?.[0]?.value ||
      name;

    const evidenceForTrust =
      pe ||
      fileEvidence[0] ||
      execution.sources?.[0]?.raw ||
      {};

    if (
      fileLooksTrusted(
        representative,
        evidenceForTrust,
        helpers
      )
    ) {
      continue;
    }

    const injectApis =
      pe ? injectionApis(pe) : [];

    const mouseApis =
      pe ? inputApis(pe) : [];

    const catalogMatches =
      catalogMatchesForFile(
        representative,
        evidenceForTrust,
        helpers
      );

    const executed =
      execution.executed === true;

    const executionScope =
      classifyExecutionScope(
        execution,
        rustSession
      );

    const deletedOrMissing =
      deleted.length > 0 ||
      execution.missing === true;

    const usb =
      execution.usbConfirmed === true;

    const unsigned =
      pe?.signed === false ||
      fileEvidence.some(
        (item) => item?.signed === false
      );

    const suspiciousPath =
      suspiciousUserPath(
        representative
      ) ||
      execution.sources.some(
        (source) =>
          suspiciousUserPath(source?.path)
      );

    const genericInstaller =
      isGenericInstaller(representative);

    const knownVersionedOneDriveComponent =
      isKnownVersionedOneDriveComponent(
        representative
      ) ||
      execution.sources.some(
        (source) =>
          isKnownVersionedOneDriveComponent(
            source?.path
          )
      );

    const highRiskName =
      /(^|[^a-z0-9])(injector|aimbot|wallhack|spoofer|cheat|no[ -]?recoil)([^a-z0-9]|$)/i
        .test(name.replace(/\.exe$/i, ""));

    const randomLoaderScore =
      knownVersionedOneDriveComponent
        ? 0
        : Math.max(
            loaderNameScore(
              representative,
              evidenceForTrust
            ),
            loaderNameScore(
              name,
              evidenceForTrust
            )
          );

    const randomLoaderName =
      randomLoaderScore >= 3;

    const packedOrHighEntropy =
      pe?.packedLike === true ||
      pe?.highEntropy === true ||
      safeArray(pe?.packerIndicators)
        .length > 0;

    const strongInjection =
      injectApis.length >= 2;

    const inputSignal =
      mouseApis.length > 0;

    const trustedVersionedOneDriveComponent =
      knownVersionedOneDriveComponent &&
      !usb &&
      !suspiciousPath &&
      unsigned !== true &&
      !packedOrHighEntropy &&
      !strongInjection &&
      !inputSignal &&
      catalogMatches.length === 0 &&
      !highRiskName;

    if (trustedVersionedOneDriveComponent) {
      continue;
    }

    const rustInputContext =
      /rust|recoil|macro|script/i.test(
        representative
      ) ||
      catalogMatches.length > 0;

    let severity = "";
    let title = "";
    let reason = "";

    const explicitCheatExecutable =
      executed &&
      !genericInstaller &&
      highRiskName;

    const behavioralUnknownLoader =
      executed &&
      !genericInstaller &&
      randomLoaderName &&
      (
        usb ||
        deletedOrMissing ||
        suspiciousPath ||
        packedOrHighEntropy ||
        strongInjection
      );

    if (explicitCheatExecutable) {
      severity = "critical";
      title =
        "PRIORIDADE MÁXIMA: executável com nome explícito de cheat executado";
      reason =
        "O executável foi efetivamente executado e o próprio nome contém indicador explícito de cheat/injector/aimbot/wallhack/spoofer/no-recoil. Essa evidência não é rebaixada por estar fora da sessão atual do Rust.";
    } else if (behavioralUnknownLoader) {
      severity = "critical";
      title =
        "PRIORIDADE MÁXIMA: possível loader desconhecido executado";
      reason =
        "O executável possui nome fortemente randômico e foi efetivamente executado em contexto típico de loader (Downloads/Temp/Desktop, USB, ausência posterior, packer/alta entropia ou APIs fortes). A detecção é comportamental, não depende de catálogo e não é rebaixada por IN/OUT-OF-SESSION.";
    } else if (
      usb &&
      executed &&
      executionScope.inSession
    ) {
      severity = "critical";
      title =
        "IN-SESSION: EXE não confiável executado em pendrive/USB";
      reason =
        "A execução em mídia removível ocorreu durante a instância atual do Rust.";
    } else if (
      usb &&
      executed
    ) {
      severity = "medium";
      title =
        "OUT-OF-SESSION: EXE executado em pendrive/USB";
      reason =
        "Há execução confirmada em mídia removível, mas ela não foi temporalmente associada à instância atual do Rust.";
    } else if (
      executed &&
      deletedOrMissing &&
      !genericInstaller &&
      (
        unsigned ||
        strongInjection ||
        catalogMatches.length > 0 ||
        highRiskName
      ) &&
      executionScope.inSession
    ) {
      severity = "critical";
      title =
        "IN-SESSION: EXE executado e posteriormente apagado/ausente";
      reason =
        "A execução ocorreu durante a instância atual do Rust e o executável desapareceu depois, com sinal adicional de risco.";
    } else if (
      executed &&
      deletedOrMissing &&
      !genericInstaller &&
      (
        unsigned ||
        strongInjection ||
        catalogMatches.length > 0 ||
        highRiskName
      )
    ) {
      severity = "medium";
      title =
        "OUT-OF-SESSION: EXE executado e posteriormente apagado/ausente";
      reason =
        "Há execução e ausência posterior com sinal adicional de risco, porém fora da instância atual do Rust ou sem timestamp suficiente.";
    } else if (
      strongInjection &&
      executed &&
      executionScope.inSession
    ) {
      severity = "critical";
      title =
        "IN-SESSION: executável com forte capacidade de injeção";
      reason =
        "O executável foi executado durante a instância atual do Rust e contém múltiplas APIs clássicas de injeção/manipulação de processo.";
    } else if (
      strongInjection &&
      executed
    ) {
      severity = "medium";
      title =
        "OUT-OF-SESSION: executável com forte capacidade de injeção";
      reason =
        "O executável foi executado e contém múltiplas APIs clássicas de injeção, mas a execução não foi associada à instância atual do Rust.";
    } else if (
      catalogMatches.length > 0 &&
      executed &&
      executionScope.inSession
    ) {
      severity = "critical";
      title =
        "IN-SESSION: executável do catálogo com execução confirmada";
      reason =
        "O executável corresponde ao catálogo de ameaça e foi executado durante a instância atual do Rust.";
    } else if (
      catalogMatches.length > 0 &&
      executed
    ) {
      severity = "medium";
      title =
        "OUT-OF-SESSION: executável do catálogo com execução confirmada";
      reason =
        "O executável corresponde ao catálogo e possui evidência de execução, mas não durante a instância atual do Rust.";
    } else if (
      inputSignal &&
      executed &&
      (
        rustInputContext ||
        usb ||
        deletedOrMissing
      ) &&
      executionScope.inSession
    ) {
      severity = "critical";
      title =
        "IN-SESSION: automação de mouse/input em contexto de alto risco";
      reason =
        "mouse_event/SendInput foi executado durante a instância atual do Rust com contexto adicional de script/recoil, USB ou exclusão.";
    } else if (
      inputSignal &&
      executed &&
      (
        rustInputContext ||
        usb ||
        deletedOrMissing
      )
    ) {
      severity = "medium";
      title =
        "OUT-OF-SESSION: automação de mouse/input em contexto de risco";
      reason =
        "mouse_event/SendInput foi observado em executável executado, mas fora da instância atual do Rust ou sem timestamp suficiente.";
    } else if (
      strongInjection
    ) {
      severity = "medium";
      title =
        "Executável com APIs fortes de injeção";
      reason =
        "Foram encontradas múltiplas APIs de injeção, porém esta análise não comprovou execução do executável.";
    } else if (
      catalogMatches.length > 0
    ) {
      severity = "medium";
      title =
        "Executável correspondente ao catálogo";
      reason =
        "O arquivo corresponde ao catálogo, mas não há evidência suficiente de execução nesta análise.";
    } else if (
      inputSignal &&
      executed
    ) {
      severity = "medium";
      title =
        "Executável com automação de mouse/input";
      reason =
        "mouse_event/SendInput foi encontrado em executável com evidência de execução, porém sem contexto adicional suficiente para tratá-lo como recoil de Rust.";
    } else if (
      executed &&
      deletedOrMissing
    ) {
      severity = "medium";
      title =
        genericInstaller
          ? "Instalador/updater executado e posteriormente ausente"
          : "Executável executado e posteriormente ausente";
      reason =
        genericInstaller
          ? "Há execução e ausência posterior, mas instaladores e atualizadores podem remover a si próprios legitimamente."
          : "A execução é comprovada, porém a ausência posterior sem outro sinal técnico forte não é suficiente para classificar como crítico.";
    }

    if (!severity)
      continue;

    await addFinding(
      insertFinding,
      analysisId,
      title,
      severity,
      "correlated_executable_v2",
      representative,
      {
        executableName: name,
        executionConfirmed: executed,
        executionSources:
          execution.sources,
        executionScope:
          executionScope.scope,
        inRustSession:
          executionScope.inSession,
        outOfRustSession:
          executionScope.outOfSession,
        executionTimestampsUtc:
          executionScope.timestamps.map(timestampIso),
        rustSessionStartUtc:
          rustSession.known
            ? timestampIso(rustSession.startMs)
            : "",
        rustSessionEndUtc:
          timestampIso(rustSession.endMs),
        deletedEvidence:
          deleted,
        deletedOrMissing,
        usbExecution: usb,
        usbContext:
          execution.usbContext,
        injectionApis:
          injectApis,
        injectionCapability:
          strongInjection,
        inputApis:
          mouseApis,
        recoilInputApi:
          inputSignal,
        catalogMatches,
        signed:
          pe?.signed,
        suspiciousPath,
        genericInstaller,
        highRiskName,
        explicitCheatExecutable,
        randomLoaderName,
        randomLoaderScore,
        behavioralUnknownLoader,
        packedOrHighEntropy,
        priorityMaximum:
          severity === "critical",
        protectedByTechnicalEngine:
          severity === "critical",
        confidence:
          severity === "critical"
            ? "high"
            : "medium",
        note: reason
      }
    );
  }

  // 2. Confirmed injection/manual-map into Rust.
  for (const item of safeArray(report?.processMemoryIntegrity)) {
    if (item?.potentialManualMap !== true)
      continue;

    const processName =
      String(
        item?.processName ||
        item?.processPath ||
        ""
      ).toLowerCase();

    const rust =
      processName.includes("rustclient") ||
      /(^|\\)rust(?:client)?\.exe$/i
        .test(processName);

    await addFinding(
      insertFinding,
      analysisId,
      rust
        ? "Possível manual-map confirmado na memória do Rust"
        : "Região executável privada com cabeçalho PE",
      rust ? "critical" : "medium",
      "memory_integrity_v2",
      (item?.processName || "processo") +
        " @ " +
        (item?.baseAddress || "memória"),
      {
        ...item,
        manualMapInRust: rust,
        injectionIntoRust: rust,
        priorityMaximum: rust,
        protectedByTechnicalEngine: rust,
        confidence: rust ? "high" : "medium",
        note: rust
          ? "Foi encontrada região MEM_PRIVATE executável com assinatura PE dentro do processo do Rust."
          : "Foi encontrada região executável privada com assinatura PE em outro processo; requer contexto adicional."
      }
    );
  }

  for (const item of safeArray(report?.processModuleIntegrity)) {
    if (item?.suspicious !== true)
      continue;

    const processName =
      String(item?.processName || "")
        .toLowerCase();

    const rust =
      processName === "rust" ||
      processName === "rustclient" ||
      processName.includes("rustclient");

    const moduleValue =
      item?.modulePath ||
      item?.moduleName ||
      "";

    if (
      !rust ||
      fileLooksTrusted(
        moduleValue,
        item,
        helpers
      )
    ) {
      continue;
    }

    await addFinding(
      insertFinding,
      analysisId,
      "Módulo externo suspeito carregado dentro do Rust",
      "critical",
      "rust_module_injection_v2",
      moduleValue,
      {
        ...item,
        injectionIntoRust: true,
        priorityMaximum: true,
        protectedByTechnicalEngine: true,
        confidence: "high",
        note:
          "O módulo foi observado carregado no processo do Rust e não corresponde ao catálogo confiável."
      }
    );
  }

  for (const item of safeArray(report?.rustModules)) {
    const haystack = [
      item?.path,
      item?.moduleName,
      item?.companyName,
      item?.signerSubject
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    const knownOverlay =
      KNOWN_OVERLAY_TOKENS.some(
        (token) => haystack.includes(token)
      );

    const suspicious =
      !knownOverlay &&
      item?.signed === false &&
      item?.underGameDirectory === false &&
      item?.underWindows === false &&
      (
        item?.underTemp === true ||
        (
          item?.underUserProfile === true &&
          item?.underProgramFiles !== true &&
          !item?.companyName
        )
      );

    if (!suspicious)
      continue;

    const value =
      item?.path ||
      item?.moduleName ||
      "";

    if (
      fileLooksTrusted(
        value,
        item,
        helpers
      )
    ) {
      continue;
    }

    await addFinding(
      insertFinding,
      analysisId,
      "Módulo externo não confiável carregado no Rust",
      "critical",
      "rust_module_v2",
      value,
      {
        ...item,
        injectionIntoRust: true,
        priorityMaximum: true,
        protectedByTechnicalEngine: true,
        confidence: "high",
        note:
          "O módulo externo foi carregado dentro do Rust a partir de local de usuário/temporário e não é confiável."
      }
    );
  }

  // 3. Echo-style audit inventory: session timeline, file logs,
  // compilation times and process start times. These are facts, not verdicts.
  const timeline = [];

  const pushTimeline = (
    timestamp,
    category,
    label,
    value,
    extra = {}
  ) => {
    const ms = validDateMs(timestamp);
    if (!ms)
      return;

    timeline.push({
      timestampUtc: timestampIso(ms),
      category,
      label,
      value: String(value || ""),
      ...extra
    });
  };

  for (const item of safeArray(report?.processes)) {
    pushTimeline(
      item?.startTimeUtc,
      "PROCESS_START",
      "Process Start",
      item?.path || item?.name,
      {
        pid: item?.pid,
        signed: item?.signed === true,
        signerSubject: item?.signerSubject || ""
      }
    );
  }

  for (const item of safeArray(report?.processCreationEvents)) {
    pushTimeline(
      item?.timestampUtc ||
      item?.timeCreatedUtc ||
      item?.createdAtUtc,
      "EXECUTED_FILE",
      "Executed File",
      item?.processPath || item?.processName,
      {
        source: "Event 4688"
      }
    );
  }

  for (const item of safeArray(report?.processTerminationEvents)) {
    pushTimeline(
      item?.timestampUtc ||
      item?.timeCreatedUtc ||
      item?.createdAtUtc,
      "CLOSED_PROGRAM",
      "Closed Program",
      item?.processPath || item?.processName,
      {
        source: "Event 4689",
        processId: item?.processId || "",
        exitStatus: item?.exitStatus || ""
      }
    );
  }

  for (const item of safeArray(report?.bam)) {
    pushTimeline(
      item?.lastExecutionUtc,
      "EXECUTED_FILE",
      "Executed File",
      item?.path,
      {
        source: "BAM",
        fileExists: item?.fileExists
      }
    );
  }

  for (const item of safeArray(report?.prefetchExecutions)) {
    pushTimeline(
      item?.lastRunUtc,
      "EXECUTED_FILE",
      "Executed File",
      item?.resolvedExecutablePath ||
      item?.nativeExecutablePath ||
      item?.executableName,
      {
        source: "Prefetch",
        executablePresent:
          item?.executablePresent
      }
    );
  }

  for (const item of safeArray(report?.usnActivity)) {
    const value =
      item?.fileName ||
      item?.volume ||
      "";

    if (item?.Created === true || item?.created === true) {
      pushTimeline(
        item?.timestampUtc,
        "FILE_CREATED",
        "Created File",
        value,
        {
          volume: item?.volume || "",
          reasons: item?.reasons || []
        }
      );
    }

    if (item?.Deleted === true || item?.deleted === true) {
      pushTimeline(
        item?.timestampUtc,
        "FILE_DELETED",
        "Deleted File",
        value,
        {
          volume: item?.volume || "",
          reasons: item?.reasons || []
        }
      );
    }

    if (item?.Renamed === true || item?.renamed === true) {
      pushTimeline(
        item?.timestampUtc,
        "FILE_MOVED",
        "Moved/Renamed File",
        value,
        {
          volume: item?.volume || "",
          reasons: item?.reasons || []
        }
      );
    }

    if (item?.Modified === true || item?.modified === true) {
      pushTimeline(
        item?.timestampUtc,
        "DATA_CHANGE",
        "Data Change",
        value,
        {
          volume: item?.volume || "",
          reasons: item?.reasons || []
        }
      );
    }
  }

  for (const item of safeArray(report?.deletedUsnRecords)) {
    pushTimeline(
      item?.timestampUtc ||
      item?.deletedAtUtc,
      "FILE_DELETED",
      "Deleted File",
      item?.fileName ||
      item?.path ||
      item?.volume,
      {
        source: "USN delete"
      }
    );
  }

  for (const item of safeArray(report?.recycleBin)) {
    pushTimeline(
      item?.deletedAtUtc,
      "FILE_DELETED",
      "Deleted File",
      item?.originalPath ||
      item?.fileName,
      {
        source: "Recycle Bin"
      }
    );
  }

  for (const item of safeArray(report?.usbTimeline)) {
    pushTimeline(
      item?.timestampUtc ||
      item?.timeCreatedUtc ||
      item?.eventTimeUtc,
      "USB_EVENT",
      "Plugged In Device",
      item?.deviceId ||
      item?.evidence ||
      item?.eventId,
      {
        source: "USB timeline"
      }
    );
  }

  timeline.sort((a, b) =>
    validDateMs(a.timestampUtc) -
    validDateMs(b.timestampUtc)
  );

  const sessionTimeline =
    rustSession.known
      ? timeline.filter((entry) => {
          const ms =
            validDateMs(entry.timestampUtc);

          return (
            ms >= rustSession.startMs - 2 * 60 * 1000 &&
            ms <= rustSession.endMs + 5 * 60 * 1000
          );
        })
      : [];

  await addFinding(
    insertFinding,
    analysisId,
    "Timeline forense da sessão (inventário)",
    "info",
    "session_timeline_v3",
    rustSession.known
      ? "Rust session " +
        timestampIso(rustSession.startMs)
      : "Sessão Rust não determinada",
    {
      inventoryOnly: true,
      rustSessionKnown:
        rustSession.known,
      rustSessionStartUtc:
        rustSession.known
          ? timestampIso(rustSession.startMs)
          : "",
      rustSessionEndUtc:
        timestampIso(rustSession.endMs),
      eventCount:
        timeline.length,
      sessionEventCount:
        sessionTimeline.length,
      sessionEvents:
        sessionTimeline.slice(0, 500),
      recentEvents:
        timeline.slice(-500),
      confidence: "info",
      note:
        "Timeline auditável inspirada nos File Logs públicos do Echo. Os eventos são fatos forenses e não são tratados como detecção isoladamente."
    }
  );

  const compilationInventory =
    [
      ...safeArray(report?.files)
        .filter((item) =>
          item?.compilationTimeUtc &&
          /\.exe$/i.test(
            baseName(
              item?.path ||
              item?.name
            )
          )
        )
        .map((item) => ({
          executable:
            item?.path ||
            item?.name,
          compilationTimeUtc:
            item?.compilationTimeUtc,
          signed:
            item?.signed === true,
          signerSubject:
            item?.signerSubject || "",
          sha256:
            item?.sha256 || ""
        })),
      ...safeArray(report?.peInspections)
        .filter((item) =>
          item?.compilationTimeUtc
        )
        .map((item) => ({
          executable:
            item?.path ||
            item?.name,
          compilationTimeUtc:
            item?.compilationTimeUtc,
          signed:
            item?.signed === true,
          signerSubject:
            item?.signerSubject || "",
          sha256:
            item?.sha256 || ""
        }))
    ]
      .filter((item, index, arr) =>
        arr.findIndex((other) =>
          normalizePath(other.executable) ===
            normalizePath(item.executable) &&
          String(other.compilationTimeUtc) ===
            String(item.compilationTimeUtc)
        ) === index
      )
      .sort((a,b) =>
        validDateMs(b.compilationTimeUtc) -
        validDateMs(a.compilationTimeUtc)
      );

  const processStartInventory =
    safeArray(report?.processes)
      .filter((item) =>
        item?.startTimeUtc
      )
      .map((item) => ({
        pid: item?.pid,
        name: item?.name || "",
        path: item?.path || "",
        startTimeUtc:
          item?.startTimeUtc,
        signed:
          item?.signed === true,
        signerSubject:
          item?.signerSubject || ""
      }))
      .sort((a,b) =>
        validDateMs(b.startTimeUtc) -
        validDateMs(a.startTimeUtc)
      );

  await addFinding(
    insertFinding,
    analysisId,
    "Compilation Times / Process Start Times (inventário)",
    "info",
    "time_inventory_v3",
    "Metadados temporais de executáveis/processos",
    {
      inventoryOnly: true,
      compilationTimes:
        compilationInventory.slice(0, 1000),
      processStartTimes:
        processStartInventory.slice(0, 1000),
      confidence: "info",
      note:
        "Compilation Times e Process Start Times são exibidos para auditoria e correlação temporal. Nenhum deles é prova de cheat isoladamente."
    }
  );

  const pcaViewer =
    safeArray(report?.pca)
      .filter((item) =>
        /\.exe$/i.test(
          baseName(item?.path)
        )
      )
      .map((item) => ({
        path: item?.path || "",
        source: item?.source || "",
        fileExists: item?.fileExists
      }));

  const amcacheViewer =
    safeArray(report?.amcache)
      .filter((item) =>
        /\.exe$/i.test(
          baseName(
            item?.fullPath ||
            item?.name
          )
        )
      )
      .map((item) => ({
        path:
          item?.fullPath ||
          item?.name ||
          "",
        sha1:
          item?.sha1 || "",
        fileId:
          item?.fileId || "",
        lastWriteUtc:
          item?.lastWriteUtc || null
      }));

  const shimCacheViewer =
    safeArray(report?.shimCache)
      .filter((item) =>
        /\.exe$/i.test(
          baseName(item?.path)
        )
      )
      .map((item) => ({
        path: item?.path || "",
        lastModifiedUtc:
          item?.lastModifiedUtc || null,
        executed:
          item?.executed
      }));

  const userAssistViewer =
    safeArray(report?.userAssist)
      .filter((item) =>
        /\.exe(?:$|[?#])/i.test(
          String(item?.decodedName || "")
        )
      )
      .map((item) => ({
        decodedName:
          item?.decodedName || "",
        guid:
          item?.guid || "",
        dataLength:
          item?.dataLength || 0
      }));

  await addFinding(
    insertFinding,
    analysisId,
    "PCA / Amcache / ShimCache / UserAssist Viewer (inventário)",
    "info",
    "execution_artifact_viewer_v3",
    "Artefatos históricos de execução",
    {
      inventoryOnly: true,
      pcaClient:
        pcaViewer.slice(0, 1500),
      amcache:
        amcacheViewer.slice(0, 1500),
      shimCache:
        shimCacheViewer.slice(0, 1500),
      userAssist:
        userAssistViewer.slice(0, 1500),
      confidence: "info",
      note:
        "Viewer de artefatos de execução inspirado nas ferramentas públicas do Echo. PCA/Amcache/ShimCache/UserAssist servem para correlação e não geram verdictos isoladamente."
    }
  );

  const recordingTokens = [
    "obs",
    "bandicam",
    "xsplit",
    "streamlabs",
    "medal",
    "action!",
    "camtasia",
    "fraps",
    "nvidia share",
    "shadowplay"
  ];

  const recordingSoftware =
    safeArray(report?.processes)
      .filter((item) => {
        const haystack =
          (
            String(item?.name || "") +
            " " +
            String(item?.path || "")
          ).toLowerCase();

        return recordingTokens.some(
          (token) =>
            haystack.includes(token)
        );
      })
      .map((item) => ({
        name: item?.name || "",
        path: item?.path || "",
        startTimeUtc:
          item?.startTimeUtc || null,
        signed:
          item?.signed === true,
        signerSubject:
          item?.signerSubject || ""
      }));

  if (recordingSoftware.length > 0) {
    await addFinding(
      insertFinding,
      analysisId,
      "Software de gravação/captura ativo (inventário)",
      "info",
      "recording_software_v3",
      recordingSoftware[0]?.name ||
      "Recording software",
      {
        inventoryOnly: true,
        recordingSoftware,
        confidence: "info",
        note:
          "Software de gravação/captura foi encontrado em execução. É exibido apenas como contexto de screenshare, sem ser tratado como cheat."
      }
    );
  }

  await addFinding(
    insertFinding,
    analysisId,
    "Ambiente da máquina (inventário)",
    "info",
    "environment_inventory_v3",
    report?.vmEnvironment?.isVirtualMachine
      ? "Virtual machine: " +
        String(
          report?.vmEnvironment?.detectedPlatform ||
          "detectada"
        )
      : "Máquina física / VM não detectada",
    {
      inventoryOnly: true,
      vmEnvironment:
        report?.vmEnvironment || {},
      recycleBinEntryCount:
        safeArray(report?.recycleBin).length,
      hiddenVolumeCount:
        safeArray(report?.hiddenVolumes).length,
      securityProducts:
        safeArray(report?.securityProducts).slice(0, 100),
      confidence: "info",
      note:
        "Resumo de ambiente equivalente às informações auxiliares exibidas em scans de screenshare. Não é detecção por si só."
    }
  );

  // 3. Web evidence. Direct navigation to a domain present in the cheat
  // catalog is critical by policy. Search-engine queries remain review context.
  const directHosts = new Set();
  const searches = new Set();
  const contextualPages = new Set();

  for (const item of safeArray(report?.browserHistorySignals)) {
    const direct =
      directCatalogWebMatch(
        item,
        helpers
      );

    const navigationUrl =
      item?.url ||
      item?.pageUrl ||
      item?.siteUrl ||
      "";

    const searchEngineNavigation =
      isSearchEngineUrl(navigationUrl);

    if (direct && !searchEngineNavigation) {
      const url =
        navigationUrl ||
        item?.host ||
        "";

      const host =
        hostOf(url) ||
        hostOf(item?.url) ||
        String(item?.host || "")
          .toLowerCase()
          .replace(/^www\./, "");

      const key =
        host ||
        String(
          direct?.direct?.name ||
          direct?.direct?.matchedBy ||
          url
        ).toLowerCase();

      if (!directHosts.has(key)) {
        directHosts.add(key);

        await addFinding(
          insertFinding,
          analysisId,
          "PRIORIDADE MÁXIMA: site do catálogo de cheat acessado diretamente",
          "critical",
          "browser_catalog_visit_v2",
          url || key,
          {
            ...item,
            catalogMatch:
              direct.direct,
            catalogMatches:
              direct.matches,
            directCatalogMatch: true,
            knownCheatDomain: true,
            searchEngineNavigation: false,
            priorityMaximum: true,
            protectedByTechnicalEngine: true,
            confidence: "high",
            note:
              "O histórico registra navegação direta para um domínio presente no catálogo de cheat. Pesquisas em mecanismos de busca não entram nesta regra. A classificação crítica confirma o acesso ao domínio catalogado, não a execução de cheat/loader."
          }
        );
      }

      continue;
    }

    if (
      item?.searchQuery &&
      explicitSearchIntent(
        item,
        helpers
      )
    ) {
      const query =
        String(item.searchQuery)
          .trim()
          .toLowerCase();

      if (!searches.has(query)) {
        searches.add(query);

        await addFinding(
          insertFinding,
          analysisId,
          "Pesquisa explícita relacionada a cheat/script de Rust",
          "medium",
          "browser_search_v2",
          item.searchQuery,
          {
            ...item,
            confidence: "medium",
            note:
              "Pesquisa explícita é contexto para revisão. Não equivale a download ou execução."
          }
        );
      }

      continue;
    }

    const title =
      String(item?.title || "");

    const pageValue =
      title +
      " " +
      String(item?.url || "");

    if (
      hasActionableRustCheatPageIntent(title) &&
      !isSearchEngineUrl(item?.url)
    ) {
      const key =
        hostOf(item?.url) ||
        item?.url ||
        title;

      if (!contextualPages.has(key)) {
        contextualPages.add(key);

        await addFinding(
          insertFinding,
          analysisId,
          "Página com conteúdo explícito de cheat/script para Rust",
          "medium",
          "browser_context_v2",
          item?.url || title,
          {
            ...item,
            confidence: "medium",
            note:
              "O título da página contém contexto explícito de Rust + cheat/script. Mantido como revisão, não como prova de uso."
          }
        );
      }
    }
  }

  // Recovered browser fragments are noisy. Only keep a valid direct catalog URL.
  for (const item of safeArray(report?.browserRecoveredArtifacts)) {
    const value =
      item?.recoveredUrl ||
      "";

    if (!/^https?:\/\//i.test(value))
      continue;

    const direct =
      directCatalogWebMatch(
        {
          ...item,
          url: value,
          recoveredUrl: value
        },
        helpers
      );

    if (!direct)
      continue;

    const host =
      hostOf(value);

    if (!host || directHosts.has(host))
      continue;

    directHosts.add(host);

    await addFinding(
      insertFinding,
      analysisId,
      "Vestígio recuperado de domínio do catálogo",
      "medium",
      "browser_recovery_v2",
      value,
      {
        ...item,
        catalogMatch:
          direct.direct,
        catalogMatches:
          direct.matches,
        directCatalogMatch: true,
        knownCheatDomain: true,
        confidence: "context",
        note:
          "Fragmento recuperado aponta para domínio do catálogo. Como a origem é recuperação SQLite/WAL, é mantido apenas para revisão."
      }
    );
  }

  // Browser database deletion is inventory only.
  for (const item of safeArray(report?.usnActivity)) {
    if (item?.browserDatabase !== true)
      continue;

    await addFinding(
      insertFinding,
      analysisId,
      "Banco de histórico do navegador apagado/alterado (inventário)",
      "info",
      "browser_history_inventory_v2",
      item?.fileName ||
      item?.name ||
      "History",
      {
        ...item,
        inventoryOnly: true,
        confidence: "info",
        note:
          "Alteração/exclusão de History/places.sqlite é inventário forense e não é tratada como suspeita."
      }
    );
  }

  // 4. Download context. Visiting a catalog site is review context, but
  // successfully downloading an executable/archive payload directly from a
  // known cheat catalog source is itself a strong acquisition signal.
  const downloadSeen = new Set();

  for (const item of safeArray(report?.browserDownloads)) {
    const value =
      item?.targetPath ||
      item?.fileName ||
      item?.finalUrl ||
      item?.sourceUrl ||
      "";

    const extension =
      extName(value);

    const direct =
      directCatalogWebMatch(
        item,
        helpers
      );

    const payloadExtensions =
      new Set([
        ".exe", ".dll", ".sys", ".com", ".scr",
        ".msi", ".zip", ".rar", ".7z"
      ]);

    const dangerousPayload =
      payloadExtensions.has(extension);

    const downloadCompleted =
      String(item?.state || "")
        .toLowerCase() === "complete" ||
      item?.fileExists === true ||
      Number(item?.receivedBytes || 0) > 0 &&
        Number(item?.receivedBytes || 0) >=
        Number(item?.totalBytes || 0);

    const directCatalogPayload =
      Boolean(direct) &&
      dangerousPayload &&
      downloadCompleted;

    const downloadedName =
      baseName(value);

    const downloadExecution =
      downloadedName
        ? executionIndex.get(downloadedName)
        : null;

    const downloadExecutionScope =
      downloadExecution
        ? classifyExecutionScope(
            downloadExecution,
            rustSession
          )
        : {
            scope: "unknown",
            inSession: false,
            outOfSession: false,
            timestamps: []
          };

    const executionConfirmed =
      downloadExecution?.executed === true;

    const executionSources =
      safeArray(downloadExecution?.sources)
        .map((source) => source?.source)
        .filter(Boolean);

    const discordAttachment =
      [".exe", ".zip", ".rar", ".7z"]
        .includes(extension) &&
      /(?:cdn\.discordapp\.com|media\.discordapp\.net|discordattachments\.com)\/attachments\//i
        .test(
          [
            item?.sourceUrl,
            item?.finalUrl,
            item?.referrerUrl
          ]
            .filter(Boolean)
            .join(" ")
        );

    if (!direct && !discordAttachment)
      continue;

    const key =
      normalizePath(value);

    if (downloadSeen.has(key))
      continue;

    downloadSeen.add(key);

    const severity =
      directCatalogPayload
        ? "critical"
        : "medium";

    await addFinding(
      insertFinding,
      analysisId,
      directCatalogPayload && executionConfirmed
        ? "PRIORIDADE MÁXIMA: payload do catálogo baixado e executado"
        : directCatalogPayload
          ? "PRIORIDADE MÁXIMA: payload baixado diretamente de fonte do catálogo"
          : direct
          ? "Arquivo baixado a partir de fonte do catálogo"
          : "Executável/arquivo compactado baixado de anexo real do Discord",
      severity,
      "browser_download_v3",
      value,
      {
        ...item,
        catalogMatch:
          direct?.direct || null,
        catalogMatches:
          direct?.matches || [],
        directCatalogMatch:
          Boolean(direct),
        knownCheatDomain:
          Boolean(direct),
        discordAttachment,
        dangerousPayload,
        downloadCompleted,
        directCatalogPayload,
        executionConfirmed,
        executionSources,
        sessionRelation:
          downloadExecutionScope.scope,
        executionTimestampsUtc:
          downloadExecutionScope.timestamps
            .map(timestampIso),
        priorityMaximum:
          directCatalogPayload,
        protectedByTechnicalEngine:
          directCatalogPayload,
        confidence:
          directCatalogPayload
            ? "high"
            : "medium",
        note:
          directCatalogPayload && executionConfirmed
            ? "O navegador registrou download concluído de payload executável/compactado diretamente de domínio presente no catálogo de cheat e o mesmo filename possui evidência independente de execução em artefatos do Windows."
            : directCatalogPayload
              ? "O navegador registrou download concluído de payload executável/compactado diretamente de domínio presente no catálogo de cheat. Diferente de uma simples visita ao site, a aquisição do payload é tratada como evidência crítica."
              : "O download é contexto de revisão. Arquivos não executáveis ou downloads sem conclusão permanecem em revisão até existir evidência técnica adicional."
      }
    );
  }

  // 5. Steam bans: Rust-specific/server bans are critical; generic bans are context.
  for (const account of safeArray(report?.steamAccounts)) {
    const consensus =
      account?.banConsensus || {};

    if (consensus?.banDetected !== true)
      continue;

    const serverBanCount =
      Number(
        account?.providerChecks?.serverArmour?.serverBanCount || 0
      );

    const rustSpecific =
      consensus?.rustSpecific === true ||
      account?.providerChecks?.steam?.rustSpecific === true;

    const critical =
      serverBanCount > 0 ||
      rustSpecific;

    await addFinding(
      insertFinding,
      analysisId,
      critical
        ? "Conta Steam com ban relacionado ao Rust/servidores"
        : "Conta Steam com histórico de ban",
      critical ? "critical" : "medium",
      "steam_account_ban_v2",
      String(
        account?.steamId64 ||
        "Steam"
      ),
      {
        steamId64:
          account?.steamId64 || "",
        accountName:
          account?.accountName || "",
        personaName:
          account?.personaName || "",
        profileUrl:
          account?.profileUrl || "",
        isLinkedAccount:
          account?.isLinkedAccount === true,
        mostRecent:
          account?.mostRecent === true,
        providerChecks:
          account?.providerChecks || {},
        banConsensus:
          consensus,
        priorityMaximum:
          critical,
        protectedByTechnicalEngine:
          critical,
        confidence:
          critical ? "high" : "context",
        note:
          critical
            ? "A fonte consultada indica ban relacionado ao Rust ou ban aplicado por servidor. Revise motivo e data."
            : "Existe histórico genérico de ban na conta Steam. Mantido como contexto porque o PC pode ser compartilhado e o ban pode ser de outro jogo."
      }
    );
  }

  // 6. Echo-inspired environmental warnings / anti-forensics context.
  const warningKeys = new Set();

  const addWarning = async (
    key,
    title,
    value,
    evidence
  ) => {
    if (warningKeys.has(key))
      return;
    warningKeys.add(key);

    await addFinding(
      insertFinding,
      analysisId,
      title,
      "medium",
      "environment_warning_v3",
      value,
      {
        ...evidence,
        warningOnly: true,
        confidence: "context"
      }
    );
  };

  for (const item of safeArray(report?.systemIntegrityExpansion)) {
    const kind =
      String(item?.kind || "")
        .toLowerCase();
    const name =
      String(item?.name || "");
    const detail =
      String(item?.detail || "");
    const combined =
      (name + " " + detail)
        .toLowerCase();

    if (
      kind === "service_state" &&
      /pcasvc|diagtrack|eventlog|dps/.test(combined) &&
      /start=4/.test(combined)
    ) {
      await addWarning(
        "service_disabled:" + name.toLowerCase(),
        "Warning: serviço forense/importante desativado",
        name || detail,
        {
          ...item,
          note:
            "Serviço importante para rastreabilidade do Windows está desativado. Isso é incomum e exige contexto, mas não prova cheat."
        }
      );
      continue;
    }

    if (
      kind === "service_start_type_change" &&
      /pcasvc|diagtrack|eventlog|dps/.test(combined)
    ) {
      await addWarning(
        "service_change:" + combined.slice(0,120),
        "Warning: tipo de inicialização de serviço importante foi alterado",
        name || detail,
        {
          ...item,
          note:
            "O Service Control Manager registrou alteração recente em serviço relevante para telemetria/compatibilidade."
        }
      );
      continue;
    }

    if (
      kind === "prefetch_state" &&
      /arquivos pf atuais:\s*0|não localizado/.test(combined)
    ) {
      await addWarning(
        "prefetch_missing",
        "Warning: Prefetch vazio ou indisponível",
        detail || "Windows Prefetch",
        {
          ...item,
          note:
            "Prefetch vazio/desabilitado pode reduzir rastreabilidade. Mantido como warning, nunca como prova isolada."
        }
      );
      continue;
    }

    if (
      kind === "srum_state" &&
      /não localizado/.test(combined)
    ) {
      await addWarning(
        "srum_missing",
        "Warning: SRUM não localizado",
        detail || "SRUDB.dat",
        {
          ...item,
          note:
            "SRUDB.dat ausente é incomum e pode reduzir contexto forense; exige revisão apenas contextual."
        }
      );
    }
  }

  for (const item of safeArray(report?.logClearSignals)) {
    await addWarning(
      "log_clear:" +
        String(item?.channel || "") +
        ":" +
        String(item?.signal || ""),
      "Warning: log do Windows limpo recentemente",
      item?.signal ||
      item?.channel ||
      "Event Log",
      {
        ...item,
        note:
          "O Windows registrou limpeza recente de log. Isso pode ter motivo legítimo; é warning de anti-forensics, não prova de cheat."
      }
    );
  }

  if (
    report?.systemArtifacts?.PrefetchDirectoryExists === false ||
    report?.systemArtifacts?.EnablePrefetcher === 0
  ) {
    await addWarning(
      "system_prefetch_disabled",
      "Warning: Prefetch desabilitado/indisponível",
      "Windows Prefetch",
      {
        ...report.systemArtifacts,
        note:
          "O mecanismo Prefetch está desabilitado ou indisponível, reduzindo a visibilidade histórica de execução."
      }
    );
  }

  if (
    report?.systemArtifacts?.BamStart === 4
  ) {
    await addWarning(
      "bam_disabled",
      "Warning: BAM desabilitado",
      "Background Activity Moderator",
      {
        ...report.systemArtifacts,
        note:
          "O BAM está configurado como desabilitado. Mantido como warning de integridade forense."
      }
    );
  }

  const disabledKeyServices =
    safeArray(report?.systemIntegrityExpansion)
      .filter((item) => {
        const kind =
          String(item?.kind || "")
            .toLowerCase();
        const combined =
          (
            String(item?.name || "") +
            " " +
            String(item?.detail || "")
          ).toLowerCase();

        return (
          kind === "service_state" &&
          /pcasvc|diagtrack|eventlog|dps/.test(combined) &&
          /start=4/.test(combined)
        );
      })
      .map((item) =>
        String(item?.name || "serviço")
      );

  if (disabledKeyServices.length >= 2) {
    await addWarning(
      "multiple_key_features_disabled",
      "Warning: recursos importantes do Windows desativados limitando resultados",
      disabledKeyServices.join(", "),
      {
        disabledServices:
          disabledKeyServices,
        note:
          "Múltiplos serviços relevantes para telemetria/compatibilidade estão desativados. Isso reduz a qualidade do scan e corresponde a um warning, não a uma detecção severa."
      }
    );
  }

  const explorer =
    safeArray(report?.processes)
      .filter((item) =>
        String(item?.name || "")
          .toLowerCase() === "explorer" ||
        /(^|\\)explorer\.exe$/i
          .test(String(item?.path || ""))
      )
      .map((item) => ({
        item,
        ms: validDateMs(item?.startTimeUtc)
      }))
      .filter((entry) => entry.ms > 0)
      .sort((a,b) => b.ms-a.ms)[0];

  if (
    explorer &&
    rustSession.known &&
    explorer.ms > rustSession.startMs + 2 * 60 * 1000
  ) {
    await addWarning(
      "explorer_restart_in_session",
      "Warning: Explorer reiniciado durante a instância do Rust",
      explorer.item?.path ||
      "explorer.exe",
      {
        ...explorer.item,
        inRustSession: true,
        explorerStartUtc:
          timestampIso(explorer.ms),
        rustSessionStartUtc:
          timestampIso(rustSession.startMs),
        note:
          "explorer.exe iniciou depois do Rust. Reinício recente do Explorer é contexto incomum porque pode alterar artefatos de execução; exige revisão."
      }
    );
  }

  const veraCryptPresent =
    safeArray(report?.processes)
      .some((item) =>
        /veracrypt/i.test(
          String(item?.name || "") +
          " " +
          String(item?.path || "")
        )
      ) ||
    safeArray(report?.services)
      .some((item) =>
        /veracrypt/i.test(
          String(item?.name || "") +
          " " +
          String(item?.displayName || "") +
          " " +
          String(item?.pathName || "")
        )
      );

  if (veraCryptPresent) {
    await addWarning(
      "veracrypt_present",
      "Warning: VeraCrypt detectado",
      "VeraCrypt",
      {
        note:
          "Volume criptografado/contêiner pode ocultar arquivos históricos. A presença do VeraCrypt é contexto apenas e não implica cheat."
      }
    );
  }

  // 6. Defender detections are review context unless independently correlated above.
  for (const item of safeArray(report?.defenderDetections)) {
    const value =
      item?.path ||
      item?.threatName ||
      "";

    if (
      fileLooksTrusted(
        value,
        item,
        helpers
      )
    ) {
      continue;
    }

    const text =
      [
        item?.threatName,
        item?.path,
        item?.resources
      ]
        .filter(Boolean)
        .join(" ");

    if (
      !/cheat|hack|inject|loader|aimbot|recoil|trojan|malware/i
        .test(text)
    ) {
      continue;
    }

    await addFinding(
      insertFinding,
      analysisId,
      "Detecção do Microsoft Defender para revisão",
      "medium",
      "defender_detection_v2",
      value,
      {
        ...item,
        confidence: "medium",
        note:
          "Detecção do antivírus é contexto útil, mas pode conter falso positivo. Exige correlação com execução/arquivo."
      }
    );
  }

  // 7. Boot integrity changes are review context, never proof alone.
  for (const item of safeArray(report?.bootIntegrity)) {
    const raw =
      String(item?.raw || "")
        .toLowerCase();

    const risky =
      /(testsigning|nointegritychecks|debug)/i
        .test(raw) &&
      /\b(yes|on|true|1)\b/i
        .test(raw);

    if (!risky)
      continue;

    await addFinding(
      insertFinding,
      analysisId,
      "Integridade de boot do Windows alterada",
      "medium",
      "boot_integrity_v2",
      item?.raw ||
      item?.setting ||
      "BCD",
      {
        ...item,
        confidence: "context",
        note:
          "Test mode/debug/nointegritychecks reduzem garantias do Windows, mas não provam cheat isoladamente."
      }
    );
  }
}
