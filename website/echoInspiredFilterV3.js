import { runCalibratedFilterV2 } from "./calibratedFilterV2.js";

const V4_VERSION = "forensic-confidence-v4";

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function validMs(value) {
  const ms = new Date(value || 0).getTime();
  return Number.isFinite(ms) && ms > 0 ? ms : 0;
}

function normalizeName(value) {
  return String(value || "")
    .replaceAll("/", "\\")
    .split("\\")
    .filter(Boolean)
    .at(-1)
    ?.toLowerCase() || "";
}

function isRustProcess(value) {
  const name = normalizeName(value)
    .replace(/\.exe$/i, "");

  return (
    name === "rust" ||
    name === "rustclient"
  );
}

function scanEndMs(report) {
  return (
    validMs(report?.collectedAtUtc) ||
    Date.now()
  );
}

function detectRustSession(report) {
  const endMs = scanEndMs(report);
  const currentRust =
    safeArray(report?.processes)
      .filter((process) =>
        isRustProcess(
          process?.path ||
          process?.name
        )
      );

  const currentStarts =
    currentRust
      .map((process) =>
        validMs(process?.startTimeUtc)
      )
      .filter(Boolean);

  if (currentStarts.length > 0) {
    return {
      active: true,
      source: "process_snapshot",
      startMs: Math.min(...currentStarts),
      endMs
    };
  }

  // Some protected game processes deny StartTime/MainModule access.
  // If RustClient is visibly active, recover the session start from
  // independent execution artifacts instead of declaring the session unknown.
  if (currentRust.length > 0) {
    const fallbackTimes = [];

    for (const item of safeArray(
      report?.processCreationEvents
    )) {
      if (
        isRustProcess(
          item?.processPath ||
          item?.processName
        )
      ) {
        const ms =
          validMs(item?.timeCreatedUtc);

        if (ms)
          fallbackTimes.push({
            ms,
            source: "event_4688"
          });
      }
    }

    for (const item of safeArray(
      report?.prefetchExecutions
    )) {
      if (
        isRustProcess(
          item?.resolvedExecutablePath ||
          item?.nativeExecutablePath ||
          item?.executableName
        )
      ) {
        const times =
          safeArray(item?.lastRunTimesUtc)
            .length > 0
            ? item.lastRunTimesUtc
            : [item?.lastRunUtc];

        for (const value of times) {
          const ms = validMs(value);

          if (ms && ms <= endMs) {
            fallbackTimes.push({
              ms,
              source: "prefetch"
            });
          }
        }
      }
    }

    for (const item of safeArray(
      report?.bam
    )) {
      if (
        isRustProcess(item?.path)
      ) {
        const ms =
          validMs(item?.lastExecutionUtc);

        if (ms && ms <= endMs) {
          fallbackTimes.push({
            ms,
            source: "bam"
          });
        }
      }
    }

    if (fallbackTimes.length > 0) {
      // For an active process, the newest coherent Rust launch evidence is the
      // best approximation of the current game instance start.
      fallbackTimes.sort(
        (a, b) => b.ms - a.ms
      );

      return {
        active: true,
        source:
          "active_process+" +
          fallbackTimes[0].source,
        startMs:
          fallbackTimes[0].ms,
        endMs
      };
    }

    return {
      active: true,
      source:
        "process_snapshot_no_start_time",
      startMs: 0,
      endMs
    };
  }

  const historicalStarts =
    safeArray(report?.processCreationEvents)
      .filter((item) =>
        isRustProcess(
          item?.processPath ||
          item?.processName
        )
      )
      .map((item) =>
        validMs(item?.timeCreatedUtc)
      )
      .filter(Boolean)
      .sort((a, b) => b - a);

  if (historicalStarts.length > 0) {
    return {
      active: false,
      source: "event_4688",
      startMs: historicalStarts[0],
      endMs
    };
  }

  return {
    active: false,
    source: "unresolved",
    startMs: 0,
    endMs
  };
}

function executionTimesFromSource(source) {
  const raw =
    source?.raw ||
    source ||
    {};

  const times = [
    source?.timeCreatedUtc,
    source?.startTimeUtc,
    source?.lastRunUtc,
    source?.lastExecutionUtc,
    raw?.timeCreatedUtc,
    raw?.startTimeUtc,
    raw?.lastRunUtc,
    raw?.lastExecutionUtc,
  ]
    .map(validMs)
    .filter(Boolean);

  for (const value of safeArray(raw?.lastRunTimesUtc)) {
    const ms = validMs(value);
    if (ms)
      times.push(ms);
  }

  return times;
}

function relationForEvidence(
  evidence,
  session
) {
  if (
    evidence?.injectionIntoRust === true ||
    evidence?.manualMapInRust === true
  ) {
    return "in_instance";
  }

  const times = [];

  for (const source of safeArray(
    evidence?.executionSources
  )) {
    times.push(
      ...executionTimesFromSource(source)
    );
  }

  for (const value of safeArray(
    evidence?.sourceFindings
  )) {
    const ev =
      value?.evidence || value;

    for (const source of safeArray(
      ev?.executionSources
    )) {
      times.push(
        ...executionTimesFromSource(source)
      );
    }
  }

  if (!session?.startMs) {
    return times.length > 0
      ? "no_game_instance"
      : "unknown";
  }

  if (times.length === 0)
    return "unknown";

  const graceBefore =
    session.startMs - 2 * 60 * 1000;

  const graceAfter =
    session.endMs + 2 * 60 * 1000;

  if (
    times.some(
      (ms) =>
        ms >= graceBefore &&
        ms <= graceAfter
    )
  ) {
    return "in_instance";
  }

  if (
    times.every(
      (ms) => ms < graceBefore
    )
  ) {
    return "out_of_instance";
  }

  return "unknown";
}

function adjustExecutableSeverity(
  title,
  severity,
  evidence,
  sessionRelation
) {
  let nextSeverity =
    String(severity || "medium")
      .toLowerCase();

  let nextTitle = String(title || "");

  const technicalInsideRust =
    evidence?.injectionIntoRust === true ||
    evidence?.manualMapInRust === true;

  const knownCheatExecutable =
    evidence?.knownCheatExecutable === true;

  const explicitCheatExecutable =
    evidence?.explicitCheatExecutable === true;

  const behavioralUnknownLoader =
    evidence?.behavioralUnknownLoader === true &&
    evidence?.executionConfirmed === true &&
    evidence?.randomLoaderName === true &&
    Number(evidence?.randomLoaderScore || 0) >= 4;

  const protectedExecutedThreat =
    evidence?.executionConfirmed === true &&
    (
      knownCheatExecutable ||
      explicitCheatExecutable ||
      behavioralUnknownLoader
    );

  if (protectedExecutedThreat) {
    const prefix =
      knownCheatExecutable
        ? "CHEAT CONHECIDO · "
        : explicitCheatExecutable
          ? "CHEAT/INJECTOR EXECUTADO · "
          : "LOADER SUSPEITO EXECUTADO · ";

    return {
      severity: "critical",
      title: prefix + nextTitle,
    };
  }

  if (technicalInsideRust) {
    return {
      severity: "critical",
      title: nextTitle,
    };
  }

  if (
    nextSeverity === "critical" &&
    evidence?.executionConfirmed === true
  ) {
    if (
      sessionRelation === "out_of_instance" ||
      sessionRelation === "no_game_instance"
    ) {
      nextSeverity = "medium";
      nextTitle =
        "Executado fora da instância atual · " +
        nextTitle;
    } else if (
      sessionRelation === "unknown"
    ) {
      // If we cannot place the execution inside the current Rust session,
      // keep only exceptionally strong technical signals critical.
      const exceptionallyStrong =
        (
          evidence?.usbExecution === true &&
          evidence?.injectionCapability === true
        ) ||
        explicitCheatExecutable ||
        behavioralUnknownLoader ||
        knownCheatExecutable;

      if (!exceptionallyStrong) {
        nextSeverity = "medium";
        nextTitle =
          "Execução sem relação temporal confirmada com Rust · " +
          nextTitle;
      }
    }
  }

  return {
    severity: nextSeverity,
    title: nextTitle,
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
    {
      baselineV2: true,
      baselineV3: true,
      baselineV4: true,
      classifierVersion: V4_VERSION,
      ...evidence
    }
  );
}

function parseStartFromServiceDetail(detail) {
  const match =
    String(detail || "")
      .match(/\bStart=(\d+|\?)\b/i);

  return match && match[1] !== "?"
    ? Number(match[1])
    : null;
}

function eventTime(item) {
  return (
    validMs(item?.timestampUtc) ||
    validMs(item?.timeCreatedUtc) ||
    validMs(item?.lastExecutionUtc) ||
    validMs(item?.lastRunUtc) ||
    validMs(item?.startTimeUtc) ||
    validMs(item?.lastWriteUtc) ||
    validMs(item?.deletedAtUtc) ||
    validMs(item?.shortcutLastWriteUtc)
  );
}

function relationForTime(ms, session) {
  if (!ms)
    return "unknown";

  if (!session?.startMs)
    return "no_game_instance";

  if (
    ms >= session.startMs - 2 * 60 * 1000 &&
    ms <= session.endMs + 2 * 60 * 1000
  ) {
    return "in_instance";
  }

  if (ms < session.startMs)
    return "out_of_instance";

  return "unknown";
}

function buildTimeline(report, session) {
  const events = [];

  const push = (
    timestamp,
    category,
    action,
    value,
    source,
    details = {}
  ) => {
    const ms = validMs(timestamp);
    if (!ms)
      return;

    events.push({
      timestampUtc:
        new Date(ms).toISOString(),
      relation:
        relationForTime(ms, session),
      category,
      action,
      value:
        String(value || "").slice(0, 800),
      source,
      details
    });
  };

  for (const item of safeArray(
    report?.processCreationEvents
  )) {
    push(
      item?.timeCreatedUtc,
      "process",
      "executed",
      item?.processPath ||
      item?.processName,
      "Event 4688",
      {
        parent:
          item?.parentProcessPath ||
          item?.parentProcessName,
        present:
          item?.processPresent,
        driveType:
          item?.driveType
      }
    );
  }

  for (const item of safeArray(
    report?.prefetchExecutions
  )) {
    const times =
      safeArray(item?.lastRunTimesUtc)
        .length > 0
        ? item.lastRunTimesUtc
        : [item?.lastRunUtc];

    for (const timestamp of times) {
      push(
        timestamp,
        "process",
        "executed",
        item?.resolvedExecutablePath ||
        item?.nativeExecutablePath ||
        item?.executableName,
        "Prefetch",
        {
          runCount:
            item?.runCount,
          executablePresent:
            item?.executablePresent,
          currentRemovable:
            item?.currentRemovable,
          volumeNotMounted:
            item?.volumeNotMounted
        }
      );
    }
  }

  for (const item of safeArray(
    report?.bam
  )) {
    push(
      item?.lastExecutionUtc,
      "process",
      "executed",
      item?.path,
      "BAM",
      {
        fileExists:
          item?.fileExists
      }
    );
  }

  for (const item of safeArray(
    report?.processes
  )) {
    push(
      item?.startTimeUtc,
      "process",
      "process_start",
      item?.path ||
      item?.name,
      "Process snapshot",
      {
        pid: item?.pid,
        signed: item?.signed,
        signer:
          item?.signerSubject
      }
    );
  }

  for (const item of safeArray(
    report?.processTerminationEvents
  )) {
    push(
      item?.timeCreatedUtc,
      "process",
      "closed",
      item?.processPath ||
      item?.processName,
      "Event 4689",
      {
        processId:
          item?.processId,
        exitStatus:
          item?.exitStatus
      }
    );
  }

  for (const item of safeArray(
    report?.usnActivity
  )) {
    const actions = [];

    if (item?.Created === true ||
        item?.created === true)
      actions.push("created");

    if (item?.Deleted === true ||
        item?.deleted === true)
      actions.push("deleted");

    if (item?.Renamed === true ||
        item?.renamed === true)
      actions.push("renamed");

    if (item?.Modified === true ||
        item?.modified === true)
      actions.push("modified");

    if (actions.length === 0)
      continue;

    for (const action of actions) {
      push(
        item?.timestampUtc,
        "file",
        action,
        item?.fileName ||
        item?.volume,
        "USN Journal",
        {
          extension:
            item?.extension,
          volume:
            item?.volume,
          driveType:
            item?.driveType,
          reasons:
            item?.reasons
        }
      );
    }
  }

  for (const item of safeArray(
    report?.deletedUsnRecords
  )) {
    push(
      item?.timestampUtc,
      "file",
      "deleted",
      item?.fileName ||
      item?.volume,
      "USN delete",
      {
        extension:
          item?.extension,
        volume:
          item?.volume,
        driveType:
          item?.driveType,
        reason:
          item?.reason
      }
    );
  }

  for (const item of safeArray(
    report?.recycleBin
  )) {
    push(
      item?.deletedAtUtc,
      "file",
      "deleted_to_recycle_bin",
      item?.originalPath ||
      item?.fileName,
      "Recycle Bin",
      {
        originalSize:
          item?.originalSize,
        dataPresent:
          item?.recycledDataPresent
      }
    );
  }

  for (const item of safeArray(
    report?.usbTimeline
  )) {
    push(
      item?.timestampUtc ||
      item?.timeCreatedUtc ||
      item?.connectedAtUtc ||
      item?.disconnectedAtUtc,
      "device",
      item?.action ||
      item?.eventType ||
      "usb_event",
      item?.deviceId ||
      item?.evidence ||
      item?.name,
      "USB timeline",
      item
    );
  }

  return events
    .sort(
      (a, b) =>
        validMs(b.timestampUtc) -
        validMs(a.timestampUtc)
    )
    .slice(0, 350);
}

function processStartInventory(report, session) {
  return safeArray(report?.processes)
    .filter((item) =>
      item?.startTimeUtc
    )
    .map((item) => ({
      process:
        item?.name || "",
      path:
        item?.path || "",
      pid:
        item?.pid,
      startTimeUtc:
        item?.startTimeUtc,
      relation:
        relationForTime(
          validMs(item?.startTimeUtc),
          session
        ),
      signed:
        item?.signed,
      signer:
        item?.signerSubject || ""
    }))
    .sort(
      (a, b) =>
        validMs(b.startTimeUtc) -
        validMs(a.startTimeUtc)
    )
    .slice(0, 120);
}

async function addEnvironmentWarnings({
  analysisId,
  report,
  insertFinding,
  session
}) {
  const serviceWarnings =
    new Set();

  for (const item of safeArray(
    report?.systemIntegrityExpansion
  )) {
    const kind =
      String(item?.kind || "")
        .toLowerCase();

    const name =
      String(item?.name || "")
        .trim();

    const lowerName =
      name.toLowerCase();

    if (
      kind === "service_state" &&
      ["pcasvc", "diagtrack", "eventlog", "dps"]
        .includes(lowerName)
    ) {
      const start =
        parseStartFromServiceDetail(
          item?.detail
        );

      if (start === 4) {
        serviceWarnings.add(
          lowerName
        );

        await addFinding(
          insertFinding,
          analysisId,
          "Serviço forense/importante desativado",
          "medium",
          "environment_warning_v3",
          name,
          {
            unusual: true,
            warningType:
              "disabled_service",
            serviceName: name,
            detail:
              item?.detail,
            confidence: "medium",
            note:
              "O serviço está configurado como desativado. Isso pode reduzir artefatos úteis para PC check, mas não prova uso de cheat sozinho."
          }
        );
      }
    }

    if (
      kind === "service_start_type_change"
    ) {
      const detail =
        String(item?.detail || "");

      const relevant =
        ["pcasvc", "diagtrack", "eventlog", "dps"]
          .find((service) =>
            detail
              .toLowerCase()
              .includes(service)
          );

      if (relevant) {
        await addFinding(
          insertFinding,
          analysisId,
          "Tipo de inicialização de serviço importante alterado recentemente",
          "medium",
          "environment_warning_v3",
          relevant,
          {
            ...item,
            unusual: true,
            warningType:
              "service_start_type_change",
            sessionRelation:
              relationForTime(
                validMs(item?.timestampUtc),
                session
              ),
            confidence: "context",
            note:
              "O Service Control Manager registrou alteração recente no tipo de inicialização de um serviço relevante para artefatos forenses."
          }
        );
      }
    }

    if (
      kind === "srum_state" &&
      /não localizado|not found|missing/i
        .test(String(item?.detail || ""))
    ) {
      await addFinding(
        insertFinding,
        analysisId,
        "SRUM não localizado",
        "medium",
        "environment_warning_v3",
        "SRUDB.dat",
        {
          ...item,
          unusual: true,
          warningType:
            "srum_missing",
          confidence: "context",
          note:
            "O banco SRUM não foi localizado. Mantido como warning porque pode haver razões legítimas ou limpeza prévia."
        }
      );
    }

    if (
      kind === "prefetch_state" &&
      (
        /não localizado|not found|missing/i
          .test(String(item?.detail || "")) ||
        /arquivos pf atuais:\s*0\b/i
          .test(String(item?.detail || ""))
      )
    ) {
      await addFinding(
        insertFinding,
        analysisId,
        "Prefetch ausente ou vazio",
        "medium",
        "environment_warning_v3",
        "Windows Prefetch",
        {
          ...item,
          unusual: true,
          warningType:
            "prefetch_missing_or_empty",
          confidence: "context",
          note:
            "O Prefetch está ausente ou vazio. Isso é incomum em uma instalação ativa, mas não prova cheat isoladamente."
        }
      );
    }
  }

  for (const item of safeArray(
    report?.usnJournalState
  )) {
    if (item?.active !== false)
      continue;

    await addFinding(
      insertFinding,
      analysisId,
      "USN Journal indisponível/inativo",
      "medium",
      "environment_warning_v3",
      item?.volume || "USN Journal",
      {
        ...item,
        unusual: true,
        warningType:
          "usn_inactive",
        confidence: "context",
        note:
          "O Change Journal não está ativo/disponível neste volume. É um warning de integridade forense, não uma detecção de cheat."
      }
    );
  }

  for (const item of safeArray(
    report?.logClearSignals
  )) {
    await addFinding(
      insertFinding,
      analysisId,
      "Sinal recente de limpeza de Event Log",
      "medium",
      "environment_warning_v3",
      item?.channel ||
      item?.signal ||
      "Event Log",
      {
        ...item,
        unusual: true,
        warningType:
          "event_log_clear",
        confidence: "context",
        note:
          "Foi observado sinal de limpeza recente de log do Windows. Exige revisão, mas não prova cheat sozinho."
      }
    );
  }

  const explorer =
    safeArray(report?.processes)
      .filter((item) =>
        normalizeName(
          item?.path ||
          item?.name
        ) === "explorer.exe"
      )
      .map((item) => ({
        item,
        ms:
          validMs(item?.startTimeUtc)
      }))
      .filter((entry) =>
        entry.ms > 0
      )
      .sort((a, b) => b.ms - a.ms)[0];

  if (
    explorer &&
    session?.startMs &&
    explorer.ms >
      session.startMs + 60 * 1000 &&
    explorer.ms <= session.endMs
  ) {
    await addFinding(
      insertFinding,
      analysisId,
      "Explorer.exe reiniciado durante a instância do Rust",
      "medium",
      "environment_warning_v3",
      "explorer.exe",
      {
        unusual: true,
        warningType:
          "explorer_restart_in_instance",
        explorerStartUtc:
          new Date(explorer.ms)
            .toISOString(),
        rustSessionStartUtc:
          new Date(session.startMs)
            .toISOString(),
        confidence: "medium",
        note:
          "O shell Explorer iniciou depois do Rust já estar em execução. Reiniciar o Explorer pode ter motivos legítimos, mas também altera artefatos de sessão."
      }
    );
  }

  const veracryptActive =
    safeArray(report?.processes)
      .some((item) =>
        /veracrypt/i.test(
          String(
            item?.path ||
            item?.name ||
            ""
          )
        )
      ) ||
    safeArray(report?.services)
      .some((item) =>
        /veracrypt/i.test(
          String(
            item?.name ||
            item?.displayName ||
            item?.pathName ||
            ""
          )
        )
      ) ||
    safeArray(report?.drivers)
      .some((item) =>
        /veracrypt/i.test(
          String(
            item?.name ||
            item?.displayName ||
            item?.pathName ||
            ""
          )
        )
      );

  if (veracryptActive) {
    await addFinding(
      insertFinding,
      analysisId,
      "VeraCrypt ativo durante a verificação",
      "medium",
      "environment_warning_v3",
      "VeraCrypt",
      {
        unusual: true,
        warningType:
          "encrypted_volume_tool_active",
        confidence: "context",
        note:
          "Ferramenta de volume criptografado detectada ativa. É contexto para revisão; não é evidência de cheat por si só."
      }
    );
  }
}

export async function runDetectionEngineV4({
  analysisId,
  report,
  insertFinding,
  helpers
}) {
  const session =
    detectRustSession(report);

  const interceptedInsert =
    async (
      id,
      title,
      severity,
      type,
      value,
      evidence = {}
    ) => {
      let nextTitle = title;
      let nextSeverity = severity;

      let sessionRelation =
        relationForEvidence(
          evidence,
          session
        );

      if (
        String(type || "")
          .includes("rust_module") ||
        String(type || "")
          .includes("memory_integrity")
      ) {
        sessionRelation =
          "in_instance";
      }

      let nextEvidence = {
        ...evidence
      };

      if (
        String(type || "") ===
          "correlated_executable_v2"
      ) {
        const knownMatch =
          helpers.knownCheatExecutableMatch?.(
            value,
            evidence
          ) || {
            matched: false
          };

        if (knownMatch.matched === true) {
          nextEvidence = {
            ...nextEvidence,
            knownCheatExecutable: true,
            knownCheatExecutableMatch: {
              matchedBy:
                knownMatch.matchedBy,
              name:
                knownMatch.entry?.name || "",
              label:
                knownMatch.entry?.label || "",
              confidence:
                knownMatch.entry?.confidence || "confirmed"
            },
            priorityMaximum:
              evidence?.executionConfirmed === true,
            protectedByTechnicalEngine:
              evidence?.executionConfirmed === true
          };
        }

        const adjusted =
          adjustExecutableSeverity(
            title,
            severity,
            nextEvidence,
            sessionRelation
          );

        nextTitle =
          adjusted.title;

        nextSeverity =
          adjusted.severity;
      }

      return insertFinding(
        id,
        nextTitle,
        nextSeverity,
        type,
        value,
        {
          ...nextEvidence,
          baselineV2: true,
          baselineV3: true,
          baselineV4: true,
          classifierVersion:
            V4_VERSION,
          sessionRelation,
          rustSession: {
            resolved:
              Boolean(session.startMs),
            active:
              session.active,
            source:
              session.source,
            startUtc:
              session.startMs
                ? new Date(session.startMs)
                    .toISOString()
                : null,
            scanEndUtc:
              new Date(session.endMs)
                .toISOString()
          }
        }
      );
    };

  await runCalibratedFilterV2({
    analysisId,
    report,
    insertFinding:
      interceptedInsert,
    helpers
  });

  await addEnvironmentWarnings({
    analysisId,
    report,
    insertFinding,
    session
  });

  const timeline =
    buildTimeline(
      report,
      session
    );

  if (timeline.length > 0) {
    await addFinding(
      insertFinding,
      analysisId,
      "Timeline forense da sessão (inventário)",
      "info",
      "forensic_timeline_v3",
      "Timeline",
      {
        inventoryOnly: true,
        rustSession: {
          resolved:
            Boolean(session.startMs),
          active:
            session.active,
          source:
            session.source,
          startUtc:
            session.startMs
              ? new Date(session.startMs)
                  .toISOString()
              : null,
          scanEndUtc:
            new Date(session.endMs)
              .toISOString()
        },
        eventCount:
          timeline.length,
        events:
          timeline,
        confidence: "info",
        note:
          "Eventos de execução, criação, modificação, exclusão, rename e dispositivos são mantidos como inventário. A severidade vem da correlação, não do evento isolado."
      }
    );
  }

  const starts =
    processStartInventory(
      report,
      session
    );

  if (starts.length > 0) {
    await addFinding(
      insertFinding,
      analysisId,
      "Process Start Times (inventário)",
      "info",
      "process_start_times_v3",
      "Process Start Times",
      {
        inventoryOnly: true,
        processes: starts,
        confidence: "info",
        note:
          "Horários de início dos processos são exibidos como contexto forense e usados para correlação temporal com a instância do Rust."
      }
    );
  }

  const compilationTimes =
    safeArray(report?.peInspections)
      .filter((item) =>
        item?.compilationTimeUtc
      )
      .map((item) => ({
        name:
          item?.name ||
          normalizeName(item?.path),
        path:
          item?.path || "",
        compilationTimeUtc:
          item?.compilationTimeUtc,
        signed:
          item?.signed,
        signer:
          item?.signerSubject || ""
      }))
      .sort(
        (a, b) =>
          validMs(b.compilationTimeUtc) -
          validMs(a.compilationTimeUtc)
      )
      .slice(0, 120);

  if (compilationTimes.length > 0) {
    await addFinding(
      insertFinding,
      analysisId,
      "PE Compilation Times (inventário)",
      "info",
      "pe_compilation_times_v3",
      "Compilation Times",
      {
        inventoryOnly: true,
        files:
          compilationTimes,
        confidence: "info",
        note:
          "Compilation Time é contexto forense. Timestamp de compilação isolado nunca é tratado como prova de cheat."
      }
    );
  }
}
