import test from "node:test";
import assert from "node:assert/strict";

import { runCalibratedFilterV2 } from "../calibratedFilterV2.js";
import { catalogWebTargetMatch } from "../detectionPolicyV4.js";
import { runDetectionEngineV4 } from "../echoInspiredFilterV3.js";

function helpers() {
  return {
    isAbsoluteTrustedCatalogArtifact: () => false,
    isTrustedCommonAppArtifact: () => false,
    isTrustedPortableExecutableName: () => false,
    isKnownBenignPeNoise: () => false,
    knownCheatExecutableMatch: () => ({ matched: false }),
    findRustCatalogMatches: (...values) =>
      values.flat(Infinity).join(" ").toLowerCase().includes("lethality.club")
        ? [{
            name: "Lethality",
            severity: "critical",
            matchedBy: "domain:lethality.club"
          }]
        : [],
    isDirectCatalogWebMatch: (match, evidence) =>
      catalogWebTargetMatch(match, evidence, "browser_history").direct,
  };
}

async function collect(report, helperOverrides = {}) {
  const findings = [];
  await runCalibratedFilterV2({
    analysisId: 1,
    report,
    helpers: { ...helpers(), ...helperOverrides },
    insertFinding: async (
      analysisId,
      title,
      severity,
      artifactType,
      artifactValue,
      evidence
    ) => findings.push({
      analysisId,
      title,
      severity,
      artifactType,
      artifactValue,
      evidence
    })
  });
  return findings;
}

async function collectFinal(report, helperOverrides = {}) {
  const findings = [];
  await runDetectionEngineV4({
    analysisId: 1,
    report,
    helpers: { ...helpers(), ...helperOverrides },
    insertFinding: async (
      analysisId, title, severity, artifactType, artifactValue, evidence
    ) => findings.push({ analysisId, title, severity, artifactType, artifactValue, evidence }),
  });
  return findings;
}

test("every structured direct catalog visit is preserved for review", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    browserHistorySignals: [
      {
        browser: "Chrome",
        profile: "Default",
        url: "https://lethality.club/rust",
        visitTimeUtc: "2026-09-25T10:00:00Z"
      },
      {
        browser: "Chrome",
        profile: "Default",
        url: "https://lethality.club/rust",
        visitTimeUtc: "2026-09-25T11:00:00Z"
      }
    ]
  });

  const visits = findings.filter((item) =>
    item.artifactType === "browser_catalog_visit_v2"
  );

  assert.equal(visits.length, 2);
  assert.ok(visits.every((item) => item.severity === "medium"));
  assert.ok(visits.every((item) =>
    item.evidence.historyClassification === "catalog_direct_visit"
  ));
});

test("random executable in Downloads remains review instead of critical", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    prefetchExecutions: [{
      resolvedExecutablePath: "C:\\Users\\Player\\Downloads\\AbC9xQ2LmN7.exe",
      executablePresent: true,
      lastRunUtc: "2026-09-26T11:00:00Z"
    }],
    peInspections: [{
      path: "C:\\Users\\Player\\Downloads\\AbC9xQ2LmN7.exe",
      signed: false,
      suspiciousApis: []
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "medium");
  assert.equal(executable.evidence.behavioralUnknownLoader, false);
});

test("executed exact cheat executable catalog match is critical historically", async () => {
  const findings = await collect(
    {
      collectedAtUtc: "2026-09-26T12:00:00Z",
      prefetchExecutions: [{
        resolvedExecutablePath: "D:\\tools\\confirmed-loader.exe",
        executablePresent: false,
        lastRunUtc: "2026-08-20T11:00:00Z"
      }]
    },
    {
      knownCheatExecutableMatch: (value) => ({
        matched: String(value).toLowerCase().includes("confirmed-loader.exe"),
        matchedBy: "name",
        entry: {
          name: "confirmed-loader.exe",
          label: "Confirmed loader",
          confidence: "confirmed"
        }
      })
    }
  );

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.knownCheatExecutable, true);
});

test("confirmed suspicious executable is critical even without execution", async () => {
  const confirmedHash = "a".repeat(64);
  const findings = await collect(
    {
      collectedAtUtc: "2026-09-26T12:00:00Z",
      files: [{
        name: "confirmed-loader.exe",
        path: "C:\\Users\\Player\\Downloads\\confirmed-loader.exe",
        sha256: confirmedHash,
        signed: false
      }]
    },
    {
      knownCheatExecutableMatch: (_value, evidence) => ({
        matched: evidence?.sha256 === confirmedHash,
        matchedBy: "sha256",
        entry: {
          name: "confirmed-loader.exe",
          label: "Confirmed loader",
          confidence: "confirmed"
        }
      })
    }
  );

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.executionConfirmed, false);
  assert.equal(executable.evidence.protectedByTechnicalEngine, true);
  assert.match(executable.title, /ARQUIVO SUSPEITO ENCONTRADO/i);
});

test("heuristic-only unexecuted filename does not become a false critical", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    files: [{
      name: "AbC9xQ2LmN7.exe",
      path: "C:\\Users\\Player\\Downloads\\AbC9xQ2LmN7.exe",
      signed: false
    }]
  });

  assert.equal(findings.some((item) =>
    item.artifactType === "correlated_executable_v2" &&
    item.severity === "critical"
  ), false);

});

test("missing executable without an independent risk signal is inventory only", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    prefetchExecutions: [{
      resolvedExecutablePath: "C:\\Program Files\\Example\\helper.exe",
      executablePresent: false,
      lastRunUtc: "2026-09-25T11:00:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "info");
});

test("untrusted injection-capable executable is at least review", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    peInspections: [{
      path: "C:\\Users\\Player\\AppData\\Roaming\\bakkesmod\\64bitbminjector.exe",
      signed: false,
      suspiciousApis: [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread"
      ]
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "medium");
});

test("recently deleted unsigned untrusted EXE is critical regardless of name", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    deletedUsnRecords: [{
      fileName: "EveryRunGetsANewName.exe",
      timestampUtc: "2026-09-20T09:30:00Z",
      reason: "FILE_DELETE"
    }],
    peInspections: [{
      path: "C:\\Users\\Player\\Desktop\\EveryRunGetsANewName.exe",
      signed: false
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.recentDeletionConfirmed, true);
  assert.equal(executable.evidence.recentDeletionWindowDays, 15);
  assert.equal(executable.evidence.unsignedConfirmed, true);
  assert.match(executable.title, /sem assinatura apagado recentemente/i);
});

test("recent unsigned deletion remains critical when execution is out of session", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    processes: [{
      name: "RustClient.exe",
      startTimeUtc: "2026-09-26T11:30:00Z"
    }],
    prefetchExecutions: [{
      executableName: "DifferentEveryTime.exe",
      resolvedExecutablePath: "C:\\Users\\Player\\Desktop\\DifferentEveryTime.exe",
      executablePresent: false,
      lastRunUtc: "2026-09-20T08:00:00Z"
    }],
    deletedUsnRecords: [{
      fileName: "DifferentEveryTime.exe",
      timestampUtc: "2026-09-20T08:05:00Z",
      reason: "FILE_DELETE"
    }],
    peInspections: [{
      path: "C:\\Users\\Player\\Desktop\\DifferentEveryTime.exe",
      signed: false
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.sessionRelation, "out_of_instance");
});

test("recently deleted untrusted EXE with unknown signature is review", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    deletedUsnRecords: [{
      fileName: "RenamedUnknown.exe",
      timestampUtc: "2026-09-18T15:00:00Z",
      reason: "FILE_DELETE"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "medium");
  assert.equal(executable.evidence.recentDeletionConfirmed, true);
});

test("deletion older than 15 days does not trigger recent-deletion policy", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    deletedUsnRecords: [{
      fileName: "OldUnknown.exe",
      timestampUtc: "2026-08-01T15:00:00Z",
      reason: "FILE_DELETE"
    }],
    peInspections: [{
      path: "C:\\Users\\Player\\Desktop\\OldUnknown.exe",
      signed: false
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.notEqual(executable.severity, "critical");
  assert.equal(executable.evidence.recentDeletionConfirmed, false);
});

test("trusted executable is not raised by recent-deletion policy", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    deletedUsnRecords: [{
      fileName: "TrustedTool.exe",
      timestampUtc: "2026-09-25T15:00:00Z",
      reason: "FILE_DELETE"
    }],
    peInspections: [{
      path: "C:\\Program Files\\Trusted\\TrustedTool.exe",
      signed: false
    }]
  }, {
    isTrustedPortableExecutableName: (name) =>
      name.toLowerCase() === "trustedtool.exe"
  });

  assert.equal(findings.some((item) =>
    item.artifactType === "correlated_executable_v2"
  ), false);
});

test("Defender malware detections remain review findings", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    defenderDetections: [{
      path: "file:_C:\\Games\\Example\\OnlineFix64.dll",
      threatName: "Trojan:Win32/Example!rfn",
      eventId: 1117
    }]
  });

  const defender = findings.find((item) =>
    item.artifactType === "defender_detection_v2"
  );

  assert.ok(defender);
  assert.equal(defender.severity, "medium");
});

test("any confirmed EXE execution on USB is critical", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    processes: [{
      name: "RustClient.exe",
      path: "C:\\Games\\Rust\\RustClient.exe",
      startTimeUtc: "2026-09-26T10:00:00Z"
    }],
    prefetchExecutions: [{
      executableName: "portable-tool.exe",
      resolvedExecutablePath: "E:\\Tools\\portable-tool.exe",
      executablePresent: true,
      currentRemovable: true,
      lastRunUtc: "2026-09-26T11:00:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );

  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.match(executable.title, /EXECUTADO DENTRO DE PENDRIVE/i);
});

test("USB execution is recovered from the removable drive inventory", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    usbFiles: [{ drive: "F:", path: "F:\\Tools\\helper.exe" }],
    bam: [{
      path: "F:\\Tools\\helper.exe",
      fileExists: true,
      lastExecutionUtc: "2026-09-26T11:30:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.match(executable.title, /EXECUTADO DENTRO DE PENDRIVE/i);
});

test("detached volume Prefetch is not called USB from temporal proximity alone", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    usbHistory: [{
      present: false,
      friendlyName: "USB Mass Storage",
      lastDisconnectedUtc: "2026-09-26T11:40:00Z"
    }],
    prefetchExecutions: [{
      executableName: "portable.exe",
      nativeExecutablePath: "\\Device\\HarddiskVolume9\\portable.exe",
      executablePresent: false,
      volumeNotMounted: true,
      nonSystemVolume: true,
      likelyDetachedOrRemovable: true,
      lastRunUtc: "2026-09-26T11:35:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(
    !executable ||
    executable.evidence?.usbExecution !== true
  );
  assert.doesNotMatch(executable?.title || "", /EXECUTADO DENTRO DE PENDRIVE/i);
});

test("Windows SetupHost on an unmounted volume is not USB evidence", async () => {
  const findings = await collect({
    collectedAtUtc: "2026-09-29T12:00:00Z",
    usbHistory: [{
      present: false,
      friendlyName: "USB Mass Storage",
      lastDisconnectedUtc: "2026-09-29T11:40:00Z"
    }],
    prefetchExecutions: [{
      executableName: "SETUPHOST.EXE",
      nativeExecutablePath: "\\VOLUME{0000000000000000-4b3c0981}\\SOURCES\\SETUPHOST.EXE",
      executablePresent: false,
      volumeNotMounted: true,
      nonSystemVolume: true,
      likelyDetachedOrRemovable: true,
      lastRunUtc: "2026-09-29T11:35:00Z"
    }]
  });

  const usbFinding = findings.find((item) =>
    item.evidence?.usbExecution === true ||
    /EXECUTADO DENTRO DE PENDRIVE/i.test(item.title || "")
  );
  assert.equal(usbFinding, undefined);
});

test("SIGN.MEDIA execution is recognized as critical removable-media evidence", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    shimCache: [{
      path: "SIGN.MEDIA=A91F20CC QmT7vLpX9.exe",
      executed: "Yes",
      filePresent: false
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.usbExecution, true);
  assert.match(executable.title, /PENDRIVE/i);
});

test("missing executed game development build is critical", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    prefetchExecutions: [{
      executableName: "RenamedPayload.exe",
      resolvedExecutablePath: "C:\\Users\\Player\\Desktop\\cs2\\bin\\Debug\\net10.0-windows7.0\\RenamedPayload.exe",
      executablePresent: false,
      lastRunUtc: "2026-09-25T11:00:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(executable);
  assert.equal(executable.severity, "critical");
  assert.equal(executable.evidence.gameTargetedDevelopmentOutput, true);
});

test("generic missing Desktop executable is review instead of inventory", async () => {
  const findings = await collectFinal({
    collectedAtUtc: "2026-09-26T12:00:00Z",
    prefetchExecutions: [{
      executableName: "Anything.exe",
      resolvedExecutablePath: "C:\\Users\\Player\\Desktop\\Anything.exe",
      executablePresent: false,
      lastRunUtc: "2026-09-25T11:00:00Z"
    }]
  });

  const executable = findings.find((item) =>
    item.artifactType === "correlated_executable_v2"
  );
  assert.ok(executable);
  assert.equal(executable.severity, "medium");
  assert.match(executable.title, /pasta de usuário/i);
});
