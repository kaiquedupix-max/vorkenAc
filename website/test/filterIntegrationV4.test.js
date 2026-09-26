import test from "node:test";
import assert from "node:assert/strict";

import { runCalibratedFilterV2 } from "../calibratedFilterV2.js";
import { catalogWebTargetMatch } from "../detectionPolicyV4.js";

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

test("every structured direct catalog visit is preserved as critical", async () => {
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
  assert.ok(visits.every((item) => item.severity === "critical"));
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
