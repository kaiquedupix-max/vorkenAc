import test from "node:test";
import assert from "node:assert/strict";

import {
  canApplyLearnedArtifactTrust,
  catalogWebTargetMatch,
  classifyExplicitCheatNameEvidence,
  classifyUnknownExecutableEvidence,
  isArtifactProtectedFromLearning,
} from "../detectionPolicyV4.js";

test("direct catalog domain is a direct match", () => {
  const result = catalogWebTargetMatch(
    { matchedBy: "domain:lethality.club" },
    { url: "https://store.lethality.club/rust" },
    "browser_history"
  );

  assert.equal(result.direct, true);
});

test("search result mentioning a catalog domain is not a direct visit", () => {
  const result = catalogWebTargetMatch(
    { matchedBy: "domain:lethality.club" },
    { url: "https://www.google.com/search?q=lethality.club" },
    "browser_history"
  );

  assert.equal(result.direct, false);
});

test("lookalike host containing catalog text is not a direct visit", () => {
  const result = catalogWebTargetMatch(
    { matchedBy: "domain:lethality.club" },
    { url: "https://lethality.club.example.org/download" },
    "browser_history"
  );

  assert.equal(result.direct, false);
});

test("referrer catalog URL cannot turn unrelated history into direct visit", () => {
  const result = catalogWebTargetMatch(
    { matchedBy: "domain:lethality.club" },
    {
      url: "https://example.org/article",
      referrerUrl: "https://lethality.club/"
    },
    "browser_history"
  );

  assert.equal(result.direct, false);
});

test("random executable in Downloads alone is review context, not critical", () => {
  const result = classifyUnknownExecutableEvidence({
    executed: true,
    randomLoaderScore: 5,
    suspiciousPath: true,
  });

  assert.equal(result.critical, false);
  assert.deepEqual(result.corroborators, []);
});

test("random executed loader with two independent technical signals is critical", () => {
  const result = classifyUnknownExecutableEvidence({
    executed: true,
    randomLoaderScore: 5,
    suspiciousPath: true,
    deletedOrMissing: true,
    packedOrHighEntropy: true,
  });

  assert.equal(result.critical, true);
});

test("generic installer never becomes an unknown critical loader", () => {
  const result = classifyUnknownExecutableEvidence({
    executed: true,
    genericInstaller: true,
    randomLoaderScore: 5,
    usb: true,
    packedOrHighEntropy: true,
  });

  assert.equal(result.critical, false);
});

test("suspicious name alone stays in review", () => {
  const result = classifyExplicitCheatNameEvidence({
    executed: true,
    highRiskName: true,
  });

  assert.equal(result.review, true);
  assert.equal(result.critical, false);
});

test("suspicious name becomes critical only in-session with technical support", () => {
  const result = classifyExplicitCheatNameEvidence({
    executed: true,
    highRiskName: true,
    inSession: true,
    strongInjection: true,
  });

  assert.equal(result.critical, true);
});

test("unexecuted injection capability can be learned as a false positive", () => {
  assert.equal(
    isArtifactProtectedFromLearning(
      "correlated_executable_v2",
      {
        injectionCapability: true,
        executionConfirmed: false,
      }
    ),
    false
  );
});

test("executed injection capability remains protected from learning", () => {
  assert.equal(
    isArtifactProtectedFromLearning(
      "correlated_executable_v2",
      {
        injectionCapability: true,
        executionConfirmed: true,
      }
    ),
    true
  );
});

test("Defender detections remain protected from learning", () => {
  assert.equal(
    isArtifactProtectedFromLearning(
      "defender_detection_v2",
      {}
    ),
    true
  );
});

test("current classifier findings can use learned trust", () => {
  assert.equal(
    canApplyLearnedArtifactTrust(
      "correlated_executable_v2",
      {
        baselineV2: true,
        baselineV3: true,
        baselineV4: true,
        baselineV5: true,
        executionConfirmed: false,
      }
    ),
    true
  );
});

test("learned trust cannot hide protected technical evidence", () => {
  assert.equal(
    canApplyLearnedArtifactTrust(
      "correlated_executable_v2",
      { executionConfirmed: true },
      { protectedFinding: true }
    ),
    false
  );
});

 test('hardware and removable inventory are critical without claiming execution',async()=>{
 const {criticalHardwareFindings,isArtifactProtectedFromLearning}=await import('../detectionPolicyV4.js');
 const findings=criticalHardwareFindings({serialDevices:[{name:'Arduino Uno',pnpDeviceId:'USB\\VID_2341'},{name:'MAKCU'},{name:'CH340 USB Serial'}],usbFiles:[{path:'E:\\setup.exe'},{path:'E:\\notes.txt'}]});
 assert.equal(findings.length,3);assert(findings.every(f=>f.evidence.priorityMaximum));
 assert.equal(findings[2].evidence.executionConfirmed,undefined);
 assert(findings.every(f=>isArtifactProtectedFromLearning(f.artifactType,f.evidence)));
 });
