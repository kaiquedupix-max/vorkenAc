import test from "node:test";
import assert from "node:assert/strict";

import {
  catalogWebTargetMatch,
  classifyExplicitCheatNameEvidence,
  classifyUnknownExecutableEvidence,
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
