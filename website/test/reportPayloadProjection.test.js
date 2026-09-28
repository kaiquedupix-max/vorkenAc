import test from "node:test";
import assert from "node:assert/strict";
import {
  projectFindingEvidenceForAdmin,
  projectReportPayloadForAdmin,
} from "../reportPayloadProjection.js";

test("large forensic collections are projected for the admin UI", () => {
  const payload = {
    machine: { name: "TEST-PC" },
    peInspections: Array.from({ length: 12788 }, (_, index) => ({ index })),
    files: Array.from({ length: 240 }, (_, index) => ({ index })),
    steamAccounts: [{ steamId64: "76561198000000000" }],
  };

  const projected = projectReportPayloadForAdmin(payload);

  assert.equal(projected.peInspections.length, 0);
  assert.equal(projected.files.length, 0);
  assert.equal(projected.steamAccounts.length, 1);
  assert.equal(projected.uiCollectionCounts.peInspections, 12788);
  assert.equal(projected.uiCollectionCounts.files, 240);
  assert.equal(projected.uiProjection.originalItems, 13029);
  assert.equal(projected.uiProjection.projectedItems, 1);
  assert.equal(projected.uiProjection.truncated, true);
  assert.equal(projected.machine, undefined);
});

test("non-interactive technical arrays stay on the server", () => {
  const payload = {
    files: [{ name: "one.exe" }],
    defenderDetections: [{ threatName: "Example" }],
  };

  const projected = projectReportPayloadForAdmin(payload);

  assert.equal(projected.files.length, 0);
  assert.equal(projected.defenderDetections.length, 0);
  assert.equal(projected.uiCollectionCounts.files, 1);
  assert.equal(projected.uiProjection.truncated, true);
});

test("invalid payload becomes an empty projection", () => {
  const projected = projectReportPayloadForAdmin(null);
  assert.deepEqual(projected.uiCollectionCounts, {});
  assert.equal(projected.uiProjection.originalItems, 0);
});

test("finding evidence is bounded before reaching the browser", () => {
  const projected = projectFindingEvidenceForAdmin({
    note: "visible",
    matches: Array.from({ length: 5000 }, (_, index) => ({ index })),
    raw: "x".repeat(10000),
  });

  assert.equal(projected.note, "visible");
  assert.equal(projected.matches.length, 20);
  assert.ok(projected.raw.length < 2100);
});
