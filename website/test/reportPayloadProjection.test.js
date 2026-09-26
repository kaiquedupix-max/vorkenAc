import test from "node:test";
import assert from "node:assert/strict";
import { projectReportPayloadForAdmin } from "../reportPayloadProjection.js";

test("large forensic collections are projected for the admin UI", () => {
  const payload = {
    machine: { name: "TEST-PC" },
    peInspections: Array.from({ length: 12788 }, (_, index) => ({ index })),
    files: Array.from({ length: 240 }, (_, index) => ({ index })),
    steamAccounts: [{ steamId64: "76561198000000000" }],
  };

  const projected = projectReportPayloadForAdmin(payload);

  assert.equal(projected.peInspections.length, 120);
  assert.equal(projected.files.length, 180);
  assert.equal(projected.steamAccounts.length, 1);
  assert.equal(projected.uiCollectionCounts.peInspections, 12788);
  assert.equal(projected.uiCollectionCounts.files, 240);
  assert.equal(projected.uiProjection.originalItems, 13029);
  assert.equal(projected.uiProjection.projectedItems, 301);
  assert.equal(projected.uiProjection.truncated, true);
  assert.deepEqual(projected.machine, payload.machine);
});

test("small reports remain complete", () => {
  const payload = {
    files: [{ name: "one.exe" }],
    defenderDetections: [{ threatName: "Example" }],
  };

  const projected = projectReportPayloadForAdmin(payload);

  assert.equal(projected.files.length, 1);
  assert.equal(projected.defenderDetections.length, 1);
  assert.equal(projected.uiProjection.truncated, false);
});

test("invalid payload becomes an empty projection", () => {
  const projected = projectReportPayloadForAdmin(null);
  assert.deepEqual(projected.uiCollectionCounts, {});
  assert.equal(projected.uiProjection.originalItems, 0);
});

