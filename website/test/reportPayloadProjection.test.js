import test from "node:test";
import assert from "node:assert/strict";
import {
  isUsbStorageDevice,
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

test("USB report projection keeps storage and removes hubs and input devices", () => {
  const payload = {
    usbCurrent: [
      { name: "USB Root Hub (USB 3.0)", pnpDeviceId: "USB\\ROOT_HUB30\\1" },
      { name: "Dispositivo de Entrada USB", pnpDeviceId: "USB\\VID_1234&PID_5678\\1" },
      { name: "Generic Flash Disk USB Device", pnpDeviceId: "USBSTOR\\DISK&VEN_GENERIC\\ABC" },
    ],
    usbHistory: [
      { friendlyName: "Kingston DataTraveler", deviceClass: "Disk&Ven_Kingston&Prod_DataTraveler", instanceId: "SERIAL1", present: false },
    ],
    usbExecutionEvidence: [
      { name: "loader.exe", path: "E:\\loader.exe", isExe: true, removableConfirmed: true },
    ],
  };

  const projected = projectReportPayloadForAdmin(payload);
  assert.equal(projected.usbCurrent.length, 1);
  assert.equal(projected.usbCurrent[0].name, "Generic Flash Disk USB Device");
  assert.equal(projected.usbHistory.length, 1);
  assert.equal(projected.usbExecutionEvidence.length, 1);
  assert.equal(projected.uiCollectionCounts.usbCurrent, 1);
});

test("USB storage classifier rejects ports and accepts USBSTOR disks", () => {
  assert.equal(isUsbStorageDevice({ name: "USB Root Hub (USB 3.0)" }), false);
  assert.equal(isUsbStorageDevice({ name: "Dispositivo de Entrada USB" }), false);
  assert.equal(isUsbStorageDevice({ pnpDeviceId: "USBSTOR\\DISK&VEN_SANDISK\\123" }), true);
});
