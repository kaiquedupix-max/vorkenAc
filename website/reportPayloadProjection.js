const DEFAULT_COLLECTION_LIMIT = 0;

const COLLECTION_LIMITS = Object.freeze({
  steamAccounts: 20,
  usbCurrent: 60,
  usbHistory: 60,
  usbFiles: 60,
  serialDevices: 60,
  browserHistorySignals: 60,
});

const SAFE_OBJECT_KEYS = new Set([
  "hardwareSummary",
  "steamAccountCorrelation",
]);

export function projectReportPayloadForAdmin(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {
      uiCollectionCounts: {},
      uiProjection: {
        truncated: false,
        originalItems: 0,
        projectedItems: 0,
      },
    };
  }

  const projected = {};
  const counts = {};
  let originalItems = 0;
  let projectedItems = 0;

  for (const [key, value] of Object.entries(payload)) {
    if (!Array.isArray(value)) {
      if (
        value == null ||
        ["string", "number", "boolean"].includes(typeof value)
      ) {
        projected[key] = value;
      } else if (SAFE_OBJECT_KEYS.has(key)) {
        projected[key] = projectFindingEvidenceForAdmin(value);
      }
      continue;
    }

    const limit = COLLECTION_LIMITS[key] ?? DEFAULT_COLLECTION_LIMIT;
    counts[key] = value.length;
    originalItems += value.length;
    projected[key] = value.slice(0, limit);
    projectedItems += projected[key].length;
  }

  projected.uiCollectionCounts = counts;
  projected.uiProjection = {
    truncated: projectedItems < originalItems,
    originalItems,
    projectedItems,
  };

  return projected;
}

export function projectFindingEvidenceForAdmin(value, depth = 0) {
  if (value == null || typeof value === "boolean" || typeof value === "number")
    return value;

  if (typeof value === "string")
    return value.length > 2000
      ? value.slice(0, 2000) + "…"
      : value;

  if (depth >= 5)
    return "[detalhe disponível no relatório bruto]";

  if (Array.isArray(value)) {
    return value
      .slice(0, 20)
      .map((item) => projectFindingEvidenceForAdmin(item, depth + 1));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 80)
        .map(([key, item]) => [
          key,
          projectFindingEvidenceForAdmin(item, depth + 1),
        ])
    );
  }

  return String(value);
}
