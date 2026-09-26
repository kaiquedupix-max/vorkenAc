const DEFAULT_COLLECTION_LIMIT = 120;

const COLLECTION_LIMITS = Object.freeze({
  steamAccounts: 50,
  usbCurrent: 200,
  usbHistory: 200,
  usbTimeline: 200,
  usbFiles: 200,
  serialDevices: 200,
  files: 180,
  processes: 180,
  prefetch: 180,
  prefetchExecutions: 180,
  bam: 180,
  userAssist: 180,
  muiCache: 180,
  pca: 180,
  amcache: 180,
  shimCache: 180,
  processCreationEvents: 180,
  browserDownloads: 180,
  browserHistorySignals: 180,
  recycleBin: 180,
  peInspections: 120,
  usnActivity: 120,
  systemIntegrityExpansion: 120,
});

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
      projected[key] = value;
      continue;
    }

    const limit = COLLECTION_LIMITS[key] || DEFAULT_COLLECTION_LIMIT;
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

