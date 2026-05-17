export const DEFAULT_SCAN_LIMITS = {
  maxArchiveDownloadBytes: 50 * 1024 * 1024,
  maxExtractedBytes: 100 * 1024 * 1024,
  maxFiles: 3000,
  maxRepoSizeKb: 100 * 1024,
  maxSingleFileBytes: 1 * 1024 * 1024,
  timeoutMs: 60_000
} as const;

export type ScanLimits = typeof DEFAULT_SCAN_LIMITS;
