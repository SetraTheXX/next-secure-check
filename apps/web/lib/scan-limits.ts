export type ScanLimits = {
  maxArchiveDownloadBytes: number;
  maxExtractedBytes: number;
  maxFiles: number;
  maxRepoSizeKb: number;
  maxSingleFileBytes: number;
  timeoutMs: number;
};

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxArchiveDownloadBytes: 50 * 1024 * 1024,
  maxExtractedBytes: 100 * 1024 * 1024,
  maxFiles: 3000,
  maxRepoSizeKb: 100 * 1024,
  maxSingleFileBytes: 1 * 1024 * 1024,
  timeoutMs: 60_000
};
