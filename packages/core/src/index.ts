export type {
  Confidence,
  Finding,
  ProjectInfo,
  RiskLevel,
  Rule,
  ScanContext,
  ScanResult,
  ScanSummary,
  Severity
} from "./types.js";

export function createScanResultSkeleton(targetPath: string, toolVersion = "0.0.0"): import("./types.js").ScanResult {
  const startedAt = Date.now();

  return {
    project: {
      name: targetPath,
      framework: "unknown",
      router: "unknown",
      language: "unknown"
    },
    summary: {
      score: 100,
      riskLevel: "excellent",
      totalFindings: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    findings: [],
    metadata: {
      scannedAt: new Date(startedAt).toISOString(),
      durationMs: Date.now() - startedAt,
      toolVersion
    }
  };
}
