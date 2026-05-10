export type {
  Confidence,
  Finding,
  ProjectInfo,
  RiskLevel,
  Rule,
  ScanContext,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
  SourceFile
} from "./types.js";
export { collectFiles, normalizePath } from "./file-collector.js";
export { detectProject } from "./project-detector.js";
export { riskLevelForScore, summarizeFindings } from "./score.js";
export { resolveProjectPath, scanProject } from "./scanner.js";

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
