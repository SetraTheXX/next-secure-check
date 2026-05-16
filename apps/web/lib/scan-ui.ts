import { parseGitHubRepoUrl } from "./github-url";

export type ScanStatus = "idle" | "loading" | "success" | "error";

export type ScanApiFinding = {
  id: string;
  ruleId: string;
  title: string;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  filePath: string;
  line?: number;
  column?: number;
  evidence?: string;
  description: string;
  recommendation: string;
  references?: string[];
};

export type ScanApiSuccess = {
  ok: true;
  repo: {
    owner: string;
    repo: string;
    fullName: string;
    htmlUrl: string;
    defaultBranch: string;
    archived: boolean;
  };
  extraction: {
    fileCount: number;
    totalBytes: number;
    tempId: string;
  };
  scan: {
    project: {
      name?: string;
      framework: string;
      router?: string;
      language: string;
    };
    summary: {
      score: number;
      riskLevel: string;
      totalFindings: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    findings: ScanApiFinding[];
    metadata: {
      scannedAt: string;
      durationMs: number;
      toolVersion: string;
    };
  };
};

export type ScanApiFailure = {
  ok: false;
  code: string;
  message: string;
  status?: number;
};

export type ScanApiResult = ScanApiSuccess | ScanApiFailure;

export const LOADING_STATE_TITLE = "Scanning repository";

export function validateRepoInput(input: string): string | null {
  if (!input.trim()) {
    return "Repository URL is required.";
  }

  const parsed = parseGitHubRepoUrl(input);
  return parsed.ok ? null : parsed.error;
}

export function formatFindingLocation(finding: ScanApiFinding): string {
  const line = finding.line ? `:${finding.line}` : "";
  const column = finding.column ? `:${finding.column}` : "";
  return `${finding.filePath}${line}${column}`;
}

export function evidenceIsRedacted(finding: ScanApiFinding): boolean {
  return finding.evidence === "[REDACTED]";
}

export function resultContainsRawEvidence(result: ScanApiSuccess, rawEvidence: string): boolean {
  return result.scan.findings.some((finding) => finding.evidence === rawEvidence);
}

export function createResultTextIndex(result: ScanApiSuccess): string[] {
  return [
    result.repo.fullName,
    "Score",
    String(result.scan.summary.score),
    result.scan.summary.riskLevel,
    "Findings",
    String(result.scan.summary.totalFindings),
    String(result.scan.summary.high),
    String(result.scan.summary.medium),
    String(result.scan.summary.low),
    String(result.scan.summary.info),
    ...result.scan.findings.flatMap((finding) => [
      finding.ruleId,
      finding.severity,
      finding.confidence,
      formatFindingLocation(finding),
      finding.evidence ?? "",
      finding.recommendation
    ])
  ];
}
