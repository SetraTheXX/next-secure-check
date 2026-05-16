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
export const MAX_RENDERED_FINDINGS = 100;

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

export function getVisibleFindings(result: ScanApiSuccess): ScanApiFinding[] {
  return result.scan.findings.slice(0, MAX_RENDERED_FINDINGS);
}

export function getHiddenFindingCount(result: ScanApiSuccess): number {
  return Math.max(0, result.scan.findings.length - MAX_RENDERED_FINDINGS);
}

export function createResultTextIndex(result: ScanApiSuccess): string[] {
  const visibleFindings = getVisibleFindings(result);

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
    ...visibleFindings.flatMap((finding) => [
      finding.ruleId,
      finding.severity,
      finding.confidence,
      formatFindingLocation(finding),
      finding.evidence ?? "",
      finding.recommendation
    ]),
    String(getHiddenFindingCount(result))
  ];
}

export function createScanJsonExport(result: ScanApiSuccess): string {
  return JSON.stringify(result, null, 2);
}

export function createScanMarkdownExport(result: ScanApiSuccess): string {
  const summary = result.scan.summary;
  const lines = [
    `# next-secure-check report: ${result.repo.fullName}`,
    "",
    `- Repository: ${result.repo.htmlUrl}`,
    `- Default branch: ${result.repo.defaultBranch}`,
    `- Score: ${summary.score}`,
    `- Risk level: ${summary.riskLevel}`,
    `- Total findings: ${summary.totalFindings}`,
    `- Severity counts: High ${summary.high}, Medium ${summary.medium}, Low ${summary.low}, Info ${summary.info}`,
    "",
    "## Findings",
    ""
  ];

  if (result.scan.findings.length === 0) {
    lines.push("No findings returned by the selected rules.");
    return lines.join("\n");
  }

  result.scan.findings.forEach((finding, index) => {
    lines.push(
      `### ${index + 1}. ${finding.title}`,
      "",
      `- Rule: ${finding.ruleId}`,
      `- Severity: ${finding.severity}`,
      `- Confidence: ${finding.confidence}`,
      `- Location: ${formatFindingLocation(finding)}`,
      `- Recommendation: ${finding.recommendation}`
    );

    if (finding.evidence) {
      lines.push("", "```text", finding.evidence, "```");
    }

    lines.push("");
  });

  return lines.join("\n").trimEnd();
}
