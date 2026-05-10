import type { ScanResult } from "@next-secure-check/core";

export type ReportFormat = "terminal" | "json" | "markdown" | "github";

const SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function formatReport(result: ScanResult, format: ReportFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(result, null, 2);
    case "markdown":
    case "github":
      return formatMarkdown(result);
    case "terminal":
      return formatTerminal(result);
  }
}

export function formatTerminal(result: ScanResult): string {
  const { summary } = result;
  const lines = [
    "next-secure-check report",
    "",
    `Project: ${result.project.name ?? "unknown"}`,
    `Framework: ${result.project.framework}`,
    `Score: ${summary.score}/100`,
    `Risk Level: ${summary.riskLevel}`,
    `Findings: ${summary.totalFindings} (HIGH ${summary.high}, MEDIUM ${summary.medium}, LOW ${summary.low}, INFO ${summary.info})`
  ];

  if (result.findings.length === 0) {
    return [...lines, "", "No findings detected."].join("\n");
  }

  for (const severity of SEVERITY_ORDER) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) {
      continue;
    }

    lines.push("", severity);
    for (const finding of findings) {
      const location = `${finding.filePath}${finding.line ? `:${finding.line}` : ""}`;
      lines.push(`- ${location}`);
      lines.push(`  ${finding.title} [${finding.ruleId}, confidence: ${finding.confidence}]`);
      if (finding.evidence) {
        lines.push(`  Evidence: ${finding.evidence}`);
      }
      lines.push(`  Fix: ${finding.recommendation}`);
    }
  }

  return lines.join("\n");
}

export function formatSummary(result: ScanResult): string {
  return formatTerminal(result);
}

export function formatMarkdown(result: ScanResult): string {
  const { summary } = result;
  const lines = [
    "# next-secure-check report",
    "",
    `- Project: ${result.project.name ?? "unknown"}`,
    `- Framework: ${result.project.framework}`,
    `- Score: ${summary.score}/100`,
    `- Risk level: ${summary.riskLevel}`,
    `- Findings: ${summary.totalFindings} (HIGH ${summary.high}, MEDIUM ${summary.medium}, LOW ${summary.low}, INFO ${summary.info})`
  ];

  if (result.findings.length === 0) {
    return [...lines, "", "No findings detected."].join("\n");
  }

  for (const severity of SEVERITY_ORDER) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) {
      continue;
    }

    lines.push("", `## ${severity}`);
    for (const finding of findings) {
      const location = `${finding.filePath}${finding.line ? `:${finding.line}` : ""}`;
      lines.push("", `### ${finding.title}`);
      lines.push("");
      lines.push(`- Location: \`${location}\``);
      lines.push(`- Rule: \`${finding.ruleId}\``);
      lines.push(`- Confidence: \`${finding.confidence}\``);
      if (finding.evidence) {
        lines.push(`- Evidence: \`${finding.evidence.replaceAll("`", "'")}\``);
      }
      lines.push(`- Recommendation: ${finding.recommendation}`);
    }
  }

  return lines.join("\n");
}
