import type { ScanResult } from "@next-secure-check/core";

export type ReportFormat = "terminal" | "json" | "markdown" | "github" | "sarif";

const SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function formatReport(result: ScanResult, format: ReportFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(result, null, 2);
    case "markdown":
      return formatMarkdown(result);
    case "github":
      return formatGithub(result);
    case "sarif":
      return formatSarif(result);
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

export function formatGithub(result: ScanResult): string {
  const { summary } = result;
  const lines = [
    "## next-secure-check",
    "",
    `**Status:** ${githubStatus(summary.high, summary.totalFindings)}`,
    "",
    "| Metric | Value |",
    "| --- | --- |",
    `| Project | ${escapeTableCell(result.project.name ?? "unknown")} |`,
    `| Framework | ${escapeTableCell(result.project.framework)} |`,
    `| Score | ${summary.score}/100 |`,
    `| Risk level | ${escapeTableCell(summary.riskLevel)} |`,
    `| Findings | ${summary.totalFindings} (HIGH ${summary.high}, MEDIUM ${summary.medium}, LOW ${summary.low}, INFO ${summary.info}) |`
  ];

  if (result.findings.length === 0) {
    return [...lines, "", "No findings detected."].join("\n");
  }

  lines.push("", "### Findings", "");
  lines.push("| Severity | Rule | Title | Location | Confidence |");
  lines.push("| --- | --- | --- | --- | --- |");

  for (const severity of SEVERITY_ORDER) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    for (const finding of findings) {
      lines.push(
        `| ${finding.severity} | \`${escapeBackticks(finding.ruleId)}\` | ${escapeTableCell(finding.title)} | \`${escapeBackticks(formatLocation(finding))}\` | ${finding.confidence} |`
      );
    }
  }

  lines.push("", "<details>");
  lines.push("<summary>Recommendations</summary>");
  lines.push("");

  for (const severity of SEVERITY_ORDER) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    for (const finding of findings) {
      lines.push(`- **${finding.severity}** \`${escapeBackticks(finding.ruleId)}\` at \`${escapeBackticks(formatLocation(finding))}\`: ${finding.recommendation}`);
    }
  }

  lines.push("", "</details>");

  return lines.join("\n");
}

export function formatSarif(result: ScanResult): string {
  const rules = uniqueRules(result);
  const ruleIndexes = new Map(rules.map((rule, index) => [rule.id, index]));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "next-secure-check",
            semanticVersion: result.metadata.toolVersion,
            rules
          }
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndexes.get(finding.ruleId) ?? 0,
          level: sarifLevel(finding.severity),
          message: {
            text: finding.title
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: formatSarifUri(finding.filePath)
                },
                ...(finding.line
                  ? {
                      region: {
                        startLine: finding.line,
                        ...(finding.column ? { startColumn: finding.column } : {})
                      }
                    }
                  : {})
              }
            }
          ],
          properties: {
            category: finding.category,
            confidence: finding.confidence,
            nextSecureCheckFindingId: finding.id,
            evidenceRedacted: isSecretFinding(finding)
          }
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

function githubStatus(high: number, totalFindings: number): string {
  if (high > 0) {
    return "Action required";
  }

  if (totalFindings > 0) {
    return "Review recommended";
  }

  return "No findings";
}

function uniqueRules(result: ScanResult): Array<Record<string, unknown>> {
  const rules = new Map<string, ScanResult["findings"][number]>();
  for (const finding of result.findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, finding);
    }
  }

  return [...rules.values()].map((finding) => ({
    id: finding.ruleId,
    name: finding.ruleId,
    shortDescription: {
      text: finding.title
    },
    fullDescription: {
      text: finding.description
    },
    defaultConfiguration: {
      level: sarifLevel(finding.severity)
    },
    help: {
      markdown: finding.recommendation,
      text: finding.recommendation
    },
    properties: {
      tags: ["security", finding.category],
      precision: sarifPrecision(finding.confidence),
      "security-severity": sarifSecuritySeverity(finding.severity)
    }
  }));
}

function sarifLevel(severity: ScanResult["findings"][number]["severity"]): "error" | "warning" | "note" {
  switch (severity) {
    case "HIGH":
      return "error";
    case "MEDIUM":
    case "LOW":
      return "warning";
    case "INFO":
      return "note";
  }
}

function sarifSecuritySeverity(severity: ScanResult["findings"][number]["severity"]): string {
  switch (severity) {
    case "HIGH":
      return "8.0";
    case "MEDIUM":
      return "5.0";
    case "LOW":
      return "2.0";
    case "INFO":
      return "0.0";
  }
}

function sarifPrecision(confidence: ScanResult["findings"][number]["confidence"]): "high" | "medium" | "low" {
  switch (confidence) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
  }
}

function isSecretFinding(finding: ScanResult["findings"][number]): boolean {
  return finding.category === "secrets" || finding.ruleId.startsWith("secrets/");
}

function formatSarifUri(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function formatLocation(finding: ScanResult["findings"][number]): string {
  return `${finding.filePath}${finding.line ? `:${finding.line}` : ""}`;
}

function escapeBackticks(value: string): string {
  return value.replaceAll("`", "'");
}

function escapeTableCell(value: string): string {
  return value.replace(/\r?\n/g, " ").replaceAll("|", "\\|");
}
