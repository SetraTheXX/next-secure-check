import { createHash } from "node:crypto";
import type { ScanResult } from "@next-secure-check/core";

export type ReportFormat = "terminal" | "json" | "markdown" | "github" | "sarif";

const SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"] as const;
const CONFIDENCE_ORDER = ["HIGH", "MEDIUM", "LOW"] as const;
const INFORMATION_URI = "https://github.com/SetraTheXX/next-secure-check";
const SUMMARY_FINDING_LIMIT = 3;

export function formatReport(result: ScanResult, format: ReportFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(redactScanResult(result), null, 2);
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
      lines.push(`  ${finding.title} [${finding.ruleId}, confidence: ${finding.confidence}, context: ${formatContext(finding)}]`);
      lines.push(`  Why: ${formatInlineText(finding.description)}`);
      lines.push(`  Context reason: ${formatInlineText(formatContextReason(finding))}`);
      if (finding.evidencePath) {
        lines.push(`  Evidence path: ${formatInlineText(finding.evidencePath)}`);
      }
      const evidence = redactFindingEvidence(finding);
      if (evidence) {
        lines.push(`  Evidence: ${evidence}`);
      }
      lines.push(`  Fix: ${finding.recommendation}`);
    }
  }

  return lines.join("\n");
}

export function formatSummary(result: ScanResult): string {
  const { summary } = result;
  const lines = [
    "next-secure-check summary",
    "",
    `Project: ${result.project.name ?? "unknown"} | Framework: ${result.project.framework}`,
    `Score: ${summary.score}/100 | Risk Level: ${summary.riskLevel}`,
    `Findings: ${summary.totalFindings} | HIGH ${summary.high} | MEDIUM ${summary.medium} | LOW ${summary.low} | INFO ${summary.info}`
  ];

  if (result.findings.length === 0) {
    return [...lines, "", "No findings detected."].join("\n");
  }

  const representativeFindings = [...result.findings]
    .sort(compareSummaryFindings)
    .slice(0, SUMMARY_FINDING_LIMIT);

  lines.push("", "Top findings:");
  for (const finding of representativeFindings) {
    lines.push(
      `- ${finding.severity} ${finding.ruleId} [confidence: ${finding.confidence}, context: ${formatContext(finding)}] ${formatLocation(finding)}`
    );
  }

  const remainingFindings = result.findings.length - representativeFindings.length;
  if (remainingFindings > 0) {
    lines.push("", `+${remainingFindings} more findings. Run without --summary for full details.`);
  }

  return lines.join("\n");
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
      lines.push(`- Context: \`${formatContext(finding)}\``);
      lines.push(`- Why: ${formatInlineText(finding.description)}`);
      lines.push(`- Context reason: ${formatInlineText(formatContextReason(finding))}`);
      if (finding.evidencePath) {
        lines.push(`- Evidence path: \`${escapeBackticks(formatInlineText(finding.evidencePath))}\``);
      }
      const evidence = redactFindingEvidence(finding);
      if (evidence) {
        lines.push(`- Evidence: \`${escapeBackticks(evidence)}\``);
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
  lines.push("| Severity | Rule | Title | Location | Confidence | Context |");
  lines.push("| --- | --- | --- | --- | --- | --- |");

  for (const severity of SEVERITY_ORDER) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    for (const finding of findings) {
      lines.push(
        `| ${finding.severity} | \`${escapeBackticks(finding.ruleId)}\` | ${escapeTableCell(finding.title)} | \`${escapeBackticks(formatLocation(finding))}\` | ${finding.confidence} | ${escapeTableCell(formatContext(finding))} |`
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
      lines.push(`  - Why: ${formatInlineText(finding.description)}`);
      lines.push(`  - Context reason: ${formatInlineText(formatContextReason(finding))}`);
      if (finding.evidencePath) {
        lines.push(`  - Evidence path: \`${escapeBackticks(formatInlineText(finding.evidencePath))}\``);
      }
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
            informationUri: INFORMATION_URI,
            semanticVersion: result.metadata.toolVersion,
            rules
          }
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndexes.get(finding.ruleId) ?? 0,
          level: sarifLevel(finding.severity),
          message: {
            text: createSarifMessageText(finding)
          },
          partialFingerprints: {
            "nextSecureCheck/v1": createFindingFingerprint(finding),
            "nextSecureCheck/ruleLocation/v1": createRuleLocationFingerprint(finding)
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
            context: finding.context ?? "unknown",
            contextReason: formatContextReason(finding),
            nextSecureCheckFindingId: finding.id,
            whyReported: formatInlineText(finding.description),
            evidenceRedacted: isSecretFinding(finding),
            ...(finding.evidencePath ? { evidencePath: finding.evidencePath } : {})
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
  type Finding = ScanResult["findings"][number];
  type RuleAggregate = {
    finding: Finding;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
  };

  const rules = new Map<string, RuleAggregate>();
  for (const finding of result.findings) {
    const current = rules.get(finding.ruleId);
    if (!current) {
      rules.set(finding.ruleId, {
        finding,
        severity: finding.severity,
        confidence: finding.confidence
      });
      continue;
    }

    current.severity = strongestValue(current.severity, finding.severity, SEVERITY_ORDER);
    current.confidence = strongestValue(current.confidence, finding.confidence, CONFIDENCE_ORDER);
  }

  return [...rules.values()].map(({ finding, severity, confidence }) => ({
    id: finding.ruleId,
    name: finding.ruleId,
    shortDescription: {
      text: finding.title
    },
    fullDescription: {
      text: finding.description
    },
    defaultConfiguration: {
      level: sarifLevel(severity)
    },
    help: {
      markdown: finding.recommendation,
      text: finding.recommendation
    },
    helpUri: ruleHelpUri(finding.ruleId),
    properties: {
      tags: sarifRuleTags(finding),
      precision: sarifPrecision(confidence),
      "security-severity": sarifSecuritySeverity(severity)
    }
  }));
}

function strongestValue<TValue extends string>(
  current: TValue,
  candidate: TValue,
  order: readonly TValue[]
): TValue {
  return order.indexOf(candidate) < order.indexOf(current) ? candidate : current;
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

const REDACTED_EVIDENCE = "[REDACTED]";

function redactFindingEvidence(finding: ScanResult["findings"][number]): string | undefined {
  if (!finding.evidence) {
    return undefined;
  }

  return isSecretFinding(finding) ? REDACTED_EVIDENCE : finding.evidence;
}

function redactScanResult(result: ScanResult): ScanResult {
  return {
    ...result,
    findings: result.findings.map((finding) =>
      finding.evidence && isSecretFinding(finding)
        ? { ...finding, evidence: REDACTED_EVIDENCE }
        : { ...finding }
    )
  };
}

function sarifRuleTags(finding: ScanResult["findings"][number]): string[] {
  return ["security", finding.category, ...cweTagsForRule(finding.ruleId)];
}

function cweTagsForRule(ruleId: string): string[] {
  switch (ruleId) {
    case "xss/dangerously-set-inner-html":
      return ["CWE-79", "external/cwe/cwe-79"];
    case "injection/command-exec":
      return ["CWE-78", "external/cwe/cwe-78"];
    case "injection/raw-sql-concat":
      return ["CWE-89", "external/cwe/cwe-89"];
    case "secrets/hardcoded-secret":
    case "secrets/weak-jwt-secret":
    case "secrets/next-public-secret":
      return ["CWE-798", "external/cwe/cwe-798"];
    case "headers/missing-security-headers":
      return ["CWE-693", "external/cwe/cwe-693"];
    case "upload/missing-file-size-limit":
    case "upload/missing-file-type-validation":
      return ["CWE-434", "external/cwe/cwe-434"];
    default:
      return [];
  }
}

function ruleHelpUri(ruleId: string): string {
  return `${INFORMATION_URI}#${ruleId.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase()}`;
}

function createFindingFingerprint(finding: ScanResult["findings"][number]): string {
  const fingerprintInput = [
    finding.ruleId,
    finding.filePath,
    finding.line ?? "",
    finding.column ?? "",
    finding.title
  ].join("\u0000");

  return createHash("sha256").update(fingerprintInput).digest("hex");
}

function createRuleLocationFingerprint(finding: ScanResult["findings"][number]): string {
  const fingerprintInput = [finding.ruleId, finding.filePath, finding.line ?? ""].join("\u0000");

  return createHash("sha256").update(fingerprintInput).digest("hex");
}

function createSarifMessageText(finding: ScanResult["findings"][number]): string {
  return [
    finding.title,
    truncateSarifMessagePart(finding.description),
    `Recommendation: ${truncateSarifMessagePart(finding.recommendation)}`
  ].join(" ");
}

function truncateSarifMessagePart(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= 180) {
    return normalized;
  }

  return `${normalized.slice(0, 177).trimEnd()}...`;
}

function formatSarifUri(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function formatLocation(finding: ScanResult["findings"][number]): string {
  return `${finding.filePath}${finding.line ? `:${finding.line}` : ""}`;
}

function compareSummaryFindings(
  left: ScanResult["findings"][number],
  right: ScanResult["findings"][number]
): number {
  const severityOrder = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
  if (severityOrder !== 0) {
    return severityOrder;
  }

  const locationOrder = compareText(formatLocation(left), formatLocation(right));
  if (locationOrder !== 0) {
    return locationOrder;
  }

  const ruleOrder = compareText(left.ruleId, right.ruleId);
  if (ruleOrder !== 0) {
    return ruleOrder;
  }

  return compareText(left.title, right.title);
}

function compareText(left: string, right: string): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function formatContext(finding: ScanResult["findings"][number]): string {
  return finding.context ?? "unknown";
}

function formatContextReason(finding: ScanResult["findings"][number]): string {
  return finding.contextReason ?? "no context metadata available";
}

function formatInlineText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function escapeBackticks(value: string): string {
  return value.replaceAll("`", "'");
}

function escapeTableCell(value: string): string {
  return value.replace(/\r?\n/g, " ").replaceAll("|", "\\|");
}
