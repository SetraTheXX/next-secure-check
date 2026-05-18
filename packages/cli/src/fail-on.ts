import type { ScanResult, Severity } from "@next-secure-check/core";

export function shouldFail(result: Pick<ScanResult, "findings" | "summary">, failOn?: string): boolean {
  if (!failOn) {
    return false;
  }

  if (failOn.toLowerCase() === "critical") {
    return result.summary.riskLevel === "critical";
  }

  const threshold = severityRank(parseSeverity(failOn));
  return result.findings.some((finding) => severityRank(finding.severity) >= threshold);
}

function parseSeverity(value: string): Severity {
  const normalized = value.toUpperCase();
  if (["HIGH", "MEDIUM", "LOW", "INFO"].includes(normalized)) {
    return normalized as Severity;
  }

  throw new Error(`Unsupported fail-on severity: ${value}`);
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    case "INFO":
      return 0;
  }
}
