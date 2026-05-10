import type { Confidence, Finding, RiskLevel, ScanSummary, Severity } from "./types.js";

const SEVERITY_COUNTS: Severity[] = ["HIGH", "MEDIUM", "LOW", "INFO"];

const PENALTY: Record<Severity, number> = {
  HIGH: 15,
  MEDIUM: 7,
  LOW: 3,
  INFO: 0
};

const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  HIGH: 1,
  MEDIUM: 0.7,
  LOW: 0.4
};

export function summarizeFindings(findings: Finding[]): ScanSummary {
  const counts = countBySeverity(findings);
  const penalty = findings.reduce((total, finding) => {
    return total + PENALTY[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence];
  }, 0);
  const score = Math.max(0, Math.round(100 - penalty));

  return {
    score,
    riskLevel: riskLevelForScore(score),
    totalFindings: findings.length,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    info: counts.INFO
  };
}

export function riskLevelForScore(score: number): RiskLevel {
  if (score >= 90) {
    return "excellent";
  }
  if (score >= 75) {
    return "good";
  }
  if (score >= 60) {
    return "medium";
  }
  if (score >= 40) {
    return "high";
  }
  return "critical";
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  return Object.fromEntries(
    SEVERITY_COUNTS.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length])
  ) as Record<Severity, number>;
}
