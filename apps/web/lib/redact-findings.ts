import type { Finding, ScanResult } from "@next-secure-check/core";

const REDACTED_EVIDENCE = "[REDACTED]";

export type RedactedFinding = Finding;
export type RedactedScanResult = Omit<ScanResult, "findings"> & {
  findings: RedactedFinding[];
};

export function redactFindingEvidence(finding: Finding): RedactedFinding {
  if (!isSecretFinding(finding)) {
    return { ...finding };
  }

  const { evidence: _evidence, ...safeFinding } = finding;
  return {
    ...safeFinding,
    evidence: REDACTED_EVIDENCE
  };
}

export function redactScanResult(result: ScanResult): RedactedScanResult {
  return {
    ...result,
    findings: result.findings.map(redactFindingEvidence)
  };
}

function isSecretFinding(finding: Finding): boolean {
  return finding.category === "secrets" || finding.ruleId.startsWith("secrets/");
}
