import type { ScanResult } from "@next-secure-check/core";

export function formatSummary(result: ScanResult): string {
  const { summary } = result;

  return [
    "next-secure-check report",
    "",
    `Score: ${summary.score}/100`,
    `Risk Level: ${summary.riskLevel}`,
    `Findings: ${summary.totalFindings}`,
    "",
    "No rules have run yet. Phase 1 will add the scanner and first rules."
  ].join("\n");
}
