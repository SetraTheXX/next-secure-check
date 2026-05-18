import { describe, expect, it } from "vitest";
import type { Finding, RiskLevel, Severity } from "@next-secure-check/core";
import { shouldFail } from "./fail-on.js";

describe("shouldFail", () => {
  it("fails critical gates based on scan risk level", () => {
    expect(shouldFail(createResult("critical", ["HIGH"]), "critical")).toBe(true);
  });

  it("does not fail critical gates for non-critical risk levels", () => {
    expect(shouldFail(createResult("high", ["HIGH"]), "critical")).toBe(false);
    expect(shouldFail(createResult("excellent", ["LOW"]), "critical")).toBe(false);
  });

  it("keeps severity threshold gates for high, medium, low, and info", () => {
    expect(shouldFail(createResult("excellent", ["HIGH"]), "high")).toBe(true);
    expect(shouldFail(createResult("excellent", ["MEDIUM"]), "high")).toBe(false);
    expect(shouldFail(createResult("excellent", ["MEDIUM"]), "medium")).toBe(true);
    expect(shouldFail(createResult("excellent", ["LOW"]), "medium")).toBe(false);
    expect(shouldFail(createResult("excellent", ["LOW"]), "low")).toBe(true);
    expect(shouldFail(createResult("excellent", ["INFO"]), "low")).toBe(false);
    expect(shouldFail(createResult("excellent", ["INFO"]), "info")).toBe(true);
  });

  it("does not fail when failOn is not configured", () => {
    expect(shouldFail(createResult("critical", ["HIGH"]), undefined)).toBe(false);
  });
});

function createResult(riskLevel: RiskLevel, severities: Severity[]) {
  const findings = severities.map((severity, index) => createFinding(severity, index));
  return {
    findings,
    summary: {
      high: severities.filter((severity) => severity === "HIGH").length,
      info: severities.filter((severity) => severity === "INFO").length,
      low: severities.filter((severity) => severity === "LOW").length,
      medium: severities.filter((severity) => severity === "MEDIUM").length,
      riskLevel,
      score: 100,
      totalFindings: findings.length
    }
  };
}

function createFinding(severity: Severity, index: number): Finding {
  return {
    category: "test",
    confidence: "HIGH",
    description: "description",
    filePath: `file-${index}.ts`,
    id: `finding-${index}`,
    recommendation: "recommendation",
    ruleId: `rule/${index}`,
    severity,
    title: "title"
  };
}
