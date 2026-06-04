import { describe, expect, it } from "vitest";
import type { Finding, RiskLevel, Severity } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import { shouldFail } from "./fail-on.js";
import { formatRuleExplanation, formatRulesList, formatUnknownRuleMessage } from "./rules-info.js";

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

describe("rules CLI helpers", () => {
  it("formats the built-in rule list", () => {
    const output = formatRulesList(getBuiltInRules());

    expect(output).toContain("next-secure-check rules");
    expect(output).toContain("Rule ID");
    expect(output).toContain("xss/dangerously-set-inner-html");
    expect(output).toContain("auth/login-without-rate-limit");
    expect(output).toContain("Total rules:");
  });

  it("explains a known rule", () => {
    const output = formatRuleExplanation(getBuiltInRules(), "xss/dangerously-set-inner-html");

    expect(output).toContain("Rule: xss/dangerously-set-inner-html");
    expect(output).toContain("Title: dangerouslySetInnerHTML usage detected");
    expect(output).toContain("Category: xss");
    expect(output).toContain("Severity:");
    expect(output).toContain("Checks:");
    expect(output).toContain("Why it matters:");
    expect(output).toContain("False positive note:");
    expect(output).toContain("Help: https://github.com/SetraTheXX/next-secure-check#xss-dangerously-set-inner-html");
  });

  it("returns undefined and formats a helpful message for unknown rule ids", () => {
    const rules = getBuiltInRules();

    expect(formatRuleExplanation(rules, "xss/not-a-rule")).toBeUndefined();
    expect(formatUnknownRuleMessage(rules, "xss/not-a-rule")).toContain("Unknown rule id: xss/not-a-rule");
    expect(formatUnknownRuleMessage(rules, "xss/not-a-rule")).toContain("next-secure-check rules");
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
