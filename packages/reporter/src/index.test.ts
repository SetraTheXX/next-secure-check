import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatGithub, formatMarkdown, formatReport, formatSummary, formatTerminal } from "./index.js";

describe("formatSummary", () => {
  it("renders the scan score and risk level", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatSummary(result)).toContain("Score: 100/100");
    expect(formatSummary(result)).toContain("Risk Level: excellent");
  });

  it("renders json reports", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(JSON.parse(formatReport(result, "json")).summary.score).toBe(100);
  });

  it("renders markdown reports", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatMarkdown(result)).toContain("# next-secure-check report");
  });

  it("renders github reports as a compact summary table", () => {
    const result = createScanResultSkeleton("demo-app");
    result.project.framework = "nextjs";
    result.summary = {
      score: 72,
      riskLevel: "high",
      totalFindings: 1,
      high: 1,
      medium: 0,
      low: 0,
      info: 0
    };
    result.findings = [
      {
        id: "finding-1",
        ruleId: "secrets/hardcoded-secret",
        title: "Possible hardcoded secret detected",
        severity: "HIGH",
        confidence: "HIGH",
        category: "secrets",
        filePath: "app/api/login/route.ts",
        line: 12,
        description: "A secret-like value appears in source code.",
        recommendation: "Move secrets to environment variables and rotate exposed values."
      }
    ];

    const githubReport = formatGithub(result);

    expect(githubReport).toContain("## next-secure-check");
    expect(githubReport).toContain("| Metric | Value |");
    expect(githubReport).toContain("| HIGH | `secrets/hardcoded-secret` | Possible hardcoded secret detected | `app/api/login/route.ts:12` | HIGH |");
    expect(githubReport).toContain("<summary>Recommendations</summary>");
    expect(formatReport(result, "github")).toBe(githubReport);
    expect(githubReport).not.toBe(formatMarkdown(result));
  });

  it("renders terminal reports with no findings", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatTerminal(result)).toContain("No findings detected.");
  });

  it("renders github reports with no findings", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatGithub(result)).toContain("**Status:** No findings");
    expect(formatGithub(result)).toContain("No findings detected.");
  });
});
