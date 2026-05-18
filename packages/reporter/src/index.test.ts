import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatGithub, formatMarkdown, formatReport, formatSarif, formatSummary, formatTerminal } from "./index.js";

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

  it("renders SARIF reports with the minimum top-level structure", () => {
    const result = createScanResultSkeleton("demo-app");
    const sarif = JSON.parse(formatSarif(result));

    expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("next-secure-check");
    expect(sarif.runs[0].tool.driver.informationUri).toBe(
      "https://github.com/SetraTheXX/next-secure-check"
    );
    expect(sarif.runs[0].tool.driver.semanticVersion).toBe("0.0.0");
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
    expect(sarif.runs[0].results).toEqual([]);
    expect(formatReport(result, "sarif")).toBe(formatSarif(result));
  });

  it("maps findings to SARIF rules, results, severity, precision, and locations", () => {
    const result = createScanResultSkeleton("demo-app");
    result.metadata.toolVersion = "0.1.0";
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
        column: 7,
        evidence: "const apiKey = \"sk_live_super_secret\"",
        description: "A secret-like value appears in source code.",
        recommendation: "Move secrets to environment variables and rotate exposed values."
      },
      {
        id: "finding-2",
        ruleId: "secrets/hardcoded-secret",
        title: "Possible hardcoded secret detected",
        severity: "HIGH",
        confidence: "MEDIUM",
        category: "secrets",
        filePath: "config/secrets.ts",
        line: 3,
        evidence: "token: \"demo-token\"",
        description: "A secret-like value appears in source code.",
        recommendation: "Move secrets to environment variables and rotate exposed values."
      },
      {
        id: "finding-3",
        ruleId: "headers/missing-security-headers",
        title: "Security headers were not detected",
        severity: "LOW",
        confidence: "LOW",
        category: "headers",
        filePath: "next.config.js",
        description: "No common security header configuration was detected.",
        recommendation: "Configure common security headers."
      }
    ];

    const sarifText = formatSarif(result);
    const sarif = JSON.parse(sarifText);
    const rules = sarif.runs[0].tool.driver.rules;
    const results = sarif.runs[0].results;

    expect(rules).toHaveLength(2);
    expect(rules[0]).toMatchObject({
      id: "secrets/hardcoded-secret",
      shortDescription: { text: "Possible hardcoded secret detected" },
      fullDescription: { text: "A secret-like value appears in source code." },
      help: {
        markdown: "Move secrets to environment variables and rotate exposed values."
      },
      defaultConfiguration: { level: "error" },
      properties: {
        tags: ["security", "secrets"],
        precision: "high",
        "security-severity": "8.0"
      }
    });
    expect(rules[1]).toMatchObject({
      id: "headers/missing-security-headers",
      defaultConfiguration: { level: "warning" },
      properties: {
        tags: ["security", "headers"],
        precision: "low",
        "security-severity": "2.0"
      }
    });

    expect(results[0]).toMatchObject({
      ruleId: "secrets/hardcoded-secret",
      ruleIndex: 0,
      level: "error",
      message: { text: "Possible hardcoded secret detected" },
      partialFingerprints: {
        "nextSecureCheck/v1": expect.any(String)
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "app/api/login/route.ts" },
            region: { startLine: 12, startColumn: 7 }
          }
        }
      ],
      properties: {
        category: "secrets",
        confidence: "HIGH",
        nextSecureCheckFindingId: "finding-1",
        evidenceRedacted: true
      }
    });
    expect(results[1].ruleIndex).toBe(0);
    expect(results[1].partialFingerprints["nextSecureCheck/v1"]).toEqual(expect.any(String));
    expect(results[1].partialFingerprints["nextSecureCheck/v1"]).not.toBe(
      results[0].partialFingerprints["nextSecureCheck/v1"]
    );
    expect(results[2]).toMatchObject({
      ruleId: "headers/missing-security-headers",
      ruleIndex: 1,
      level: "warning",
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "next.config.js" }
          }
        }
      ],
      properties: {
        evidenceRedacted: false
      }
    });
    expect(sarifText).not.toContain("sk_live_super_secret");
    expect(sarifText).not.toContain("demo-token");
  });

  it("generates stable SARIF partial fingerprints for the same finding", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [
      {
        id: "finding-1",
        ruleId: "headers/missing-security-headers",
        title: "Security headers were not detected",
        severity: "LOW",
        confidence: "LOW",
        category: "headers",
        filePath: "next.config.js",
        line: 2,
        column: 1,
        description: "No common security header configuration was detected.",
        recommendation: "Configure common security headers."
      }
    ];

    const firstSarif = JSON.parse(formatSarif(result));
    const secondSarif = JSON.parse(formatSarif(result));

    expect(firstSarif.runs[0].results[0].partialFingerprints).toEqual(
      secondSarif.runs[0].results[0].partialFingerprints
    );
  });

  it("maps medium and info findings to SARIF levels and security severities", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [
      {
        id: "finding-1",
        ruleId: "validation/api-route-without-validation",
        title: "API route may be missing input validation",
        severity: "MEDIUM",
        confidence: "MEDIUM",
        category: "validation",
        filePath: "app/api/users/route.ts",
        description: "API routes that consume user input should validate the input.",
        recommendation: "Add input validation."
      },
      {
        id: "finding-2",
        ruleId: "config/next-powered-by-header",
        title: "X-Powered-By header may be enabled",
        severity: "INFO",
        confidence: "MEDIUM",
        category: "config",
        filePath: "next.config.js",
        description: "The default header can reveal framework information.",
        recommendation: "Set poweredByHeader: false."
      }
    ];

    const sarif = JSON.parse(formatSarif(result));

    expect(sarif.runs[0].tool.driver.rules[0].properties["security-severity"]).toBe("5.0");
    expect(sarif.runs[0].tool.driver.rules[1].properties["security-severity"]).toBe("0.0");
    expect(sarif.runs[0].results[0].level).toBe("warning");
    expect(sarif.runs[0].results[1].level).toBe("note");
  });
});
