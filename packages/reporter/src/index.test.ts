import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatGithub, formatMarkdown, formatReport, formatSarif, formatSummary, formatTerminal } from "./index.js";

describe("formatSummary", () => {
  it("renders the scan score and risk level", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatSummary(result)).toContain("Score: 100/100");
    expect(formatSummary(result)).toContain("Risk Level: excellent");
  });

  it("renders a concise finding overview without evidence details", () => {
    const result = createScanResultSkeleton("demo-app");
    result.summary = {
      score: 80,
      riskLevel: "medium",
      totalFindings: 1,
      high: 0,
      medium: 1,
      low: 0,
      info: 0
    };
    result.findings = [
      {
        ...createContextFinding(),
        evidence: "request.json() -> query",
        line: 12,
        recommendation: "Add input validation."
      }
    ];

    const summary = formatSummary(result);

    expect(summary).toContain("next-secure-check summary");
    expect(summary).toContain("Score: 80/100 | Risk Level: medium");
    expect(summary).toContain("Findings: 1 | HIGH 0 | MEDIUM 1 | LOW 0 | INFO 0");
    expect(summary).toContain(
      "- MEDIUM validation/api-route-without-validation [confidence: MEDIUM, context: api-code] app/api/users/route.ts:12"
    );
    expect(summary).not.toContain("Evidence:");
    expect(summary).not.toContain("Fix:");
  });

  it("limits the overview to deterministic top findings", () => {
    const result = createScanResultSkeleton("demo-app");
    result.summary = {
      score: 42,
      riskLevel: "high",
      totalFindings: 4,
      high: 1,
      medium: 2,
      low: 1,
      info: 0
    };
    result.findings = [
      { ...createContextFinding(), id: "medium-z", filePath: "z.ts" },
      { ...createContextFinding(), id: "low-a", filePath: "a.ts", severity: "LOW", confidence: "LOW" },
      { ...createContextFinding(), id: "high-a", filePath: "a.ts", severity: "HIGH", confidence: "HIGH" },
      { ...createContextFinding(), id: "medium-a", filePath: "a.ts" }
    ];

    const summary = formatSummary(result);

    expect(summary.indexOf("- HIGH validation/api-route-without-validation")).toBeLessThan(
      summary.indexOf("- MEDIUM validation/api-route-without-validation")
    );
    expect(summary).toContain("+1 more findings. Run without --summary for full details.");
  });

  it("keeps evidence and recommendations in the default terminal report", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [{ ...createContextFinding(), evidence: "request.json() -> query" }];

    const terminal = formatReport(result, "terminal");

    expect(terminal).toContain("Evidence: request.json() -> query");
    expect(terminal).toContain("Fix: Add input validation.");
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
        context: "api-code",
        contextReason: "matched Next.js API route path",
        line: 12,
        description: "A secret-like value appears in source code.",
        recommendation: "Move secrets to environment variables and rotate exposed values."
      }
    ];

    const githubReport = formatGithub(result);

    expect(githubReport).toContain("## next-secure-check");
    expect(githubReport).toContain("| Metric | Value |");
    expect(githubReport).toContain("| Severity | Rule | Title | Location | Confidence | Context |");
    expect(githubReport).toContain("| HIGH | `secrets/hardcoded-secret` | Possible hardcoded secret detected | `app/api/login/route.ts:12` | HIGH | api-code |");
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

  it("renders finding context in terminal reports", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [createContextFinding()];
    result.summary = {
      score: 80,
      riskLevel: "medium",
      totalFindings: 1,
      high: 0,
      medium: 1,
      low: 0,
      info: 0
    };

    const terminalReport = formatTerminal(result);

    expect(terminalReport).toContain(
      "API route may be missing input validation [validation/api-route-without-validation, confidence: MEDIUM, context: api-code]"
    );
  });

  it("renders finding context in markdown reports", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [createContextFinding()];

    const markdownReport = formatMarkdown(result);

    expect(markdownReport).toContain("- Context: `api-code`");
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
        context: "api-code",
        contextReason: "matched Next.js API route path",
        line: 12,
        column: 7,
        evidence: "const apiKey = \"sk_live_super_secret\"",
        evidencePath: "request.json() -> apiKey",
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
        context: "unknown",
        contextReason: "no known file context pattern matched",
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
        context: "unknown",
        contextReason: "no known file context pattern matched",
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
      helpUri: "https://github.com/SetraTheXX/next-secure-check#secrets-hardcoded-secret",
      properties: {
        tags: ["security", "secrets", "CWE-798", "external/cwe/cwe-798"],
        precision: "high",
        "security-severity": "8.0"
      }
    });
    expect(rules[1]).toMatchObject({
      id: "headers/missing-security-headers",
      helpUri: "https://github.com/SetraTheXX/next-secure-check#headers-missing-security-headers",
      defaultConfiguration: { level: "warning" },
      properties: {
        tags: ["security", "headers", "CWE-693", "external/cwe/cwe-693"],
        precision: "low",
        "security-severity": "2.0"
      }
    });

    expect(results[0]).toMatchObject({
      ruleId: "secrets/hardcoded-secret",
      ruleIndex: 0,
      level: "error",
      message: {
        text: "Possible hardcoded secret detected A secret-like value appears in source code. Recommendation: Move secrets to environment variables and rotate exposed values."
      },
      partialFingerprints: {
        "nextSecureCheck/v1": expect.any(String),
        "nextSecureCheck/ruleLocation/v1": expect.any(String)
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
        context: "api-code",
        contextReason: "matched Next.js API route path",
        nextSecureCheckFindingId: "finding-1",
        evidenceRedacted: true,
        evidencePath: "request.json() -> apiKey"
      }
    });
    expect(results[1].ruleIndex).toBe(0);
    expect(results[1].partialFingerprints["nextSecureCheck/v1"]).toEqual(expect.any(String));
    expect(results[1].partialFingerprints["nextSecureCheck/ruleLocation/v1"]).toEqual(expect.any(String));
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
        evidenceRedacted: false,
        context: "unknown",
        contextReason: "no known file context pattern matched"
      }
    });
    expect(sarifText).not.toContain("sk_live_super_secret");
    expect(sarifText).not.toContain("demo-token");
    expect(results[0].message.text).toContain("Possible hardcoded secret detected");
    expect(results[0].message.text).toContain("A secret-like value appears in source code.");
    expect(results[0].message.text).toContain("Recommendation: Move secrets to environment variables");
    expect(results[0].message.text).not.toContain("sk_live_super_secret");
  });

  it("adds SARIF helpUri and CWE metadata for common security rule families", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [
      createSarifFinding("xss/dangerously-set-inner-html", "xss", "MEDIUM", "MEDIUM"),
      createSarifFinding("injection/command-exec", "injection", "HIGH", "MEDIUM"),
      createSarifFinding("injection/raw-sql-concat", "injection", "HIGH", "MEDIUM"),
      createSarifFinding("upload/missing-file-type-validation", "upload", "MEDIUM", "MEDIUM"),
      createSarifFinding("auth/admin-route-without-auth", "auth", "HIGH", "MEDIUM")
    ];

    const sarif = JSON.parse(formatSarif(result));
    const rules = sarif.runs[0].tool.driver.rules;

    expect(rules.find((rule: { id: string }) => rule.id === "xss/dangerously-set-inner-html")).toMatchObject({
      helpUri: "https://github.com/SetraTheXX/next-secure-check#xss-dangerously-set-inner-html",
      properties: {
        tags: ["security", "xss", "CWE-79", "external/cwe/cwe-79"]
      }
    });
    expect(rules.find((rule: { id: string }) => rule.id === "injection/command-exec").properties.tags).toEqual([
      "security",
      "injection",
      "CWE-78",
      "external/cwe/cwe-78"
    ]);
    expect(rules.find((rule: { id: string }) => rule.id === "injection/raw-sql-concat").properties.tags).toEqual([
      "security",
      "injection",
      "CWE-89",
      "external/cwe/cwe-89"
    ]);
    expect(rules.find((rule: { id: string }) => rule.id === "upload/missing-file-type-validation").properties.tags).toEqual([
      "security",
      "upload",
      "CWE-434",
      "external/cwe/cwe-434"
    ]);
    expect(rules.find((rule: { id: string }) => rule.id === "auth/admin-route-without-auth").properties.tags).toEqual([
      "security",
      "auth"
    ]);
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
        context: "unknown",
        contextReason: "no known file context pattern matched",
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
        context: "api-code",
        contextReason: "matched Next.js API route path",
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
        context: "unknown",
        contextReason: "no known file context pattern matched",
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

  it("uses the strongest effective severity and confidence for shared SARIF rule metadata", () => {
    const result = createScanResultSkeleton("demo-app");
    result.findings = [
      {
        id: "release-finding",
        ruleId: "injection/command-exec",
        title: "Shell command execution detected",
        severity: "LOW",
        confidence: "LOW",
        category: "injection",
        filePath: ".github/release.ts",
        description: "A shell command is executed.",
        recommendation: "Review command inputs."
      },
      {
        id: "api-finding",
        ruleId: "injection/command-exec",
        title: "Shell command execution detected",
        severity: "HIGH",
        confidence: "HIGH",
        category: "injection",
        filePath: "app/api/run/route.ts",
        description: "A shell command is executed.",
        recommendation: "Review command inputs."
      }
    ];

    const sarif = JSON.parse(formatSarif(result));
    const rule = sarif.runs[0].tool.driver.rules[0];

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(rule.defaultConfiguration.level).toBe("error");
    expect(rule.properties["security-severity"]).toBe("8.0");
    expect(rule.properties.precision).toBe("high");
    expect(sarif.runs[0].results.map((entry: { level: string }) => entry.level)).toEqual(["warning", "error"]);
  });
});

function createContextFinding() {
  return {
    id: "finding-1",
    ruleId: "validation/api-route-without-validation",
    title: "API route may be missing input validation",
    severity: "MEDIUM" as const,
    confidence: "MEDIUM" as const,
    category: "validation",
    filePath: "app/api/users/route.ts",
    context: "api-code" as const,
    contextReason: "matched Next.js API route path",
    description: "API routes that consume user input should validate the input.",
    recommendation: "Add input validation."
  };
}

function createSarifFinding(
  ruleId: string,
  category: string,
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO",
  confidence: "HIGH" | "MEDIUM" | "LOW"
) {
  return {
    id: `${ruleId}:finding`,
    ruleId,
    title: ruleId,
    severity,
    confidence,
    category,
    filePath: "app/api/example/route.ts",
    context: "api-code" as const,
    contextReason: "matched Next.js API route path",
    description: "Test description.",
    recommendation: "Test recommendation."
  };
}
