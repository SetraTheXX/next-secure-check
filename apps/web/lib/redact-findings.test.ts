import type { Finding, ScanResult } from "@next-secure-check/core";
import { describe, expect, it } from "vitest";
import { redactFindingEvidence, redactScanResult } from "./redact-findings";

describe("redactFindingEvidence", () => {
  it("redacts evidence for secrets category", () => {
    const result = redactFindingEvidence(
      createFinding({
        category: "secrets",
        evidence: "API_KEY=raw-secret",
        ruleId: "hardcoded-secret"
      })
    );

    expect(result.evidence).toBe("[REDACTED]");
  });

  it("redacts evidence for secrets rule namespace", () => {
    const result = redactFindingEvidence(
      createFinding({
        category: "config",
        evidence: "TOKEN=raw-secret",
        ruleId: "secrets/env-token"
      })
    );

    expect(result.evidence).toBe("[REDACTED]");
  });

  it("keeps non-secret evidence", () => {
    const result = redactFindingEvidence(
      createFinding({
        category: "headers",
        evidence: "headers missing",
        ruleId: "headers/missing-security"
      })
    );

    expect(result.evidence).toBe("headers missing");
  });
});

describe("redactScanResult", () => {
  it("redacts only secret findings in a scan result", () => {
    const scan = createScanResult([
      createFinding({ category: "secrets", evidence: "secret", ruleId: "hardcoded-secret" }),
      createFinding({ category: "headers", evidence: "safe", ruleId: "headers/missing" })
    ]);

    const result = redactScanResult(scan);

    expect(result.findings.map((finding) => finding.evidence)).toEqual(["[REDACTED]", "safe"]);
  });
});

function createFinding(overrides: Partial<Finding>): Finding {
  return {
    category: "headers",
    confidence: "HIGH",
    description: "description",
    evidence: "evidence",
    filePath: "app/page.tsx",
    id: "finding-id",
    recommendation: "recommendation",
    ruleId: "rule/id",
    severity: "HIGH",
    title: "title",
    ...overrides
  };
}

function createScanResult(findings: Finding[]): ScanResult {
  return {
    findings,
    metadata: {
      durationMs: 1,
      scannedAt: "2026-05-17T00:00:00.000Z",
      toolVersion: "test"
    },
    project: {
      framework: "nextjs",
      language: "typescript",
      name: "repo",
      router: "app"
    },
    summary: {
      high: findings.length,
      info: 0,
      low: 0,
      medium: 0,
      riskLevel: "high",
      score: 50,
      totalFindings: findings.length
    }
  };
}
