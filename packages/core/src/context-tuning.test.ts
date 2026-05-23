import { describe, expect, it } from "vitest";
import { applyContextTuning } from "./context-tuning.js";
import type { Finding, FindingContext } from "./types.js";

describe("applyContextTuning", () => {
  it("lowers command execution findings in release tooling context", () => {
    expect(tune("injection/command-exec", "release-tooling")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered command execution finding in release/tooling context"
    });
  });

  it("lowers command execution findings in CLI tooling context", () => {
    expect(tune("injection/command-exec", "cli-tooling")).toMatchObject({
      severity: "MEDIUM",
      confidence: "MEDIUM",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });

  it("keeps command execution findings in API code unchanged", () => {
    const finding = tune("injection/command-exec", "api-code");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalSeverity).toBeUndefined();
    expect(finding.originalConfidence).toBeUndefined();
    expect(finding.contextAdjustmentReason).toBeUndefined();
  });

  it("lowers raw SQL findings in docs/example/template context", () => {
    expect(tune("injection/raw-sql-concat", "example-code")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });

  it("lowers admin route findings in example context", () => {
    expect(tune("auth/admin-route-without-auth", "example-code")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });

  it("lowers API validation findings in template context", () => {
    expect(tune("validation/api-route-without-validation", "template-code")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });

  it("lowers auth rate-limit findings in example context", () => {
    expect(tune("auth/login-without-rate-limit", "example-code")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });
});

function tune(ruleId: string, context: FindingContext): Finding {
  return applyContextTuning({
    id: "finding-1",
    ruleId,
    title: "Finding",
    severity: "HIGH",
    confidence: "HIGH",
    category: ruleId.split("/")[0] ?? "test",
    filePath: "file.ts",
    context,
    contextReason: "test context",
    description: "description",
    recommendation: "recommendation"
  });
}
