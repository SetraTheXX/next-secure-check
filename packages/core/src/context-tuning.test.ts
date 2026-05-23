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

  it("lowers raw SQL findings in app component/UI context", () => {
    expect(tune("injection/raw-sql-concat", "app-code", "apps/v4/app/(app)/components/table.tsx")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered raw SQL finding in app component/UI context"
    });
  });

  it("keeps raw SQL findings in API code unchanged", () => {
    const finding = tune("injection/raw-sql-concat", "api-code", "app/api/users/route.ts");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalSeverity).toBeUndefined();
    expect(finding.originalConfidence).toBeUndefined();
  });

  it("lowers admin route findings in example context", () => {
    expect(tune("auth/admin-route-without-auth", "example-code")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH"
    });
  });

  it("lowers admin route findings in non-API app component context", () => {
    expect(tune("auth/admin-route-without-auth", "app-code", "apps/v4/app/(app)/(styles)/admin-card.tsx")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered admin route finding in non-API app component context"
    });
  });

  it("keeps admin route findings in API context unchanged", () => {
    const finding = tune("auth/admin-route-without-auth", "api-code", "apps/v4/app/api/admin/route.ts");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalSeverity).toBeUndefined();
    expect(finding.originalConfidence).toBeUndefined();
    expect(finding.contextAdjustmentReason).toBeUndefined();
  });

  it("lowers password-handling findings in docs/example/template context", () => {
    expect(tune("auth/password-without-hashing-library", "template-code", "templates/default/app/api/register/route.ts")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered password-handling finding in docs/example/template context"
    });
  });

  it("lowers password-handling findings in app component/UI context", () => {
    expect(tune("auth/password-without-hashing-library", "app-code", "apps/v4/app/(app)/components/password-field.tsx")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered password-handling finding in app component/UI context"
    });
  });

  it("keeps password-handling findings in API code unchanged", () => {
    const finding = tune("auth/password-without-hashing-library", "api-code", "app/api/register/route.ts");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalSeverity).toBeUndefined();
  });

  it("lowers upload validation findings in docs/example/template context", () => {
    expect(tune("upload/missing-file-size-limit", "example-code", "examples/upload/app/api/route.ts")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered upload validation finding in docs/example/template context"
    });
  });

  it("lowers upload validation findings in app component/UI context", () => {
    expect(tune("upload/missing-file-type-validation", "app-code", "apps/v4/app/(app)/components/file-filter.tsx")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered upload validation finding in app component/UI context"
    });
  });

  it("keeps upload validation findings in API code unchanged", () => {
    const finding = tune("upload/missing-file-type-validation", "api-code", "app/api/upload/route.ts");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalSeverity).toBeUndefined();
  });

  it("lowers dangerouslySetInnerHTML findings in docs/example/template context", () => {
    expect(tune("xss/dangerously-set-inner-html", "example-code", "examples/demo/app/page.tsx")).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered dangerouslySetInnerHTML finding in docs/example/template context"
    });
  });

  it("lowers dangerouslySetInnerHTML confidence in app story/demo paths only", () => {
    const storyFinding = tune("xss/dangerously-set-inner-html", "app-code", "apps/web/app/components/button.stories.tsx");
    const appFinding = tune("xss/dangerously-set-inner-html", "app-code", "app/profile/page.tsx", {
      evidence: "return <main dangerouslySetInnerHTML={{ __html: searchParams.preview }} />;"
    });

    expect(storyFinding).toMatchObject({
      severity: "HIGH",
      confidence: "LOW",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered dangerouslySetInnerHTML confidence in demo/story/fixture app context"
    });
    expect(storyFinding.originalSeverity).toBeUndefined();
    expect(appFinding.originalSeverity).toBeUndefined();
    expect(appFinding.originalConfidence).toBeUndefined();
  });

  it("lowers dangerouslySetInnerHTML confidence in app component UI paths", () => {
    expect(
      tune("xss/dangerously-set-inner-html", "app-code", "apps/web/app/components/preview.tsx", {
        evidence: "return <div dangerouslySetInnerHTML={{ __html: html }} />;"
      })
    ).toMatchObject({
      severity: "HIGH",
      confidence: "LOW",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered dangerouslySetInnerHTML confidence in app component/UI context"
    });
  });

  it("keeps explicitly user-controlled dangerouslySetInnerHTML app findings unchanged", () => {
    const finding = tune("xss/dangerously-set-inner-html", "app-code", "app/profile/page.tsx", {
      evidence: "return <main dangerouslySetInnerHTML={{ __html: userInput }} />;"
    });

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH"
    });
    expect(finding.originalConfidence).toBeUndefined();
  });

  it("lowers powered-by header findings in docs/example/template context", () => {
    expect(tune("config/next-powered-by-header", "template-code", "templates/default/next.config.js")).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      contextAdjustmentReason: "lowered powered-by header finding in docs/example/template context"
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

function tune(ruleId: string, context: FindingContext, filePath = "file.ts", overrides: Partial<Finding> = {}): Finding {
  return applyContextTuning({
    id: "finding-1",
    ruleId,
    title: "Finding",
    severity: "HIGH",
    confidence: "HIGH",
    category: ruleId.split("/")[0] ?? "test",
    filePath,
    context,
    contextReason: "test context",
    description: "description",
    recommendation: "recommendation",
    ...overrides
  });
}
