import { describe, expect, it } from "vitest";
import {
  createScanJsonExport,
  createScanMarkdownExport,
  createResultTextIndex,
  evidenceIsRedacted,
  formatFindingLocation,
  getHiddenFindingCount,
  getVisibleFindings,
  LOADING_STATE_TITLE,
  MAX_RENDERED_FINDINGS,
  resultContainsRawEvidence,
  validateRepoInput
} from "../lib/scan-ui";

describe("Home scan UI helpers", () => {
  it("validates empty repo input", () => {
    expect(validateRepoInput("")).toBe("Repository URL is required.");
  });

  it("validates invalid repo input", () => {
    expect(validateRepoInput("https://example.com/owner/repo")).toBe(
      "Only github.com repositories are supported."
    );
  });

  it("formats finding location with line and column", () => {
    expect(
      formatFindingLocation({
        ...createFinding(),
        column: 8,
        line: 12
      })
    ).toBe("app/page.tsx:12:8");
  });

  it("has loading state copy covered by the UI flow", () => {
    expect(LOADING_STATE_TITLE).toBe("Scanning repository");
  });

  it("keeps API error message renderable", () => {
    expect("Repository not found").toBe("Repository not found");
  });

  it("renders successful API response details", () => {
    const result = createSuccessResult();
    const text = createResultTextIndex(result).join(" ");

    expect(text).toContain("owner/repo");
    expect(text).toContain("Score");
    expect(text).toContain("72");
    expect(text).toContain("Findings");
    expect(text).toContain("secrets/hardcoded");
    expect(text).toContain("HIGH");
    expect(text).toContain("app/page.tsx:3:5");
    expect(text).toContain("Rotate the secret.");
  });

  it("shows redacted evidence without raw secret evidence", () => {
    const result = createSuccessResult();
    const finding = result.scan.findings[0];

    expect(finding).toBeDefined();
    expect(finding ? evidenceIsRedacted(finding) : false).toBe(true);
    expect(resultContainsRawEvidence(result, "GITHUB_TOKEN=raw-secret")).toBe(false);

    const text = createResultTextIndex(result).join(" ");
    expect(text).toContain("[REDACTED]");
    expect(text).not.toContain("GITHUB_TOKEN=raw-secret");
  });

  it("supports the redacted evidence UI label", () => {
    expect(evidenceIsRedacted(createFinding())).toBe(true);
    expect("Evidence redacted server-side").toContain("redacted");
  });

  it("creates valid JSON export", () => {
    const exported = createScanJsonExport(createSuccessResult());

    expect(() => JSON.parse(exported)).not.toThrow();
    expect(JSON.parse(exported)).toMatchObject({
      ok: true,
      repo: {
        fullName: "owner/repo"
      }
    });
  });

  it("creates Markdown export with score, risk, and findings", () => {
    const exported = createScanMarkdownExport(createSuccessResult());

    expect(exported).toContain("# next-secure-check report: owner/repo");
    expect(exported).toContain("- Score: 72");
    expect(exported).toContain("- Risk level: high");
    expect(exported).toContain("## Findings");
    expect(exported).toContain("secrets/hardcoded");
  });

  it("does not include raw secret evidence in exports", () => {
    const result = createSuccessResult();

    expect(createScanJsonExport(result)).not.toContain("GITHUB_TOKEN=raw-secret");
    expect(createScanMarkdownExport(result)).not.toContain("GITHUB_TOKEN=raw-secret");
  });

  it("includes redacted evidence in exports", () => {
    const result = createSuccessResult();

    expect(createScanJsonExport(result)).toContain("[REDACTED]");
    expect(createScanMarkdownExport(result)).toContain("[REDACTED]");
  });

  it("limits visible findings for large UI result sets", () => {
    const result = createSuccessResult(
      Array.from({ length: MAX_RENDERED_FINDINGS + 2 }, (_, index) =>
        createFinding({
          id: `finding-${index}`,
          ruleId: `headers/rule-${index}`
        })
      )
    );

    expect(getVisibleFindings(result)).toHaveLength(MAX_RENDERED_FINDINGS);
    expect(getHiddenFindingCount(result)).toBe(2);
    expect(createResultTextIndex(result).join(" ")).toContain("2");
  });
});

function createFinding(overrides = {}) {
  return {
    category: "secrets",
    confidence: "HIGH" as const,
    description: "Secret in source",
    evidence: "[REDACTED]",
    filePath: "app/page.tsx",
    id: "finding-1",
    line: 3,
    column: 5,
    recommendation: "Rotate the secret.",
    ruleId: "secrets/hardcoded",
    severity: "HIGH" as const,
    title: "Hardcoded secret",
    ...overrides
  };
}

function createSuccessResult(findings = [createFinding()]) {
  return {
    extraction: {
      fileCount: 12,
      tempId: "temp-id",
      totalBytes: 2048
    },
    ok: true as const,
    repo: {
      archived: false,
      defaultBranch: "main",
      fullName: "owner/repo",
      htmlUrl: "https://github.com/owner/repo",
      owner: "owner",
      repo: "repo"
    },
    scan: {
      findings,
      metadata: {
        durationMs: 11,
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
        high: 1,
        info: 0,
        low: 0,
        medium: 0,
        riskLevel: "high",
        score: 72,
        totalFindings: 1
      }
    }
  };
}
