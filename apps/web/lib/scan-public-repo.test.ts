import type { Finding, Rule, ScanOptions, ScanResult } from "@next-secure-check/core";
import { describe, expect, it, vi } from "vitest";
import { scanPublicGitHubRepo } from "./scan-public-repo";

describe("scanPublicGitHubRepo", () => {
  it("runs metadata, download/extract, scanner, redaction, and cleanup", async () => {
    const cleanup = vi.fn().mockResolvedValue(undefined);
    const scanProjectImpl = vi.fn().mockResolvedValue(
      createScanResult([
        createFinding({
          category: "secrets",
          evidence: "SECRET=value",
          ruleId: "secrets/hardcoded"
        })
      ])
    );
    const getRulesImpl = vi.fn().mockReturnValue([createRule()]);

    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl: vi.fn().mockResolvedValue({
        cleanup,
        extractedPath: "C:/tmp/extracted",
        fileCount: 2,
        ok: true,
        tempId: "temp-id",
        totalBytes: 123
      }),
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata()),
      getRulesImpl,
      scanProjectImpl
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.repo.fullName).toBe("owner/repo");
      expect(result.extraction).toEqual({
        fileCount: 2,
        tempId: "temp-id",
        totalBytes: 123
      });
      expect(result.scan.findings[0]?.evidence).toBe("[REDACTED]");
    }
    expect(scanProjectImpl).toHaveBeenCalledWith("C:/tmp/extracted", {
      rules: expect.any(Array)
    });
    expect(getRulesImpl).toHaveBeenCalled();
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("returns invalid URL failures before network work", async () => {
    const fetchMetadataImpl = vi.fn();

    const result = await scanPublicGitHubRepo("https://example.com/owner/repo", {
      fetchMetadataImpl
    });

    expect(result).toEqual({
      ok: false,
      code: "INVALID_REPO_URL",
      message: "Only github.com repositories are supported."
    });
    expect(fetchMetadataImpl).not.toHaveBeenCalled();
  });

  it("returns metadata failures", async () => {
    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      fetchMetadataImpl: vi.fn().mockResolvedValue({
        error: "Repository not found",
        ok: false,
        status: 404
      })
    });

    expect(result).toEqual({
      ok: false,
      code: "METADATA_FETCH_FAILED",
      message: "Repository not found",
      status: 404
    });
  });

  it("continues scanning when repo size is within the configured limit", async () => {
    const downloadAndExtractImpl = vi.fn().mockResolvedValue({
      cleanup: vi.fn().mockResolvedValue(undefined),
      extractedPath: "C:/tmp/extracted",
      fileCount: 1,
      ok: true,
      tempId: "temp-id",
      totalBytes: 1
    });

    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl,
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata({ sizeKb: 100 })),
      limits: {
        maxRepoSizeKb: 100
      },
      scanProjectImpl: vi.fn().mockResolvedValue(createScanResult([]))
    });

    expect(result.ok).toBe(true);
    expect(downloadAndExtractImpl).toHaveBeenCalledTimes(1);
  });

  it("rejects repos over the configured size limit before download and extraction", async () => {
    const downloadAndExtractImpl = vi.fn();

    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl,
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata({ sizeKb: 101 })),
      limits: {
        maxRepoSizeKb: 100
      }
    });

    expect(result).toEqual({
      ok: false,
      code: "ARCHIVE_TOO_LARGE",
      message: "Repository is too large to scan. Maximum supported size is 100 KB."
    });
    expect(downloadAndExtractImpl).not.toHaveBeenCalled();
  });

  it("returns download and extraction failures", async () => {
    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl: vi.fn().mockResolvedValue({
        code: "PATH_TRAVERSAL_DETECTED",
        message: "Archive entry path is unsafe",
        ok: false
      }),
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata())
    });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("cleans up when scanner fails", async () => {
    const cleanup = vi.fn().mockResolvedValue(undefined);

    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl: vi.fn().mockResolvedValue({
        cleanup,
        extractedPath: "C:/tmp/extracted",
        fileCount: 1,
        ok: true,
        tempId: "temp-id",
        totalBytes: 1
      }),
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata()),
      scanProjectImpl: vi.fn().mockRejectedValue(new Error("scanner failed"))
    });

    expect(result).toEqual({
      ok: false,
      code: "SCAN_FAILED",
      message: "Repository scan failed"
    });
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("reports cleanup failure after a successful scan", async () => {
    const result = await scanPublicGitHubRepo("https://github.com/owner/repo", {
      downloadAndExtractImpl: vi.fn().mockResolvedValue({
        cleanup: vi.fn().mockRejectedValue(new Error("cleanup failed")),
        extractedPath: "C:/tmp/extracted",
        fileCount: 1,
        ok: true,
        tempId: "temp-id",
        totalBytes: 1
      }),
      fetchMetadataImpl: vi.fn().mockResolvedValue(createMetadata()),
      scanProjectImpl: vi.fn().mockResolvedValue(createScanResult([]))
    });

    expect(result).toEqual({
      ok: false,
      code: "CLEANUP_FAILED",
      message: "Repository cleanup failed"
    });
  });
});

function createMetadata(overrides?: Partial<ReturnType<typeof createMetadata>>) {
  return {
    archived: false,
    defaultBranch: "main",
    disabled: false,
    fullName: "owner/repo",
    htmlUrl: "https://github.com/owner/repo",
    isPrivate: false,
    ok: true as const,
    owner: "owner",
    repo: "repo",
    sizeKb: 1,
    tarballUrl: "https://api.github.com/repos/owner/repo/tarball",
    ...overrides
  };
}

function createRule(): Rule {
  return {
    category: "secrets",
    id: "secrets/hardcoded",
    scan: () => [],
    severity: "HIGH",
    title: "Hardcoded secret"
  };
}

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
