import { describe, expect, it, vi } from "vitest";
import { POST } from "./route";
import { scanPublicGitHubRepo } from "../../../lib/scan-public-repo";

vi.mock("../../../lib/scan-public-repo", () => ({
  scanPublicGitHubRepo: vi.fn()
}));

const scanPublicGitHubRepoMock = vi.mocked(scanPublicGitHubRepo);

describe("POST /api/scans", () => {
  it("rejects invalid JSON body", async () => {
    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: "{",
        method: "POST"
      })
    );

    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "INVALID_REQUEST_BODY",
      message: "Request body must be valid JSON."
    });
    expect(response.status).toBe(400);
  });

  it("rejects missing repoUrl", async () => {
    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({}),
        method: "POST"
      })
    );

    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "INVALID_REQUEST_BODY",
      message: "repoUrl is required."
    });
    expect(response.status).toBe(400);
  });

  it("returns scan success response", async () => {
    scanPublicGitHubRepoMock.mockResolvedValueOnce({
      extraction: {
        fileCount: 1,
        tempId: "temp-id",
        totalBytes: 10
      },
      ok: true,
      repo: {
        archived: false,
        defaultBranch: "main",
        fullName: "owner/repo",
        htmlUrl: "https://github.com/owner/repo",
        owner: "owner",
        repo: "repo"
      },
      scan: {
        findings: [],
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
          high: 0,
          info: 0,
          low: 0,
          medium: 0,
          riskLevel: "excellent",
          score: 100,
          totalFindings: 0
        }
      }
    });

    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({ repoUrl: "https://github.com/owner/repo" }),
        method: "POST"
      })
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      repo: {
        fullName: "owner/repo"
      }
    });
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledWith("https://github.com/owner/repo");
  });

  it("maps scan errors to safe responses", async () => {
    scanPublicGitHubRepoMock.mockResolvedValueOnce({
      code: "INVALID_REPO_URL",
      message: "Only github.com repositories are supported.",
      ok: false
    });

    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({ repoUrl: "https://example.com/owner/repo" }),
        method: "POST"
      })
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      code: "INVALID_REPO_URL",
      message: "Only github.com repositories are supported.",
      ok: false
    });
  });
});
