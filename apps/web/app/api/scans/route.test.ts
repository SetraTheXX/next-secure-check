import { beforeEach, describe, expect, it, vi } from "vitest";
import { POST } from "./route";
import { resetScanAbuseGuardForTests } from "../../../lib/scan-abuse-guard";
import { scanPublicGitHubRepo } from "../../../lib/scan-public-repo";

vi.mock("../../../lib/scan-public-repo", () => ({
  scanPublicGitHubRepo: vi.fn()
}));

const scanPublicGitHubRepoMock = vi.mocked(scanPublicGitHubRepo);

describe("POST /api/scans", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    resetScanAbuseGuardForTests();
    scanPublicGitHubRepoMock.mockReset();
  });

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
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
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
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
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

  it("passes valid exclude paths to the public repo scanner", async () => {
    scanPublicGitHubRepoMock.mockResolvedValueOnce(createSuccessResult());

    const excludePaths = [
      "**/*.test.ts",
      "**/*.test.tsx",
      "**/*.spec.ts",
      "**/*.spec.tsx",
      "examples/**"
    ];
    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({
          excludePaths,
          repoUrl: "https://github.com/owner/repo"
        }),
        method: "POST"
      })
    );

    expect(response.status).toBe(200);
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledWith("https://github.com/owner/repo", {
      excludePaths
    });
  });

  it("rejects invalid exclude paths before starting a scan", async () => {
    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({
          excludePaths: ["examples/**", "../secret"],
          repoUrl: "https://github.com/owner/repo"
        }),
        method: "POST"
      })
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "INVALID_REQUEST_BODY",
      message: "excludePaths must be an array of safe relative glob patterns."
    });
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
  });

  it("rejects overly long exclude path lists before starting a scan", async () => {
    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({
          excludePaths: Array.from({ length: 11 }, (_, index) => `path-${index}/**`),
          repoUrl: "https://github.com/owner/repo"
        }),
        method: "POST"
      })
    );

    expect(response.status).toBe(400);
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
  });

  it("allows scan requests below the per-IP rate limit", async () => {
    scanPublicGitHubRepoMock.mockResolvedValue(createSuccessResult());

    const responses = [
      await POST(createScanRequest({ ip: "203.0.113.1" })),
      await POST(createScanRequest({ ip: "203.0.113.1" })),
      await POST(createScanRequest({ ip: "203.0.113.1" }))
    ];

    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledTimes(3);
  });

  it("rate limits scan requests per IP before starting a scan", async () => {
    scanPublicGitHubRepoMock.mockResolvedValue(createSuccessResult());

    await POST(createScanRequest({ ip: "203.0.113.2" }));
    await POST(createScanRequest({ ip: "203.0.113.2" }));
    await POST(createScanRequest({ ip: "203.0.113.2" }));
    const response = await POST(createScanRequest({ ip: "203.0.113.2" }));

    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "SCAN_RATE_LIMITED",
      message: "Too many scan requests. Please wait before starting another scan."
    });
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledTimes(3);
  });

  it("preserves 429 rate limit responses when the distributed scan guard is configured", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(createUpstashResponse([{ result: 4 }, { result: 1 }]))
    );

    const response = await POST(createScanRequest({ ip: "203.0.113.10" }));

    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "SCAN_RATE_LIMITED",
      message: "Too many scan requests. Please wait before starting another scan."
    });
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
  });

  it("rejects scans over the concurrent scan limit before starting another scan", async () => {
    const firstScan = createDeferredScan();
    const secondScan = createDeferredScan();
    scanPublicGitHubRepoMock
      .mockReturnValueOnce(firstScan.promise)
      .mockReturnValueOnce(secondScan.promise);

    const firstResponse = POST(createScanRequest({ ip: "203.0.113.3" }));
    const secondResponse = POST(createScanRequest({ ip: "203.0.113.4" }));
    await Promise.resolve();

    const response = await POST(createScanRequest({ ip: "203.0.113.5" }));

    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
      message: "Too many scans are running. Please try again shortly."
    });
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledTimes(2);

    firstScan.resolve(createSuccessResult());
    secondScan.resolve(createSuccessResult());
    await Promise.all([firstResponse, secondResponse]);
  });

  it("preserves 429 concurrency responses when the distributed scan guard is configured", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(createUpstashResponse([{ result: 1 }, { result: 1 }]))
        .mockResolvedValueOnce(createUpstashResponse([{ result: 3 }, { result: 1 }]))
        .mockResolvedValueOnce(createUpstashResponse([{ result: 2 }]))
    );

    const response = await POST(createScanRequest({ ip: "203.0.113.11" }));

    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
      message: "Too many scans are running. Please try again shortly."
    });
    expect(scanPublicGitHubRepoMock).not.toHaveBeenCalled();
  });

  it("releases the active scan counter after successful scans", async () => {
    const firstScan = createDeferredScan();
    scanPublicGitHubRepoMock.mockReturnValueOnce(firstScan.promise).mockResolvedValue(createSuccessResult());

    const firstResponse = POST(createScanRequest({ ip: "203.0.113.6" }));
    await Promise.resolve();
    firstScan.resolve(createSuccessResult());
    await firstResponse;

    const response = await POST(createScanRequest({ ip: "203.0.113.7" }));

    expect(response.status).toBe(200);
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledTimes(2);
  });

  it("releases the active scan counter after failed scans", async () => {
    const firstScan = createDeferredScan();
    scanPublicGitHubRepoMock.mockReturnValueOnce(firstScan.promise).mockResolvedValue(createSuccessResult());

    const firstResponse = POST(createScanRequest({ ip: "203.0.113.8" }));
    await Promise.resolve();
    firstScan.reject(new Error("scan failed"));
    await firstResponse;

    const response = await POST(createScanRequest({ ip: "203.0.113.9" }));

    expect(response.status).toBe(200);
    expect(scanPublicGitHubRepoMock).toHaveBeenCalledTimes(2);
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

  it("returns safe response for unexpected scan exceptions", async () => {
    scanPublicGitHubRepoMock.mockRejectedValueOnce(new Error("stack trace with secret"));

    const response = await POST(
      new Request("http://localhost/api/scans", {
        body: JSON.stringify({ repoUrl: "https://github.com/owner/repo" }),
        method: "POST"
      })
    );

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({
      code: "SCAN_FAILED",
      message: "Scan failed unexpectedly.",
      ok: false
    });
  });
});

function createScanRequest(options?: { ip?: string }): Request {
  const headers = new Headers({
    "content-type": "application/json"
  });
  if (options?.ip) {
    headers.set("x-forwarded-for", options.ip);
  }

  return new Request("http://localhost/api/scans", {
    body: JSON.stringify({ repoUrl: "https://github.com/owner/repo" }),
    headers,
    method: "POST"
  });
}

function createDeferredScan() {
  let resolve!: (value: Awaited<ReturnType<typeof scanPublicGitHubRepo>>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<Awaited<ReturnType<typeof scanPublicGitHubRepo>>>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return {
    promise,
    reject,
    resolve
  };
}

function createSuccessResult(): Awaited<ReturnType<typeof scanPublicGitHubRepo>> {
  return {
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
  };
}

function createUpstashResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    headers: {
      "content-type": "application/json"
    },
    status: 200
  });
}
