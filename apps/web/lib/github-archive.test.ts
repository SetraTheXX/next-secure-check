import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadGitHubTarball } from "./github-archive";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("downloadGitHubTarball", () => {
  it("downloads a GitHub tarball", async () => {
    const bytes = new Uint8Array([31, 139, 8]);
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: bytes,
        contentType: "application/x-gzip",
        status: 200
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/vercel/next.js/tarball"
    );
    const headers = new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers);

    expect(headers.get("Accept")).toBe("application/vnd.github+json");
    expect(headers.get("User-Agent")).toBe("next-secure-check");
    expect(headers.has("Authorization")).toBe(false);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.bytes).toEqual(bytes);
      expect(result.sizeBytes).toBe(3);
      expect(result.contentType).toBe("application/x-gzip");
      expect(result.sourceUrl).toBe("https://api.github.com/repos/vercel/next.js/tarball");
    }
  });

  it("uses an optional GitHub token without exposing it in download errors", async () => {
    vi.stubEnv("GITHUB_TOKEN", "github-secret-token");
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: new Uint8Array(),
        contentType: "application/json",
        ok: false,
        status: 403
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball"
    );
    const headers = new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers);

    expect(headers.get("Authorization")).toBe("Bearer github-secret-token");
    expect(headers.get("User-Agent")).toBe("next-secure-check");
    expect(JSON.stringify(result)).not.toContain("github-secret-token");
  });

  it("rejects non-GitHub tarball URLs", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball("https://example.com/archive.tar.gz");

    expect(result).toEqual({
      ok: false,
      code: "INVALID_TARBALL_URL",
      message: "Invalid GitHub tarball URL"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects oversized tarballs from content length", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: new Uint8Array([1]),
        contentLength: "4",
        contentType: "application/x-gzip",
        status: 200
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { maxDownloadBytes: 3 }
    );

    expect(result).toEqual({
      ok: false,
      code: "ARCHIVE_TOO_LARGE",
      message: "GitHub tarball is too large",
      status: 200
    });
  });

  it("rejects oversized tarballs after reading bytes", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: new Uint8Array([1, 2, 3, 4]),
        contentType: "application/x-gzip",
        status: 200
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { maxDownloadBytes: 3 }
    );

    expect(result).toEqual({
      ok: false,
      code: "ARCHIVE_TOO_LARGE",
      message: "GitHub tarball is too large",
      status: 200
    });
  });

  it("rejects unsupported content types", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: new Uint8Array([1]),
        contentType: "text/html",
        status: 200
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball"
    );

    expect(result).toEqual({
      ok: false,
      code: "UNSUPPORTED_CONTENT_TYPE",
      message: "GitHub tarball response has an unsupported content type",
      status: 200
    });
  });

  it("maps rate limits", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      createResponse({
        body: new Uint8Array(),
        contentType: "application/json",
        ok: false,
        status: 403
      })
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball"
    );

    expect(result).toEqual({
      ok: false,
      code: "RATE_LIMITED",
      message: "GitHub tarball download was rate limited",
      status: 403
    });
  });

  it("handles timeout", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(() => new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const promise = downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { timeoutMs: 5 }
    );
    vi.advanceTimersByTime(10);

    await expect(promise).resolves.toEqual({
      ok: false,
      code: "DOWNLOAD_TIMEOUT",
      message: "GitHub tarball download timed out"
    });
  });

  it("handles network errors", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("network down"));
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await downloadGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball"
    );

    expect(result).toEqual({
      ok: false,
      code: "NETWORK_ERROR",
      message: "GitHub tarball download failed"
    });
  });
});

function createResponse(options: {
  body: Uint8Array;
  contentLength?: string;
  contentType: string;
  ok?: boolean;
  status: number;
}): Response {
  return {
    arrayBuffer: async () => options.body.buffer,
    body: undefined,
    headers: new Headers({
      ...(options.contentLength ? { "content-length": options.contentLength } : {}),
      "content-type": options.contentType
    }),
    ok: options.ok ?? (options.status >= 200 && options.status < 300),
    status: options.status
  } as Response;
}
