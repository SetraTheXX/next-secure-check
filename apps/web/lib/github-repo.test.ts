import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchPublicGitHubRepoMetadata } from "./github-repo";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("fetchPublicGitHubRepoMetadata", () => {
  it("handles public repo metadata success", async () => {
    const mockJson = {
      full_name: "vercel/next.js",
      default_branch: "main",
      private: false,
      archived: false,
      disabled: false,
      size: 123,
      html_url: "https://github.com/vercel/next.js",
      tarball_url: "https://api.github.com/repos/vercel/next.js/tarball"
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockJson
    });
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("vercel", "next.js");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.fullName).toBe("vercel/next.js");
      expect(result.archived).toBe(false);
      expect(result.disabled).toBe(false);
      expect(result.sizeKb).toBe(123);
    }
  });

  it("handles 404 not found", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("owner", "missing");
    expect(result).toEqual({ ok: false, error: "Repository not found", status: 404 });
  });

  it("rejects private repo", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 403
    });
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("owner", "private");
    expect(result).toEqual({
      ok: false,
      error: "Private repositories are not supported",
      status: 403
    });
  });

  it("rejects disabled repo", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        full_name: "owner/disabled",
        default_branch: "main",
        private: false,
        archived: false,
        disabled: true,
        size: 1,
        html_url: "https://github.com/owner/disabled",
        tarball_url: "https://api.github.com/repos/owner/disabled/tarball"
      })
    });
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("owner", "disabled");
    expect(result).toEqual({ ok: false, error: "Repository is disabled", status: 200 });
  });

  it("returns archived repo metadata", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        full_name: "owner/archived",
        default_branch: "main",
        private: false,
        archived: true,
        disabled: false,
        size: 5,
        html_url: "https://github.com/owner/archived",
        tarball_url: "https://api.github.com/repos/owner/archived/tarball"
      })
    });
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("owner", "archived");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.archived).toBe(true);
    }
  });

  it("handles timeout", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise(() => {})
    );
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const promise = fetchPublicGitHubRepoMetadata("owner", "slow", { timeoutMs: 5 });
    vi.advanceTimersByTime(10);

    const result = await promise;
    expect(result).toEqual({ ok: false, error: "Request timed out" });
    vi.useRealTimers();
  });

  it("handles network errors", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("network down"));
    vi.stubGlobal("fetch", fetchMock as typeof fetch);

    const result = await fetchPublicGitHubRepoMetadata("owner", "repo");
    expect(result).toEqual({ ok: false, error: "Network error" });
  });
});
