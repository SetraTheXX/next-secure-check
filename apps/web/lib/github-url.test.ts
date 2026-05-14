import { describe, expect, it } from "vitest";
import { parseGitHubRepoUrl } from "./github-url";

describe("parseGitHubRepoUrl", () => {
  it("accepts https github urls", () => {
    const result = parseGitHubRepoUrl("https://github.com/vercel/next.js");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.owner).toBe("vercel");
      expect(result.repo).toBe("next.js");
      expect(result.normalizedUrl).toBe("https://github.com/vercel/next.js");
    }
  });

  it("accepts github.com without scheme", () => {
    const result = parseGitHubRepoUrl("github.com/owner/repo");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.normalizedUrl).toBe("https://github.com/owner/repo");
    }
  });

  it("rejects non-github hosts", () => {
    const result = parseGitHubRepoUrl("gitlab.com/owner/repo");
    expect(result.ok).toBe(false);
  });

  it("rejects missing repo", () => {
    const result = parseGitHubRepoUrl("https://github.com/owner");
    expect(result.ok).toBe(false);
  });

  it("rejects subpaths", () => {
    const result = parseGitHubRepoUrl("https://github.com/owner/repo/tree/main");
    expect(result.ok).toBe(false);
  });

  it("rejects issues path", () => {
    const result = parseGitHubRepoUrl("https://github.com/owner/repo/issues");
    expect(result.ok).toBe(false);
  });

  it("rejects .git suffix", () => {
    const result = parseGitHubRepoUrl("https://github.com/owner/repo.git");
    expect(result.ok).toBe(false);
  });

  it("rejects javascript urls", () => {
    const result = parseGitHubRepoUrl("javascript:alert(1)");
    expect(result.ok).toBe(false);
  });

  it("rejects empty input", () => {
    const result = parseGitHubRepoUrl("   ");
    expect(result.ok).toBe(false);
  });

  it("rejects owner/repo without host", () => {
    const result = parseGitHubRepoUrl("owner/repo");
    expect(result.ok).toBe(false);
  });
});
