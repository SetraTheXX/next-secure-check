export type GitHubRepoParseResult =
  | { ok: true; owner: string; repo: string; normalizedUrl: string }
  | { ok: false; error: string };

const repoPathPattern = /^[A-Za-z0-9_.-]+$/;

export function parseGitHubRepoUrl(input: string): GitHubRepoParseResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, error: "URL is required." };
  }

  let normalizedInput = trimmed;
  if (/^github\.com\//i.test(normalizedInput)) {
    normalizedInput = `https://${normalizedInput}`;
  }

  if (!/^https?:\/\//i.test(normalizedInput)) {
    return { ok: false, error: "Only GitHub repo URLs are supported." };
  }

  let url: URL;
  try {
    url = new URL(normalizedInput);
  } catch {
    return { ok: false, error: "Invalid URL." };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, error: "Only HTTP(S) URLs are supported." };
  }

  if (url.hostname !== "github.com") {
    return { ok: false, error: "Only github.com repositories are supported." };
  }

  if (url.username || url.password) {
    return { ok: false, error: "Credentials are not allowed in repo URLs." };
  }

  if (url.search || url.hash) {
    return { ok: false, error: "Repository URL must not include query or fragment." };
  }

  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length !== 2) {
    return { ok: false, error: "URL must point to a repository root." };
  }

  const [owner, repo] = parts;
  if (!repoPathPattern.test(owner) || !repoPathPattern.test(repo)) {
    return { ok: false, error: "Owner and repo names must be URL-safe." };
  }

  if (repo.endsWith(".git")) {
    return { ok: false, error: "Repository URL must not end with .git." };
  }

  return {
    ok: true,
    owner,
    repo,
    normalizedUrl: `https://github.com/${owner}/${repo}`
  };
}
