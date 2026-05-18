const USER_AGENT = "next-secure-check";

export function createGitHubRequestHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": USER_AGENT
  };
  const token = process.env.GITHUB_TOKEN?.trim();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}
