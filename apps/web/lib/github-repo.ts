import { createGitHubRequestHeaders } from "./github-request";
import { fetchWithAbortTimeout, getGitHubTimeoutMs, OperationTimeoutError } from "./timeout";

export type GitHubRepoMetadataResult =
  | {
      ok: true;
      owner: string;
      repo: string;
      fullName: string;
      defaultBranch: string;
      isPrivate: false;
      archived: boolean;
      disabled: boolean;
      sizeKb: number;
      htmlUrl: string;
      tarballUrl: string;
    }
  | {
      ok: false;
      error: string;
      status?: number;
    };

export async function fetchPublicGitHubRepoMetadata(
  owner: string,
  repo: string,
  options?: { timeoutMs?: number }
): Promise<GitHubRepoMetadataResult> {
  const timeoutMs = options?.timeoutMs ?? getGitHubTimeoutMs();
  const url = `https://api.github.com/repos/${owner}/${repo}`;

  try {
    const response = await fetchWithAbortTimeout(
      url,
      {
        headers: createGitHubRequestHeaders()
      },
      timeoutMs
    );

    if (!response.ok) {
      if (response.status === 404) {
        return { ok: false, error: "Repository not found", status: 404 };
      }

      if (response.status === 403 || response.status === 429) {
        return {
          ok: false,
          error: "GitHub API rate limit exceeded",
          status: response.status
        };
      }

      return { ok: false, error: "Repository metadata fetch failed", status: response.status };
    }

    const data = (await response.json()) as {
      full_name: string;
      default_branch: string;
      private: boolean;
      archived: boolean;
      disabled: boolean;
      size: number;
      html_url: string;
      tarball_url: string;
    };

    if (data.private) {
      return {
        ok: false,
        error: "Private repositories are not supported",
        status: response.status
      };
    }

    if (data.disabled) {
      return { ok: false, error: "Repository is disabled", status: response.status };
    }

    return {
      ok: true,
      owner,
      repo,
      fullName: data.full_name,
      defaultBranch: data.default_branch,
      isPrivate: false,
      archived: data.archived,
      disabled: data.disabled,
      sizeKb: data.size,
      htmlUrl: data.html_url,
      tarballUrl: createGitHubTarballUrl(owner, repo, data.default_branch)
    };
  } catch (error) {
    if (error instanceof OperationTimeoutError) {
      return { ok: false, error: "Request timed out" };
    }

    if (error instanceof Error) {
      return { ok: false, error: "Network error" };
    }

    return { ok: false, error: "Unknown error" };
  }
}

function createGitHubTarballUrl(owner: string, repo: string, ref: string): string {
  return `https://api.github.com/repos/${owner}/${repo}/tarball/${encodeURIComponent(ref)}`;
}
