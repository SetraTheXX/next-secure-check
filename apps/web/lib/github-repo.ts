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

const DEFAULT_TIMEOUT_MS = 8000;

export async function fetchPublicGitHubRepoMetadata(
  owner: string,
  repo: string,
  options?: { timeoutMs?: number }
): Promise<GitHubRepoMetadataResult> {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const url = `https://api.github.com/repos/${owner}/${repo}`;

  try {
    const response = (await Promise.race([
      fetch(url, {
        headers: {
          Accept: "application/vnd.github+json"
        }
      }),
      new Promise<Response>((_, reject) => {
        const timer = setTimeout(() => {
          clearTimeout(timer);
          const error = new Error("timeout");
          error.name = "TimeoutError";
          reject(error);
        }, timeoutMs);
      })
    ])) as Response;

    if (!response.ok) {
      if (response.status === 404) {
        return { ok: false, error: "Repository not found", status: 404 };
      }

      if (response.status === 403) {
        return {
          ok: false,
          error: "Private repositories are not supported",
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
      tarballUrl: data.tarball_url
    };
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      return { ok: false, error: "Request timed out" };
    }

    if (error instanceof Error) {
      return { ok: false, error: "Network error" };
    }

    return { ok: false, error: "Unknown error" };
  }
}
