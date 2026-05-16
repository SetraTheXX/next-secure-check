import { scanProject, type ScanResult } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import type { ArchiveErrorCode } from "./archive-types";
import { fetchPublicGitHubRepoMetadata } from "./github-repo";
import { parseGitHubRepoUrl } from "./github-url";
import { redactScanResult, type RedactedScanResult } from "./redact-findings";
import { downloadAndExtractGitHubTarball } from "./safe-extract";
import type { ScanLimits } from "./scan-limits";

export type ScanPublicGitHubRepoOptions = {
  tempRoot?: string;
  timeoutMs?: number;
  limits?: Partial<ScanLimits>;
  scanProjectImpl?: typeof scanProject;
  getRulesImpl?: typeof getBuiltInRules;
  fetchMetadataImpl?: typeof fetchPublicGitHubRepoMetadata;
  downloadAndExtractImpl?: typeof downloadAndExtractGitHubTarball;
};

export type ScanPublicGitHubRepoResult =
  | {
      ok: true;
      repo: {
        owner: string;
        repo: string;
        fullName: string;
        htmlUrl: string;
        defaultBranch: string;
        archived: boolean;
      };
      extraction: {
        fileCount: number;
        totalBytes: number;
        tempId: string;
      };
      scan: RedactedScanResult;
    }
  | {
      ok: false;
      code: ScanPublicGitHubRepoErrorCode;
      message: string;
      status?: number;
    };

export type ScanPublicGitHubRepoErrorCode =
  | "INVALID_REPO_URL"
  | "METADATA_FETCH_FAILED"
  | ArchiveErrorCode
  | "SCAN_FAILED"
  | "CLEANUP_FAILED";

export async function scanPublicGitHubRepo(
  repoUrl: string,
  options?: ScanPublicGitHubRepoOptions
): Promise<ScanPublicGitHubRepoResult> {
  const parsedUrl = parseGitHubRepoUrl(repoUrl);
  if (!parsedUrl.ok) {
    return {
      ok: false,
      code: "INVALID_REPO_URL",
      message: parsedUrl.error
    };
  }

  const fetchMetadata = options?.fetchMetadataImpl ?? fetchPublicGitHubRepoMetadata;
  const metadata = await fetchMetadata(parsedUrl.owner, parsedUrl.repo, {
    timeoutMs: options?.timeoutMs
  });

  if (!metadata.ok) {
    return {
      ok: false,
      code: "METADATA_FETCH_FAILED",
      message: metadata.error,
      status: metadata.status
    };
  }

  const downloadAndExtract = options?.downloadAndExtractImpl ?? downloadAndExtractGitHubTarball;
  const extraction = await downloadAndExtract(metadata.tarballUrl, {
    limits: options?.limits,
    tempRoot: options?.tempRoot,
    timeoutMs: options?.timeoutMs
  });

  if (!extraction.ok) {
    return extraction;
  }

  let scan: ScanResult;
  try {
    const runScan = options?.scanProjectImpl ?? scanProject;
    const getRules = options?.getRulesImpl ?? getBuiltInRules;
    scan = await runScan(extraction.extractedPath, {
      rules: getRules()
    });
  } catch {
    await cleanupQuietly(extraction.cleanup);
    return {
      ok: false,
      code: "SCAN_FAILED",
      message: "Repository scan failed"
    };
  }

  try {
    await extraction.cleanup();
  } catch {
    return {
      ok: false,
      code: "CLEANUP_FAILED",
      message: "Repository cleanup failed"
    };
  }

  return {
    ok: true,
    repo: {
      owner: metadata.owner,
      repo: metadata.repo,
      fullName: metadata.fullName,
      htmlUrl: metadata.htmlUrl,
      defaultBranch: metadata.defaultBranch,
      archived: metadata.archived
    },
    extraction: {
      fileCount: extraction.fileCount,
      totalBytes: extraction.totalBytes,
      tempId: extraction.tempId
    },
    scan: redactScanResult(scan)
  };
}

async function cleanupQuietly(cleanup: () => Promise<void>): Promise<void> {
  try {
    await cleanup();
  } catch {
    // The public response must not expose cleanup internals or stack traces.
  }
}
