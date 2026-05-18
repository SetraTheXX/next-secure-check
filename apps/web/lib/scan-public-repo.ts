import { readdir } from "node:fs/promises";
import path from "node:path";
import { scanProject, type ScanResult } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import type { ArchiveErrorCode } from "./archive-types";
import { fetchPublicGitHubRepoMetadata } from "./github-repo";
import { parseGitHubRepoUrl } from "./github-url";
import { redactScanResult, type RedactedScanResult } from "./redact-findings";
import { cleanupOrphanExtractionDirs, downloadAndExtractGitHubTarball } from "./safe-extract";
import { DEFAULT_SCAN_LIMITS, type ScanLimits } from "./scan-limits";

export type ScanPublicGitHubRepoOptions = {
  excludePaths?: string[];
  tempRoot?: string;
  timeoutMs?: number;
  limits?: Partial<ScanLimits>;
  scanProjectImpl?: typeof scanProject;
  getRulesImpl?: typeof getBuiltInRules;
  fetchMetadataImpl?: typeof fetchPublicGitHubRepoMetadata;
  downloadAndExtractImpl?: typeof downloadAndExtractGitHubTarball;
  cleanupOrphansImpl?: typeof cleanupOrphanExtractionDirs;
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

  await cleanupOrphansQuietly(options?.cleanupOrphansImpl ?? cleanupOrphanExtractionDirs, {
    tempRoot: options?.tempRoot
  });

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

  const limits = { ...DEFAULT_SCAN_LIMITS, ...options?.limits };
  if (metadata.sizeKb > limits.maxRepoSizeKb) {
    return {
      ok: false,
      code: "ARCHIVE_TOO_LARGE",
      message: `Repository is too large to scan. Maximum supported size is ${limits.maxRepoSizeKb} KB.`
    };
  }

  const downloadAndExtract = options?.downloadAndExtractImpl ?? downloadAndExtractGitHubTarball;
  const extraction = await downloadAndExtract(metadata.tarballUrl, {
    limits,
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
    const scanRoot = await resolveScanRoot(extraction.extractedPath);
    scan = await runScan(scanRoot, {
      excludePaths: options?.excludePaths,
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

export async function resolveScanRoot(extractedPath: string): Promise<string> {
  try {
    const entries = await readdir(extractedPath, { withFileTypes: true });
    const directories = entries.filter((entry) => entry.isDirectory());
    const files = entries.filter((entry) => entry.isFile());

    if (files.length === 0 && directories.length === 1) {
      return path.join(extractedPath, directories[0].name);
    }
  } catch {
    return extractedPath;
  }

  return extractedPath;
}

async function cleanupQuietly(cleanup: () => Promise<void>): Promise<void> {
  try {
    await cleanup();
  } catch {
    // The public response must not expose cleanup internals or stack traces.
  }
}

async function cleanupOrphansQuietly(
  cleanupOrphans: typeof cleanupOrphanExtractionDirs,
  options: Parameters<typeof cleanupOrphanExtractionDirs>[0]
): Promise<void> {
  try {
    await cleanupOrphans(options);
  } catch {
    // Orphan cleanup is opportunistic and must never mask the scan result.
  }
}
