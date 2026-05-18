import { createWriteStream } from "node:fs";
import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { extract, type Headers } from "tar-stream";
import type { ArchiveErrorCode, TarballExtractResult } from "./archive-types";
import { downloadGitHubTarball } from "./github-archive";
import { DEFAULT_SCAN_LIMITS, type ScanLimits } from "./scan-limits";
import { isSafeArchiveEntryPath, normalizeArchiveEntryPath } from "./safe-path";

type ExtractTarballSafelyOptions = {
  tempRoot?: string;
  limits?: Partial<ScanLimits>;
};

type DownloadAndExtractOptions = {
  tempRoot?: string;
  timeoutMs?: number;
  limits?: Partial<ScanLimits>;
};

type CleanupOrphanExtractionDirsOptions = {
  maxAgeMs?: number;
  nowMs?: number;
  tempRoot?: string;
};

type ExtractionState = {
  fileCount: number;
  totalBytes: number;
  seenPaths: Set<string>;
};

class ArchiveExtractionError extends Error {
  constructor(
    readonly code: ArchiveErrorCode,
    message: string
  ) {
    super(message);
    this.name = "ArchiveExtractionError";
  }
}

export const EXTRACTION_DIR_PREFIX = "next-secure-check-";
export const ORPHAN_EXTRACTION_MAX_AGE_MS = 30 * 60 * 1000;

const EXTRACTION_DIR_NAME_PATTERN =
  /^next-secure-check-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-(?:[A-Za-z0-9_-]+)?$/i;

export async function cleanupOrphanExtractionDirs(
  options?: CleanupOrphanExtractionDirsOptions
): Promise<void> {
  const tempRoot = options?.tempRoot ?? tmpdir();
  const maxAgeMs = options?.maxAgeMs ?? ORPHAN_EXTRACTION_MAX_AGE_MS;
  const nowMs = options?.nowMs ?? Date.now();

  try {
    const entries = await readdir(tempRoot, { withFileTypes: true });
    await Promise.all(
      entries.map(async (entry) => {
        if (!entry.isDirectory() || !isManagedExtractionDirName(entry.name)) {
          return;
        }

        const entryPath = path.join(tempRoot, entry.name);
        try {
          const entryStat = await stat(entryPath);
          if (nowMs - entryStat.mtimeMs < maxAgeMs) {
            return;
          }

          await rm(entryPath, {
            force: true,
            recursive: true
          });
        } catch {
          // Orphan cleanup is best-effort and must never fail a user scan.
        }
      })
    );
  } catch {
    return;
  }
}

export async function extractTarballSafely(
  archiveBytes: Uint8Array,
  options?: ExtractTarballSafelyOptions
): Promise<TarballExtractResult> {
  const limits = { ...DEFAULT_SCAN_LIMITS, ...options?.limits };
  const tempRoot = options?.tempRoot ?? tmpdir();
  let extractedPath: string | undefined;

  try {
    await mkdir(tempRoot, { recursive: true });
    extractedPath = await createExtractionDirectory(tempRoot);
    const state: ExtractionState = {
      fileCount: 0,
      totalBytes: 0,
      seenPaths: new Set()
    };

    await extractArchiveBytes(archiveBytes, extractedPath, limits, state);

    const cleanup = createCleanup(extractedPath);
    return {
      ok: true,
      extractedPath,
      fileCount: state.fileCount,
      totalBytes: state.totalBytes,
      cleanup,
      tempId: path.basename(extractedPath)
    };
  } catch (error) {
    if (extractedPath) {
      await cleanupAfterFailure(extractedPath);
    }

    if (error instanceof ArchiveExtractionError) {
      return {
        ok: false,
        code: error.code,
        message: error.message
      };
    }

    return {
      ok: false,
      code: "EXTRACTION_FAILED",
      message: "Tarball extraction failed"
    };
  }
}

export async function downloadAndExtractGitHubTarball(
  tarballUrl: string,
  options?: DownloadAndExtractOptions
): Promise<TarballExtractResult> {
  const downloadResult = await downloadGitHubTarball(tarballUrl, {
    timeoutMs: options?.timeoutMs,
    maxDownloadBytes: options?.limits?.maxArchiveDownloadBytes
  });

  if (!downloadResult.ok) {
    return {
      ok: false,
      code: downloadResult.code,
      message: downloadResult.message,
      status: downloadResult.status
    };
  }

  return extractTarballSafely(downloadResult.bytes, {
    tempRoot: options?.tempRoot,
    limits: options?.limits
  });
}

async function createExtractionDirectory(tempRoot: string): Promise<string> {
  const prefix = path.join(tempRoot, `${EXTRACTION_DIR_PREFIX}${randomUUID()}-`);
  try {
    await mkdir(prefix, { recursive: false });
    return prefix;
  } catch {
    const { mkdtemp } = await import("node:fs/promises");
    return mkdtemp(prefix);
  }
}

function isManagedExtractionDirName(name: string): boolean {
  return name.startsWith(EXTRACTION_DIR_PREFIX) && EXTRACTION_DIR_NAME_PATTERN.test(name);
}

async function extractArchiveBytes(
  archiveBytes: Uint8Array,
  extractedRoot: string,
  limits: ScanLimits,
  state: ExtractionState
): Promise<void> {
  const tarExtract = extract();
  const pump = pipeline(Readable.from([Buffer.from(archiveBytes)]), createGunzip(), tarExtract);

  try {
    for await (const entry of tarExtract) {
      await handleEntry(entry.header, entry, extractedRoot, limits, state);
    }

    await pump;
  } catch (error) {
    tarExtract.destroy();
    await pump.catch(() => undefined);

    if (error instanceof ArchiveExtractionError) {
      throw error;
    }

    throw new ArchiveExtractionError("EXTRACTION_FAILED", "Tarball extraction failed");
  }
}

async function handleEntry(
  header: Headers,
  entry: Readable,
  extractedRoot: string,
  limits: ScanLimits,
  state: ExtractionState
): Promise<void> {
  const safeRelativePath = resolveSafeRelativePath(header.name);
  if (!safeRelativePath) {
    entry.resume();
    throw new ArchiveExtractionError(
      "PATH_TRAVERSAL_DETECTED",
      "Archive entry path is unsafe"
    );
  }

  if (state.seenPaths.has(safeRelativePath)) {
    entry.resume();
    throw new ArchiveExtractionError(
      "EXTRACTION_FAILED",
      "Archive contains duplicate entry paths"
    );
  }
  state.seenPaths.add(safeRelativePath);

  const finalPath = resolveInsideRoot(extractedRoot, safeRelativePath);
  if (!finalPath) {
    entry.resume();
    throw new ArchiveExtractionError(
      "PATH_TRAVERSAL_DETECTED",
      "Archive entry resolves outside extraction root"
    );
  }

  const entryType = header.type ?? "file";
  if (entryType === "symlink" || entryType === "link") {
    entry.resume();
    throw new ArchiveExtractionError("SYMLINK_NOT_ALLOWED", "Archive links are not allowed");
  }

  if (entryType === "directory") {
    entry.resume();
    await mkdir(finalPath, { recursive: true, mode: 0o755 });
    return;
  }

  if (entryType !== "file") {
    entry.resume();
    throw new ArchiveExtractionError(
      "EXTRACTION_FAILED",
      "Archive contains unsupported entry type"
    );
  }

  state.fileCount += 1;
  if (state.fileCount > limits.maxFiles) {
    entry.resume();
    throw new ArchiveExtractionError(
      "FILE_COUNT_LIMIT_EXCEEDED",
      "Archive file count limit exceeded"
    );
  }

  if (header.size !== undefined && header.size > limits.maxSingleFileBytes) {
    entry.resume();
    throw new ArchiveExtractionError(
      "SINGLE_FILE_LIMIT_EXCEEDED",
      "Archive file size limit exceeded"
    );
  }

  await mkdir(path.dirname(finalPath), { recursive: true, mode: 0o755 });
  await writeFileEntry(entry, finalPath, limits, state);
}

function resolveSafeRelativePath(entryPath: string): string | undefined {
  if (!isSafeArchiveEntryPath(entryPath)) {
    return undefined;
  }

  return normalizeArchiveEntryPath(entryPath) ?? undefined;
}

function resolveInsideRoot(extractedRoot: string, relativePath: string): string | undefined {
  const root = path.resolve(extractedRoot);
  const finalPath = path.resolve(root, relativePath);
  const relativeFromRoot = path.relative(root, finalPath);

  if (
    relativeFromRoot === "" ||
    relativeFromRoot.startsWith("..") ||
    path.isAbsolute(relativeFromRoot)
  ) {
    return undefined;
  }

  return finalPath;
}

async function writeFileEntry(
  entry: Readable,
  finalPath: string,
  limits: ScanLimits,
  state: ExtractionState
): Promise<void> {
  const output = createWriteStream(finalPath, {
    flags: "wx",
    mode: 0o600
  });

  let fileBytes = 0;

  try {
    for await (const chunk of entry) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      fileBytes += bytes.byteLength;
      state.totalBytes += bytes.byteLength;

      if (fileBytes > limits.maxSingleFileBytes) {
        throw new ArchiveExtractionError(
          "SINGLE_FILE_LIMIT_EXCEEDED",
          "Archive file size limit exceeded"
        );
      }

      if (state.totalBytes > limits.maxExtractedBytes) {
        throw new ArchiveExtractionError(
          "EXTRACTED_SIZE_LIMIT_EXCEEDED",
          "Archive extracted size limit exceeded"
        );
      }

      if (!output.write(bytes)) {
        await onceDrain(output);
      }
    }
  } catch (error) {
    entry.destroy();
    output.destroy();
    throw error;
  }

  await closeWriteStream(output);
}

function onceDrain(output: NodeJS.WritableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    output.once("drain", resolve);
    output.once("error", reject);
  });
}

function closeWriteStream(output: NodeJS.WritableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    output.end(() => resolve());
    output.once("error", reject);
  });
}

function createCleanup(extractedPath: string): () => Promise<void> {
  let cleaned = false;

  return async () => {
    if (cleaned) {
      return;
    }

    cleaned = true;
    await rm(extractedPath, {
      force: true,
      recursive: true
    });
  };
}

async function cleanupAfterFailure(extractedPath: string): Promise<void> {
  try {
    await rm(extractedPath, {
      force: true,
      recursive: true
    });
  } catch {
    // Preserve the original extraction error; cleanup failure must not mask it.
  }
}
