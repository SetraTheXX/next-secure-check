import { mkdir, mkdtemp, readFile, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pack, type Headers } from "tar-stream";
import {
  cleanupOrphanExtractionDirs,
  downloadAndExtractGitHubTarball,
  extractTarballSafely,
  ORPHAN_EXTRACTION_MAX_AGE_MS
} from "./safe-extract";

let tempRoot: string;

beforeEach(async () => {
  tempRoot = await mkdtemp(path.join(tmpdir(), "next-secure-check-test-"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(tempRoot, { force: true, recursive: true });
});

describe("extractTarballSafely", () => {
  it("extracts a simple tar.gz with one file", async () => {
    const archive = await createTarGz([{ name: "README.md", data: "hello" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.fileCount).toBe(1);
    expect(result.totalBytes).toBe(5);
    await expect(readFile(path.join(result.extractedPath, "README.md"), "utf8")).resolves.toBe(
      "hello"
    );
    await result.cleanup();
  });

  it("extracts nested directories and files", async () => {
    const archive = await createTarGz([
      { name: "src", type: "directory" },
      { name: "src/index.ts", data: "export {};" }
    ]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (result.ok) {
      await expect(readFile(path.join(result.extractedPath, "src/index.ts"), "utf8")).resolves.toBe(
        "export {};"
      );
      await result.cleanup();
    }
  });

  it("handles directory entries safely", async () => {
    const archive = await createTarGz([{ name: "src/utils", type: "directory" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (result.ok) {
      await expect(stat(path.join(result.extractedPath, "src/utils"))).resolves.toMatchObject({
        isDirectory: expect.any(Function)
      });
      await result.cleanup();
    }
  });

  it("cleanup removes extracted directory", async () => {
    const archive = await createTarGz([{ name: "file.txt", data: "content" }]);
    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    const extractedPath = result.extractedPath;
    await result.cleanup();

    await expect(stat(extractedPath)).rejects.toThrow();
  });

  it("cleanup can be called twice safely", async () => {
    const archive = await createTarGz([{ name: "file.txt", data: "content" }]);
    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (result.ok) {
      await expect(result.cleanup()).resolves.toBeUndefined();
      await expect(result.cleanup()).resolves.toBeUndefined();
    }
  });

  it("cleans temp directory after extraction failure", async () => {
    const archive = await createTarGz([{ name: "../secret.txt", data: "secret" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result.ok).toBe(false);
    await expect(readdir(tempRoot)).resolves.toEqual([]);
  });

  it("preserves the extraction error when failure cleanup succeeds", async () => {
    const archive = await createTarGz([{ name: "../secret.txt", data: "secret" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("preserves the extraction error when failure cleanup fails", async () => {
    const archive = await createTarGz([{ name: "../secret.txt", data: "secret" }]);
    const rmMock = await mockSafeExtractRmFailure();
    const { extractTarballSafely: extractWithFailingRm } = await import("./safe-extract");

    const result = await extractWithFailingRm(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
    expect(rmMock).toHaveBeenCalled();
  });

  it("keeps explicit cleanup failures visible after successful extraction", async () => {
    const archive = await createTarGz([{ name: "file.txt", data: "content" }]);
    const rmMock = await mockSafeExtractRmFailure();
    const { extractTarballSafely: extractWithFailingRm } = await import("./safe-extract");
    const result = await extractWithFailingRm(archive, { tempRoot });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    await expect(result.cleanup()).rejects.toThrow("cleanup failed");
    expect(rmMock).toHaveBeenCalled();
  });

  it("rejects path traversal", async () => {
    const archive = await createTarGz([{ name: "../secret.txt", data: "secret" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("rejects nested path traversal", async () => {
    const archive = await createTarGz([{ name: "src/../../secret.txt", data: "secret" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("rejects absolute paths", async () => {
    const archive = await createTarGz([{ name: "/etc/passwd", data: "root" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("rejects Windows drive paths", async () => {
    const archive = await createTarGz([{ name: "C:\\Windows\\system32", data: "dll" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "PATH_TRAVERSAL_DETECTED",
      message: "Archive entry path is unsafe"
    });
  });

  it("rejects symlink entries", async () => {
    const archive = await createTarGz([
      { name: "linked", linkname: "target", type: "symlink" }
    ]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "SYMLINK_NOT_ALLOWED",
      message: "Archive links are not allowed"
    });
  });

  it("rejects hardlink entries", async () => {
    const archive = await createTarGz([{ name: "linked", linkname: "target", type: "link" }]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "SYMLINK_NOT_ALLOWED",
      message: "Archive links are not allowed"
    });
  });

  it("rejects duplicate file paths", async () => {
    const archive = await createTarGz([
      { name: "dup.txt", data: "first" },
      { name: "dup.txt", data: "second" }
    ]);

    const result = await extractTarballSafely(archive, { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "EXTRACTION_FAILED",
      message: "Archive contains duplicate entry paths"
    });
  });

  it("rejects file count over limit", async () => {
    const archive = await createTarGz([
      { name: "one.txt", data: "1" },
      { name: "two.txt", data: "2" }
    ]);

    const result = await extractTarballSafely(archive, {
      limits: { maxFiles: 1 },
      tempRoot
    });

    expect(result).toEqual({
      ok: false,
      code: "FILE_COUNT_LIMIT_EXCEEDED",
      message: "Archive file count limit exceeded"
    });
  });

  it("rejects single file over limit", async () => {
    const archive = await createTarGz([{ name: "large.txt", data: "1234" }]);

    const result = await extractTarballSafely(archive, {
      limits: { maxSingleFileBytes: 3 },
      tempRoot
    });

    expect(result).toEqual({
      ok: false,
      code: "SINGLE_FILE_LIMIT_EXCEEDED",
      message: "Archive file size limit exceeded"
    });
  });

  it("rejects total extracted size over limit", async () => {
    const archive = await createTarGz([
      { name: "one.txt", data: "12" },
      { name: "two.txt", data: "34" }
    ]);

    const result = await extractTarballSafely(archive, {
      limits: { maxExtractedBytes: 3 },
      tempRoot
    });

    expect(result).toEqual({
      ok: false,
      code: "EXTRACTED_SIZE_LIMIT_EXCEEDED",
      message: "Archive extracted size limit exceeded"
    });
  });

  it("returns extraction failed for corrupt archives", async () => {
    const result = await extractTarballSafely(new Uint8Array([1, 2, 3]), { tempRoot });

    expect(result).toEqual({
      ok: false,
      code: "EXTRACTION_FAILED",
      message: "Tarball extraction failed"
    });
  });
});

describe("downloadAndExtractGitHubTarball", () => {
  it("downloads and extracts a mocked GitHub tarball", async () => {
    const archive = await createTarGz([{ name: "package.json", data: "{}" }]);
    vi.stubGlobal("fetch", createFetchMock(archive, "application/x-gzip"));

    const result = await downloadAndExtractGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { tempRoot }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      await expect(readFile(path.join(result.extractedPath, "package.json"), "utf8")).resolves.toBe(
        "{}"
      );
      await result.cleanup();
    }
  });

  it("propagates download failures", async () => {
    vi.stubGlobal("fetch", createFetchMock(new Uint8Array(), "application/json", 403));

    const result = await downloadAndExtractGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { tempRoot }
    );

    expect(result).toEqual({
      ok: false,
      code: "RATE_LIMITED",
      message: "GitHub tarball download was rate limited",
      status: 403
    });
  });

  it("propagates unsupported content type download errors", async () => {
    vi.stubGlobal("fetch", createFetchMock(new Uint8Array([1]), "text/html"));

    const result = await downloadAndExtractGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { tempRoot }
    );

    expect(result).toEqual({
      ok: false,
      code: "UNSUPPORTED_CONTENT_TYPE",
      message: "GitHub tarball response has an unsupported content type",
      status: 200
    });
  });

  it("cleans temp directory when extraction fails after download", async () => {
    const archive = await createTarGz([{ name: "../secret.txt", data: "secret" }]);
    vi.stubGlobal("fetch", createFetchMock(archive, "application/x-gzip"));

    const result = await downloadAndExtractGitHubTarball(
      "https://api.github.com/repos/owner/repo/tarball",
      { tempRoot }
    );

    expect(result.ok).toBe(false);
    await expect(readdir(tempRoot)).resolves.toEqual([]);
  });

  it("ignores orphan cleanup removal failures", async () => {
    await createManagedExtractionDir("old");
    const rmMock = await mockSafeExtractRmFailure();
    const { cleanupOrphanExtractionDirs: cleanupWithFailingRm } = await import("./safe-extract");

    await expect(cleanupWithFailingRm({ tempRoot })).resolves.toBeUndefined();

    expect(rmMock).toHaveBeenCalled();
  });
});

describe("cleanupOrphanExtractionDirs", () => {
  it("removes old managed extraction directories", async () => {
    const orphanDir = await createManagedExtractionDir("old");

    await cleanupOrphanExtractionDirs({
      nowMs: Date.now(),
      tempRoot
    });

    await expect(stat(orphanDir)).rejects.toThrow();
  });

  it("keeps new managed extraction directories", async () => {
    const activeDir = await createManagedExtractionDir("new");

    await cleanupOrphanExtractionDirs({
      nowMs: Date.now(),
      tempRoot
    });

    await expect(stat(activeDir)).resolves.toMatchObject({
      isDirectory: expect.any(Function)
    });
  });

  it("never removes directories outside the managed UUID extraction prefix", async () => {
    const legacySmokeDir = path.join(tempRoot, "next-secure-check-test-smoke");
    const unrelatedDir = path.join(tempRoot, "unrelated");
    await mkdir(legacySmokeDir);
    await mkdir(unrelatedDir);
    await makeOld(legacySmokeDir);
    await makeOld(unrelatedDir);

    await cleanupOrphanExtractionDirs({
      nowMs: Date.now(),
      tempRoot
    });

    await expect(stat(legacySmokeDir)).resolves.toMatchObject({
      isDirectory: expect.any(Function)
    });
    await expect(stat(unrelatedDir)).resolves.toMatchObject({
      isDirectory: expect.any(Function)
    });
  });

  it("does not remove managed extraction files", async () => {
    const managedFile = path.join(
      tempRoot,
      "next-secure-check-00000000-0000-0000-0000-000000000000-"
    );
    await writeFile(managedFile, "not a directory");
    await makeOld(managedFile);

    await cleanupOrphanExtractionDirs({
      nowMs: Date.now(),
      tempRoot
    });

    await expect(readFile(managedFile, "utf8")).resolves.toBe("not a directory");
  });
});

type TarEntry = {
  data?: string | Uint8Array;
  linkname?: string;
  name: string;
  type?: Headers["type"];
};

async function createTarGz(entries: TarEntry[]): Promise<Uint8Array> {
  const archive = pack();

  for (const entry of entries) {
    const data = normalizeEntryData(entry.data);
    archive.entry(
      {
        linkname: entry.linkname,
        name: entry.name,
        size: data.byteLength,
        type: entry.type ?? "file"
      },
      data
    );
  }

  archive.finalize();
  const chunks: Buffer[] = [];
  for await (const chunk of archive) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return gzipSync(Buffer.concat(chunks));
}

function normalizeEntryData(data: string | Uint8Array | undefined): Buffer {
  if (typeof data === "string") {
    return Buffer.from(data);
  }

  if (data) {
    return Buffer.from(data);
  }

  return Buffer.alloc(0);
}

function createFetchMock(
  bytes: Uint8Array,
  contentType: string,
  status = 200
): typeof fetch {
  const buffer = Buffer.from(bytes);

  return vi.fn().mockResolvedValue({
    arrayBuffer: async () =>
      buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength),
    body: undefined,
    headers: new Headers({
      "content-length": String(bytes.byteLength),
      "content-type": contentType
    }),
    ok: status >= 200 && status < 300,
    status
  }) as unknown as typeof fetch;
}

async function mockSafeExtractRmFailure(): Promise<ReturnType<typeof vi.fn>> {
  const rmMock = vi.fn().mockRejectedValue(new Error("cleanup failed"));

  vi.resetModules();
  vi.doMock("node:fs/promises", async (importOriginal) => {
    const actual = await importOriginal<typeof import("node:fs/promises")>();
    return {
      ...actual,
      rm: rmMock
    };
  });

  return rmMock;
}

async function createManagedExtractionDir(age: "new" | "old"): Promise<string> {
  const dir = path.join(tempRoot, `next-secure-check-00000000-0000-0000-0000-00000000000${age === "old" ? "1" : "2"}-`);
  await mkdir(dir);

  if (age === "old") {
    await makeOld(dir);
  }

  return dir;
}

async function makeOld(targetPath: string): Promise<void> {
  const oldDate = new Date(Date.now() - ORPHAN_EXTRACTION_MAX_AGE_MS - 60_000);
  await utimes(targetPath, oldDate, oldDate);
}
