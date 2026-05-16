import type { TarballDownloadResult } from "./archive-types";
import { DEFAULT_SCAN_LIMITS } from "./scan-limits";

const ALLOWED_TARBALL_CONTENT_TYPES = new Set([
  "application/gzip",
  "application/octet-stream",
  "application/x-gzip",
  "application/x-tar",
  "binary/octet-stream"
]);

export type DownloadGitHubTarballOptions = {
  timeoutMs?: number;
  maxDownloadBytes?: number;
};

export async function downloadGitHubTarball(
  tarballUrl: string,
  options?: DownloadGitHubTarballOptions
): Promise<TarballDownloadResult> {
  const parsedUrl = parseTarballUrl(tarballUrl);
  if (!parsedUrl) {
    return {
      ok: false,
      code: "INVALID_TARBALL_URL",
      message: "Invalid GitHub tarball URL"
    };
  }

  const timeoutMs = options?.timeoutMs ?? DEFAULT_SCAN_LIMITS.timeoutMs;
  const maxDownloadBytes =
    options?.maxDownloadBytes ?? DEFAULT_SCAN_LIMITS.maxArchiveDownloadBytes;

  try {
    const response = await fetchWithTimeout(parsedUrl.toString(), timeoutMs);

    if (!response.ok) {
      if (response.status === 403 || response.status === 429) {
        return {
          ok: false,
          code: "RATE_LIMITED",
          message: "GitHub tarball download was rate limited",
          status: response.status
        };
      }

      return {
        ok: false,
        code: "NETWORK_ERROR",
        message: "GitHub tarball download failed",
        status: response.status
      };
    }

    const contentType = normalizeContentType(response.headers.get("content-type"));
    if (!isSupportedTarballContentType(contentType)) {
      return {
        ok: false,
        code: "UNSUPPORTED_CONTENT_TYPE",
        message: "GitHub tarball response has an unsupported content type",
        status: response.status
      };
    }

    const contentLength = parseContentLength(response.headers.get("content-length"));
    if (contentLength !== undefined && contentLength > maxDownloadBytes) {
      return {
        ok: false,
        code: "ARCHIVE_TOO_LARGE",
        message: "GitHub tarball is too large",
        status: response.status
      };
    }

    const bytes = await readResponseBytes(response, maxDownloadBytes);
    if (!bytes) {
      return {
        ok: false,
        code: "ARCHIVE_TOO_LARGE",
        message: "GitHub tarball is too large",
        status: response.status
      };
    }

    return {
      ok: true,
      bytes,
      sizeBytes: bytes.byteLength,
      contentType,
      sourceUrl: parsedUrl.toString()
    };
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      return {
        ok: false,
        code: "DOWNLOAD_TIMEOUT",
        message: "GitHub tarball download timed out"
      };
    }

    return {
      ok: false,
      code: "NETWORK_ERROR",
      message: "GitHub tarball download failed"
    };
  }
}

function parseTarballUrl(tarballUrl: string): URL | undefined {
  try {
    const url = new URL(tarballUrl);
    if (url.protocol !== "https:") {
      return undefined;
    }

    if (url.hostname !== "api.github.com") {
      return undefined;
    }

    if (!/^\/repos\/[^/]+\/[^/]+\/tarball(?:\/[^/]+)?$/.test(url.pathname)) {
      return undefined;
    }

    return url;
  } catch {
    return undefined;
  }
}

function normalizeContentType(contentType: string | null): string {
  return contentType?.split(";")[0]?.trim().toLowerCase() ?? "";
}

function isSupportedTarballContentType(contentType: string): boolean {
  return ALLOWED_TARBALL_CONTENT_TYPES.has(contentType);
}

function parseContentLength(contentLength: string | null): number | undefined {
  if (!contentLength) {
    return undefined;
  }

  const parsed = Number(contentLength);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  return Promise.race([
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
  ]);
}

async function readResponseBytes(
  response: Response,
  maxDownloadBytes: number
): Promise<Uint8Array | undefined> {
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    return bytes.byteLength <= maxDownloadBytes ? bytes : undefined;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let sizeBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      if (value) {
        sizeBytes += value.byteLength;
        if (sizeBytes > maxDownloadBytes) {
          await reader.cancel();
          return undefined;
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(sizeBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return bytes;
}
