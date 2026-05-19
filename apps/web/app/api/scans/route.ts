import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { getScanClientIp, tryAcquireScanSlot } from "../../../lib/scan-abuse-guard";
import { validateExcludePaths } from "../../../lib/scan-excludes";
import { scanPublicGitHubRepo } from "../../../lib/scan-public-repo";
import { logSafeScanEvent } from "../../../lib/safe-log";

type ScanRequestBody = {
  excludePaths?: unknown;
  repoUrl?: unknown;
};

export async function POST(request: Request): Promise<NextResponse> {
  const scanId = randomUUID();
  const startedAt = Date.now();
  let body: ScanRequestBody;

  try {
    body = (await request.json()) as ScanRequestBody;
  } catch {
    return jsonWithSafeLog(scanId, startedAt, {
      body: {
        ok: false,
        code: "INVALID_REQUEST_BODY",
        message: "Request body must be valid JSON."
      },
      code: "INVALID_REQUEST_BODY",
      status: 400
    });
  }

  if (!body || typeof body.repoUrl !== "string" || !body.repoUrl.trim()) {
    return jsonWithSafeLog(scanId, startedAt, {
      body: {
        ok: false,
        code: "INVALID_REQUEST_BODY",
        message: "repoUrl is required."
      },
      code: "INVALID_REQUEST_BODY",
      status: 400
    });
  }

  const excludePaths = validateExcludePaths(body.excludePaths);
  if (!excludePaths) {
    return jsonWithSafeLog(scanId, startedAt, {
      body: {
        ok: false,
        code: "INVALID_REQUEST_BODY",
        message: "excludePaths must be an array of safe relative glob patterns."
      },
      code: "INVALID_REQUEST_BODY",
      status: 400
    });
  }

  const guard = await tryAcquireScanSlot(getScanClientIp(request.headers));
  if (!guard.ok) {
    return jsonWithSafeLog(scanId, startedAt, {
      body: {
        ok: false,
        code: guard.code,
        message: guard.message
      },
      code: guard.code,
      status: 429
    });
  }

  let result: Awaited<ReturnType<typeof scanPublicGitHubRepo>>;

  try {
    result =
      excludePaths.length > 0
        ? await scanPublicGitHubRepo(body.repoUrl, { excludePaths })
        : await scanPublicGitHubRepo(body.repoUrl);
  } catch {
    return jsonWithSafeLog(scanId, startedAt, {
      body: {
        ok: false,
        code: "SCAN_FAILED",
        message: "Scan failed unexpectedly."
      },
      code: "SCAN_FAILED",
      status: 500
    });
  } finally {
    await guard.release();
  }

  if (result.ok) {
    return jsonWithSafeLog(scanId, startedAt, {
      body: result,
      status: 200
    });
  }

  return jsonWithSafeLog(scanId, startedAt, {
    body: result,
    code: result.code,
    status: statusForErrorCode(result.code)
  });
}

function statusForErrorCode(code: string): number {
  if (code === "INVALID_REPO_URL") {
    return 400;
  }

  if (code === "METADATA_FETCH_FAILED" || code === "INVALID_TARBALL_URL") {
    return 422;
  }

  if (
    code === "DOWNLOAD_TIMEOUT" ||
    code === "SCAN_TIMEOUT" ||
    code === "RATE_LIMITED" ||
    code === "NETWORK_ERROR" ||
    code === "UNSUPPORTED_CONTENT_TYPE"
  ) {
    return 502;
  }

  return 500;
}

function jsonWithSafeLog<T>(
  scanId: string,
  startedAt: number,
  options: {
    body: T;
    code?: string;
    status: number;
  }
): NextResponse {
  logSafeScanEvent({
    code: options.code,
    durationMs: Date.now() - startedAt,
    event:
      options.status >= 500
        ? "scan_failed"
        : options.status >= 400
          ? "scan_rejected"
          : "scan_completed",
    scanId,
    status: options.status
  });

  return NextResponse.json(options.body, { status: options.status });
}
