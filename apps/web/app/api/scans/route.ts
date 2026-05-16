import { NextResponse } from "next/server";
import { scanPublicGitHubRepo } from "../../../lib/scan-public-repo";

type ScanRequestBody = {
  repoUrl?: unknown;
};

export async function POST(request: Request): Promise<NextResponse> {
  let body: ScanRequestBody;

  try {
    body = (await request.json()) as ScanRequestBody;
  } catch {
    return NextResponse.json(
      {
        ok: false,
        code: "INVALID_REQUEST_BODY",
        message: "Request body must be valid JSON."
      },
      { status: 400 }
    );
  }

  if (!body || typeof body.repoUrl !== "string" || !body.repoUrl.trim()) {
    return NextResponse.json(
      {
        ok: false,
        code: "INVALID_REQUEST_BODY",
        message: "repoUrl is required."
      },
      { status: 400 }
    );
  }

  let result: Awaited<ReturnType<typeof scanPublicGitHubRepo>>;

  try {
    result = await scanPublicGitHubRepo(body.repoUrl);
  } catch {
    return NextResponse.json(
      {
        ok: false,
        code: "SCAN_FAILED",
        message: "Scan failed unexpectedly."
      },
      { status: 500 }
    );
  }

  if (result.ok) {
    return NextResponse.json(result, { status: 200 });
  }

  return NextResponse.json(result, { status: statusForErrorCode(result.code) });
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
    code === "RATE_LIMITED" ||
    code === "NETWORK_ERROR" ||
    code === "UNSUPPORTED_CONTENT_TYPE"
  ) {
    return 502;
  }

  return 500;
}
