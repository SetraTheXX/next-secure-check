import { describe, expect, it } from "vitest";
import {
  MAX_SCAN_REQUEST_BODY_BYTES,
  readScanRequestJson,
  validateScanRequestContentLength
} from "./scan-request-body";

describe("validateScanRequestContentLength", () => {
  it("accepts a missing content length so the request stream can be measured", () => {
    expect(validateScanRequestContentLength(null)).toBe("valid");
  });

  it("rejects malformed and oversized content length values", () => {
    expect(validateScanRequestContentLength("12, 12")).toBe("invalid");
    expect(validateScanRequestContentLength(String(MAX_SCAN_REQUEST_BODY_BYTES + 1))).toBe("too_large");
    expect(validateScanRequestContentLength("000" + MAX_SCAN_REQUEST_BODY_BYTES)).toBe("valid");
  });
});

describe("readScanRequestJson", () => {
  it("rejects an oversized stream when content length is absent", async () => {
    const request = createStreamRequest(new Uint8Array(MAX_SCAN_REQUEST_BODY_BYTES + 1));

    await expect(readScanRequestJson(request)).resolves.toEqual({
      ok: false,
      reason: "too_large"
    });
  });

  it("rejects an oversized stream when content length understates its size", async () => {
    const request = createStreamRequest(new Uint8Array(MAX_SCAN_REQUEST_BODY_BYTES + 1), {
      "content-length": "1"
    });

    await expect(readScanRequestJson(request)).resolves.toEqual({
      ok: false,
      reason: "too_large"
    });
  });

  it("parses a valid bounded JSON request", async () => {
    const request = createStreamRequest(new TextEncoder().encode(JSON.stringify({ repoUrl: "owner/repo" })));

    await expect(readScanRequestJson(request)).resolves.toEqual({
      ok: true,
      value: { repoUrl: "owner/repo" }
    });
  });

  it("rejects a request aborted before reading even when its JSON body is ready", async () => {
    const abortController = new AbortController();
    const request = createStreamRequest(
      new TextEncoder().encode(JSON.stringify({ repoUrl: "owner/repo" })),
      {},
      abortController.signal
    );
    abortController.abort();

    await expect(readScanRequestJson(request)).resolves.toEqual({
      ok: false,
      reason: "aborted"
    });
  });
});

function createStreamRequest(
  bytes: Uint8Array,
  headers: Record<string, string> = {},
  signal?: AbortSignal
): Request {
  const body = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      }
    },
    { highWaterMark: 0 }
  );

  return new Request("http://localhost/api/scans", {
    body,
    duplex: "half",
    headers: new Headers(headers),
    method: "POST",
    signal
  } as RequestInit & { duplex: "half" });
}
