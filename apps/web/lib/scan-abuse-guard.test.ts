import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getScanClientIp,
  resetScanAbuseGuardForTests,
  tryAcquireScanSlot
} from "./scan-abuse-guard";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  resetScanAbuseGuardForTests();
});

describe("getScanClientIp", () => {
  it("falls back to unknown when client IP headers are missing", () => {
    expect(getScanClientIp(new Headers())).toBe("unknown");
  });

  it("falls back to unknown when client IP headers are empty", () => {
    expect(getScanClientIp(new Headers({ "x-forwarded-for": "   " }))).toBe("unknown");
  });

  it("uses the Vercel forwarded header before generic proxy headers", () => {
    const headers = new Headers({
      "x-forwarded-for": "203.0.113.20",
      "x-real-ip": "203.0.113.30",
      "x-vercel-forwarded-for": "203.0.113.10"
    });

    expect(getScanClientIp(headers)).toBe("203.0.113.10");
  });

  it("uses a valid x-forwarded-for client IP", () => {
    expect(getScanClientIp(new Headers({ "x-forwarded-for": "203.0.113.1" }))).toBe(
      "203.0.113.1"
    );
  });

  it("uses the first valid IP from a comma separated x-forwarded-for header", () => {
    const headers = new Headers({
      "x-forwarded-for": "spoofed, 198.51.100.10, 203.0.113.10"
    });

    expect(getScanClientIp(headers)).toBe("198.51.100.10");
  });

  it("trims whitespace around forwarded IP values", () => {
    expect(getScanClientIp(new Headers({ "x-forwarded-for": "  198.51.100.20  " }))).toBe(
      "198.51.100.20"
    );
  });

  it("falls back to x-real-ip when forwarded headers are invalid", () => {
    const headers = new Headers({
      "x-forwarded-for": "not-an-ip",
      "x-real-ip": "203.0.113.40"
    });

    expect(getScanClientIp(headers)).toBe("203.0.113.40");
  });

  it("returns unknown for spoofed or invalid IP values without a fallback", () => {
    expect(getScanClientIp(new Headers({ "x-forwarded-for": "127.0.0.1.evil.com" }))).toBe(
      "unknown"
    );
  });

  it("returns unknown for overly long client IP headers", () => {
    const headerValue = `${"1".repeat(513)}, 203.0.113.50`;

    expect(getScanClientIp(new Headers({ "x-forwarded-for": headerValue }))).toBe("unknown");
  });

  it("supports IPv6 client IP values", () => {
    expect(getScanClientIp(new Headers({ "x-forwarded-for": "2001:db8::1" }))).toBe(
      "2001:db8::1"
    );
  });
});

describe("tryAcquireScanSlot", () => {
  it("keeps the existing per-IP rate limit behavior without distributed env", async () => {
    resetScanAbuseGuardForTests();

    const first = await tryAcquireScanSlot("203.0.113.60", 1_000);
    const second = await tryAcquireScanSlot("203.0.113.60", 1_000);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (first.ok) {
      first.release();
    }
    if (second.ok) {
      second.release();
    }

    const third = await tryAcquireScanSlot("203.0.113.60", 1_000);
    expect(third.ok).toBe(true);
    if (third.ok) {
      third.release();
    }

    const result = await tryAcquireScanSlot("203.0.113.60", 1_000);

    expect(result).toMatchObject({
      code: "SCAN_RATE_LIMITED",
      ok: false
    });
  });

  it("uses Upstash REST when distributed env is configured", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createUpstashResponse([{ result: 1 }, { result: 1 }]))
      .mockResolvedValueOnce(createUpstashResponse([{ result: 1 }, { result: 1 }]))
      .mockResolvedValueOnce(createUpstashResponse([{ result: 0 }]));
    vi.stubGlobal("fetch", fetchMock);

    const result = await tryAcquireScanSlot("203.0.113.70", 1_000);
    expect(result.ok).toBe(true);
    if (result.ok) {
      await result.release();
    }

    const firstRequest = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const headers = new Headers(firstRequest.headers);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://redis.example.com/pipeline");
    expect(headers.get("Authorization")).toBe("Bearer upstash-secret-token");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(JSON.stringify(result)).not.toContain("upstash-secret-token");
  });

  it("rate limits through the distributed store", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(createUpstashResponse([{ result: 4 }, { result: 1 }]))
    );

    const result = await tryAcquireScanSlot("203.0.113.71", 1_000);

    expect(result).toEqual({
      ok: false,
      code: "SCAN_RATE_LIMITED",
      message: "Too many scan requests. Please wait before starting another scan."
    });
  });

  it("enforces distributed concurrent scan limits", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createUpstashResponse([{ result: 1 }, { result: 1 }]))
      .mockResolvedValueOnce(createUpstashResponse([{ result: 3 }, { result: 1 }]))
      .mockResolvedValueOnce(createUpstashResponse([{ result: 2 }]));
    vi.stubGlobal("fetch", fetchMock);

    const result = await tryAcquireScanSlot("203.0.113.72", 1_000);

    expect(result).toEqual({
      ok: false,
      code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
      message: "Too many scans are running. Please try again shortly."
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("fails closed without leaking tokens when the distributed store fails", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-secret-token");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      })
    );

    const result = await tryAcquireScanSlot("203.0.113.73", 1_000);

    expect(result).toEqual({
      ok: false,
      code: "CONCURRENT_SCAN_LIMIT_EXCEEDED",
      message: "Too many scans are running. Please try again shortly."
    });
    expect(JSON.stringify(result)).not.toContain("upstash-secret-token");
  });
});

function createUpstashResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    headers: {
      "content-type": "application/json"
    },
    status: 200
  });
}
