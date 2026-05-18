import { describe, expect, it } from "vitest";
import {
  getScanClientIp,
  resetScanAbuseGuardForTests,
  tryAcquireScanSlot
} from "./scan-abuse-guard";

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
  it("keeps the existing per-IP rate limit behavior", () => {
    resetScanAbuseGuardForTests();

    const first = tryAcquireScanSlot("203.0.113.60", 1_000);
    const second = tryAcquireScanSlot("203.0.113.60", 1_000);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (first.ok) {
      first.release();
    }
    if (second.ok) {
      second.release();
    }

    const third = tryAcquireScanSlot("203.0.113.60", 1_000);
    expect(third.ok).toBe(true);
    if (third.ok) {
      third.release();
    }

    const result = tryAcquireScanSlot("203.0.113.60", 1_000);

    expect(result).toMatchObject({
      code: "SCAN_RATE_LIMITED",
      ok: false
    });
  });
});
