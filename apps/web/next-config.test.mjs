import { describe, expect, it } from "vitest";
import nextConfig, { createContentSecurityPolicy } from "./next.config.mjs";

describe("Next.js security headers", () => {
  it("keeps production CSP strict enough without blocking Next.js hydration", () => {
    const csp = createContentSecurityPolicy({ development: false });

    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");
  });

  it("allows the Next.js dev runtime requirements only in development CSP", () => {
    const csp = createContentSecurityPolicy({ development: true });

    expect(csp).toContain("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).toContain("connect-src 'self' https://api.github.com ws:");
  });

  it("keeps the hardening headers configured", async () => {
    const [{ headers }] = await nextConfig.headers();
    const headerMap = new Map(headers.map((header) => [header.key, header.value]));

    expect(nextConfig.poweredByHeader).toBe(false);
    expect(headerMap.get("Content-Security-Policy")).toContain("script-src");
    expect(headerMap.get("X-Frame-Options")).toBe("DENY");
    expect(headerMap.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headerMap.get("Referrer-Policy")).toBe("no-referrer");
    expect(headerMap.get("Permissions-Policy")).toBe("camera=(), microphone=(), geolocation=()");
  });
});
