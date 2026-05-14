import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { scanProject } from "@next-secure-check/core";
import { getBuiltInRules } from "./index.js";

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-rules-"));
}

async function scanFixture(files: Record<string, string>) {
  const root = await tempProject();
  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const absolutePath = path.join(root, filePath);
      await mkdir(path.dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, content);
    })
  );

  return scanProject(root, { rules: getBuiltInRules() });
}

describe("built-in security rules", () => {
  it("detects committed env files", async () => {
    const result = await scanFixture({ ".env.local": "TOKEN=abc" });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/env-file-committed")).toBe(true);
  });

  it("does not flag env example files as committed env secrets", async () => {
    const result = await scanFixture({ ".env.example": "TOKEN=" });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/env-file-committed")).toBe(false);
  });

  it("detects hardcoded secrets", async () => {
    const result = await scanFixture({ "index.ts": 'const apiKey = "1234567890";' });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/hardcoded-secret")).toBe(true);
  });

  it("detects weak JWT secrets", async () => {
    const result = await scanFixture({ "index.ts": 'const JWT_SECRET = "secret";' });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/weak-jwt-secret")).toBe(true);
  });

  it("detects eval usage", async () => {
    const result = await scanFixture({ "index.ts": "eval('1 + 1');" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/no-eval")).toBe(true);
  });

  it("detects dangerouslySetInnerHTML usage", async () => {
    const result = await scanFixture({ "app/page.tsx": "export default () => <div dangerouslySetInnerHTML={{__html: html}} />;" });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(true);
  });

  it("detects wildcard CORS", async () => {
    const result = await scanFixture({ "app/api/data/route.ts": 'headers: { "Access-Control-Allow-Origin": "*" }' });

    expect(result.findings.some((finding) => finding.ruleId === "config/insecure-cors-wildcard")).toBe(true);
  });

  it("detects login endpoints without rate limiting", async () => {
    const result = await scanFixture({ "app/api/login/route.ts": "export async function POST() { return Response.json({ ok: true }); }" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
  });

  it("does not flag login endpoints with rate limiting", async () => {
    const result = await scanFixture({ "app/api/login/route.ts": "const rateLimit = true; export async function POST() {}" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("detects password handling without hashing libraries", async () => {
    const result = await scanFixture({ "app/api/register/route.ts": "const password = body.password;" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(true);
  });

  it("does not flag password handling when bcrypt is installed", async () => {
    const result = await scanFixture({
      "package.json": '{"dependencies":{"bcrypt":"latest"}}',
      "app/api/register/route.ts": "const password = body.password;"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(false);
  });

  it("detects raw SQL interpolation", async () => {
    const result = await scanFixture({ "app/api/users/route.ts": "const sql = `SELECT * FROM users WHERE id = ${id}`;" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(true);
  });

  it("detects missing security headers in Next.js apps", async () => {
    const result = await scanFixture({ "package.json": '{"name":"demo"}', "app/page.tsx": "export default function Page() { return null; }" });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(true);
  });

  it("does not flag missing security headers when headers are configured", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default function Page() { return null; }",
      "next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] } }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(false);
  });

  it("detects NEXT_PUBLIC secret-like variables", async () => {
    const result = await scanFixture({ ".env": "NEXT_PUBLIC_STRIPE_SECRET=sk_test_123" });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/next-public-secret")).toBe(true);
  });
});
