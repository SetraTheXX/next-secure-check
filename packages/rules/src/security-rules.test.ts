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

  it("does not flag eval text inside metadata strings", async () => {
    const result = await scanFixture({ "index.ts": 'const title = "eval() usage detected";' });

    expect(result.findings.some((finding) => finding.ruleId === "injection/no-eval")).toBe(false);
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

  it("does not flag unrelated URL credential validation as password hashing risk", async () => {
    const result = await scanFixture({
      "lib/github-url.ts": "const url = new URL(input); if (url.username || url.password) return false;"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(false);
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

  it("detects register endpoints without rate limiting", async () => {
    const result = await scanFixture({ "app/api/register/route.ts": "export async function POST() { return Response.json({ ok: true }); }" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(true);
  });

  it("does not flag register endpoints with rate limiting", async () => {
    const result = await scanFixture({ "app/api/register/route.ts": "const rateLimit = true; export async function POST() {}" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("detects new Function() usage", async () => {
    const result = await scanFixture({ "index.ts": "const f = new Function('return 1');" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/no-new-function")).toBe(true);
  });

  it("does not flag new Function text inside metadata strings", async () => {
    const result = await scanFixture({ "index.ts": 'const title = "new Function() usage detected";' });

    expect(result.findings.some((finding) => finding.ruleId === "injection/no-new-function")).toBe(false);
  });

  it("detects shell command execution", async () => {
    const result = await scanFixture({ "index.ts": "import { exec } from 'child_process'; exec('ls');" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(true);
  });

  it("does not flag RegExp exec API usage as shell command execution", async () => {
    const result = await scanFixture({
      "index.ts": "while ((match = matcher.exec(lineContent)) !== null) { matches.push(match); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(false);
  });

  it("detects child_process imports", async () => {
    const result = await scanFixture({ "index.ts": "import { exec } from 'child_process';" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(true);
  });

  it("detects missing file type validation in upload endpoints", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-type-validation")).toBe(true);
  });

  it("does not flag upload endpoints with file type validation", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); if (file.type === 'image/png') {} return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-type-validation")).toBe(false);
  });

  it("detects missing file size limit in upload endpoints", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-size-limit")).toBe(true);
  });

  it("does not flag upload endpoints with file size limit", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); if (file.size > 100) {} return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-size-limit")).toBe(false);
  });

  it("does not flag files with upload content but non-upload path", async () => {
    const result = await scanFixture({
      "config/secrets.ts": "export const STRIPE_KEY = 'sk_test_123'; const data = await req.formData();"
    });

    expect(result.findings.some((finding) => finding.category === "upload")).toBe(false);
  });

  it("does not flag files with upload path but non-upload content", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function GET() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.category === "upload")).toBe(false);
  });

  it("detects API routes without input validation", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "export async function POST(req) { const body = await req.json(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(true);
  });

  it("does not flag API routes with input validation", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "import { z } from 'zod'; const schema = z.object({ name: z.string() }); export async function POST(req) { const body = await req.json(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("detects admin routes without auth protection", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("does not flag admin routes with auth protection", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": "import { getServerSession } from 'next-auth'; export async function GET() { const session = await getServerSession(); return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("detects production browser source maps enabled in next.config.js", async () => {
    const result = await scanFixture({
      "next.config.js": "module.exports = { productionBrowserSourceMaps: true };"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/production-browser-source-maps")).toBe(true);
  });

  it("does not flag productionBrowserSourceMaps when disabled", async () => {
    const result = await scanFixture({
      "next.config.js": "module.exports = { productionBrowserSourceMaps: false };"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/production-browser-source-maps")).toBe(false);
  });

  it("detects missing poweredByHeader: false in next.config.js for Next.js projects", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"next":"latest"}}',
      "next.config.js": "module.exports = { reactStrictMode: true };"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/next-powered-by-header")).toBe(true);
  });

  it("does not flag poweredByHeader: false", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"next":"latest"}}',
      "next.config.js": "module.exports = { poweredByHeader: false };"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/next-powered-by-header")).toBe(false);
  });

  it("does not flag non-Next.js projects for powered by header", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"express":"latest"}}',
      "next.config.js": "module.exports = { reactStrictMode: true };"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/next-powered-by-header")).toBe(false);
  });
});
