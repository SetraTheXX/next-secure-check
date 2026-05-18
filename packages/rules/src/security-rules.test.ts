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
    const result = await scanFixture({ "index.ts": 'const apiKey = "aB3_dEfGh9JkLmN0";' });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/hardcoded-secret")).toBe(true);
  });

  it("does not flag low-signal hardcoded secret sample values", async () => {
    const result = await scanFixture({
      "index.ts": [
        'const token = "test1234";',
        'const password = "12345678";',
        'const secret = "password";',
        'const apiKey = "changeme";',
        'const privateKey = "example";',
        'const githubToken = "demo";',
        'const stripeKey = "dummy";',
        'const jwtSecret = "placeholder";'
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/hardcoded-secret")).toBe(false);
  });

  it("keeps detecting known provider token patterns with high confidence", async () => {
    const result = await scanFixture({ "index.ts": 'const apiKey = "sk_live_super_secret";' });
    const finding = result.findings.find((item) => item.ruleId === "secrets/hardcoded-secret");

    expect(finding).toMatchObject({
      confidence: "HIGH",
      evidence: 'const apiKey = "sk_live_super_secret";'
    });
  });

  it("keeps detecting long high-signal secret-like values", async () => {
    const result = await scanFixture({ "index.ts": 'const githubToken = "gh_demo_A1b2C3d4E5f6G7h8";' });

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
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "MEDIUM"
    });
  });

  it("keeps static dangerouslySetInnerHTML literals at low severity", async () => {
    const result = await scanFixture({
      "app/page.tsx": 'export default () => <div dangerouslySetInnerHTML={{__html: "<h1>Safe static copy</h1>"}} />;'
    });
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "LOW"
    });
  });

  it("raises user-controlled-looking dangerouslySetInnerHTML sources to medium severity", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        "export default function Page({ searchParams }) {",
        "  return <main dangerouslySetInnerHTML={{ __html: searchParams.preview }} />;",
        "}"
      ].join("\n")
    });
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "MEDIUM"
    });
  });

  it("keeps unknown dangerouslySetInnerHTML sources at low severity", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default () => <div dangerouslySetInnerHTML={trustedMarkup} />;"
    });
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "LOW"
    });
  });

  it("does not flag dangerouslySetInnerHTML text inside metadata strings", async () => {
    const result = await scanFixture({
      "index.ts": 'const title = "dangerouslySetInnerHTML usage detected";'
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
  });

  it("does not flag dangerouslySetInnerHTML inside rule regex literals", async () => {
    const result = await scanFixture({
      "index.ts": "const pattern = /dangerouslySetInnerHTML/;"
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
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

  it("detects raw SQL interpolation passed to query APIs", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "db.query(`SELECT * FROM users WHERE email = ${email}`);",
        "connection.execute(`DELETE FROM users WHERE id = ${id}`);"
      ].join("\n")
    });

    const findings = result.findings.filter((finding) => finding.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(2);
  });

  it("does not flag raw SQL text in low-risk logging and error contexts", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "console.log(`SELECT * FROM users WHERE id = ${id}`);",
        "logger.debug(`SELECT * FROM users WHERE id = ${id}`);",
        "logger.info(`UPDATE users SET name = ${name} WHERE id = ${id}`);",
        "throw new Error(`DELETE FROM users WHERE id = ${id}`);"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("does not flag raw SQL concatenation in low-risk logging contexts", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": 'console.log("SELECT * FROM users WHERE id = " + id);'
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("keeps flagging Prisma raw SQL tagged templates for review", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;"
    });

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

  it("does not flag indented RegExp exec API usage as shell command execution", async () => {
    const result = await scanFixture({
      "index.ts": "function collect() {\n  while ((match = matcher.exec(lineContent)) !== null) { matches.push(match); }\n}"
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(false);
  });

  it("does not flag other exec method calls as shell command execution", async () => {
    const result = await scanFixture({
      "index.ts": "regex.exec(input);\nrouter.exec();\napp.exec();"
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(false);
  });

  it("detects bare command execution after a safe exec method call on the same line", async () => {
    const result = await scanFixture({
      "index.ts": 'regex.exec(input); exec("ls");'
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings[0]?.evidence).toBe('regex.exec(input); exec("ls");');
  });

  it("detects bare spawn after a safe exec method call on the same line", async () => {
    const result = await scanFixture({
      "index.ts": 'object.exec(); spawn("ls");'
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings[0]?.evidence).toBe('object.exec(); spawn("ls");');
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

  it("does not flag API routes with custom typeof validation", async () => {
    const result = await scanFixture({
      "app/api/scans/route.ts": "export async function POST(request) { const body = await request.json(); if (!body || typeof body.repoUrl !== 'string' || !body.repoUrl.trim()) return Response.json({ ok: false }, { status: 400 }); return Response.json({ ok: true }); }"
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
