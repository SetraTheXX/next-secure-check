import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { scanProject } from "@next-secure-check/core";
import { getBuiltInRules } from "./index.js";

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-rules-"));
}

async function scanFixture(files: Record<string, string>, options: { contextTuning?: "standard" | "off" } = {}) {
  const root = await tempProject();
  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const absolutePath = path.join(root, filePath);
      await mkdir(path.dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, content);
    })
  );

  return scanProject(root, { contextTuning: options.contextTuning, rules: getBuiltInRules() });
}

describe("built-in security rules", () => {
  it("detects committed env files", async () => {
    const result = await scanFixture({ ".env.local": "TOKEN=abc" });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/env-file-committed")).toBe(true);
  });

  it("detects committed env file variants", async () => {
    const result = await scanFixture({
      ".env.development": "TOKEN=dev",
      ".env.production.local": "TOKEN=prod",
      ".env.test": "TOKEN=test"
    });

    const envFindings = result.findings.filter((finding) => finding.ruleId === "secrets/env-file-committed");
    expect(envFindings.map((finding) => finding.filePath)).toEqual([
      ".env.development",
      ".env.production.local",
      ".env.test"
    ]);
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

  it("does not flag static dangerouslySetInnerHTML literals", async () => {
    const result = await scanFixture({
      "app/page.tsx": 'export default () => <div dangerouslySetInnerHTML={{__html: "<h1>Safe static copy</h1>"}} />;'
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
  });

  it("does not flag clearly sanitized dangerouslySetInnerHTML sources", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        "export default function Page({ html, markdown }) {",
        "  return <>",
        "    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(markdown) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizeMarkdown(markdown) }} />",
        "  </>;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
  });

  it("does not flag imported sanitizer aliases used for dangerouslySetInnerHTML", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        'import sanitizeHtml from "sanitize-html";',
        'import purifier from "dompurify";',
        'import { sanitizeHtml as sanitizePackageHtml } from "sanitize-html";',
        "export default function Page({ html, markdown }) {",
        "  return <>",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: purifier.sanitize(html) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizePackageHtml(markdown) }} />",
        "  </>;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
  });

  it("does not trust unknown dangerouslySetInnerHTML sanitizer wrappers", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        'import { sanitize as localSanitize } from "./sanitize";',
        'import { sanitizeHtml } from "./sanitize";',
        "export default function Page({ html, markdown }) {",
        "  return <>",
        "    <div dangerouslySetInnerHTML={{ __html: localSanitize(html) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitize(markdown) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizeContent(markdown) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: toSafeHtml(markdown) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: customSanitizer(markdown) }} />",
        "    <div dangerouslySetInnerHTML={{ __html: renderer.sanitize(markdown) }} />",
        "  </>;",
        "}"
      ].join("\n")
    });
    const findings = result.findings.filter((finding) => finding.ruleId === "xss/dangerously-set-inner-html");

    expect(findings).toHaveLength(7);
    expect(findings.every((finding) => finding.severity === "MEDIUM")).toBe(true);
  });

  it("adds bounded source evidence for direct request-derived HTML", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        "export default function Page({ request }) {",
        "  return <main dangerouslySetInnerHTML={{ __html: request.json() }} />;",
        "}"
      ].join("\n")
    });
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "MEDIUM",
      evidencePath: "request.json()"
    });
  });

  it("does not flag same-file static or sanitized HTML constants", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        'const safeHtml = "<strong>Hello</strong>";',
        "const sanitizedHtml = DOMPurify.sanitize(markdown);",
        "export default function Page() {",
        "  return <>",
        "    <div dangerouslySetInnerHTML={{ __html: safeHtml }} />",
        "    <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />",
        "  </>;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
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

  it.each([
    ["userInput", "userInput"],
    ["params", "params.preview"],
    ["query", "query.preview"],
    ["body", "body.html"],
    ["request", "request.html"],
    ["req", "req.body.html"],
    ["formData", "formData.get('html')"],
    ["comment.body", "comment.body"],
    ["markdown", "markdown"],
    ["html", "html"],
    ["content", "content"],
    ["cmsContent", "cmsContent"]
  ])("keeps risky dangerouslySetInnerHTML source %s flagged", async (_label, sourceExpression) => {
    const result = await scanFixture({
      "app/page.tsx": `export default function Page() { return <main dangerouslySetInnerHTML={{ __html: ${sourceExpression} }} />; }`
    });

    expect(result.findings.find((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toMatchObject({
      severity: "MEDIUM"
    });
  });

  it("detects member expression dangerouslySetInnerHTML sources", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        "export default function Page({ post }) {",
        "  return <main dangerouslySetInnerHTML={{ __html: post.content }} />;",
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

  it("does not flag normal JSX text or unrelated html props", async () => {
    const result = await scanFixture({
      "app/page.tsx": [
        "export default function Page({ html }) {",
        "  return <><div>{html}</div><Component html={html} /></>;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "xss/dangerously-set-inner-html")).toBe(false);
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

  it("preserves dangerouslySetInnerHTML context tuning for example and template paths", async () => {
    const result = await scanFixture({
      "examples/demo/app/page.tsx": "export default () => <div dangerouslySetInnerHTML={{ __html: markdownHtml }} />;",
      "templates/default/app/page.tsx": "export default () => <div dangerouslySetInnerHTML={{ __html: post.content }} />;"
    });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "examples/demo/app/page.tsx",
          ruleId: "xss/dangerously-set-inner-html",
          severity: "MEDIUM",
          confidence: "LOW",
          originalConfidence: "HIGH",
          context: "example-code"
        }),
        expect.objectContaining({
          filePath: "templates/default/app/page.tsx",
          ruleId: "xss/dangerously-set-inner-html",
          severity: "MEDIUM",
          confidence: "LOW",
          originalConfidence: "HIGH",
          context: "template-code"
        })
      ])
    );
  });

  it("keeps dangerouslySetInnerHTML context tuning off when requested", async () => {
    const result = await scanFixture(
      {
        "templates/default/app/page.tsx": "export default () => <div dangerouslySetInnerHTML={{ __html: post.content }} />;"
      },
      { contextTuning: "off" }
    );
    const finding = result.findings.find((item) => item.ruleId === "xss/dangerously-set-inner-html");

    expect(finding).toMatchObject({
      severity: "MEDIUM",
      confidence: "HIGH",
      context: "template-code"
    });
    expect(finding?.originalConfidence).toBeUndefined();
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
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "export async function POST() {",
        "  const allowed = await checkRateLimit();",
        "  if (!allowed) return Response.json({}, { status: 429 });",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("does not treat a rate-limit-looking identifier as an implemented limiter", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": "const rateLimit = true; export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
  });

  it("does not flag login endpoints with route-level rate-limit helpers", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "export async function POST() {",
        "  const allowed = await checkRateLimit();",
        "  if (!allowed) return Response.json({ error: 'too many requests' }, { status: 429 });",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("does not flag login endpoints with route-level Upstash or Redis limiter usage", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "import { Ratelimit } from '@upstash/ratelimit';",
        "const limiter = new Ratelimit();",
        "export async function POST() {",
        "  const result = await limiter.limit('ip');",
        "  return Response.json({ ok: result.success });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("does not flag login endpoints covered by rate-limited middleware matcher", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "export function middleware() {",
        "  const allowed = rateLimit();",
        "  if (!allowed) return Response.json({ error: 'too many requests' }, { status: 429 });",
        "}",
        "export const config = { matcher: ['/api/login/:path*'] };"
      ].join("\n"),
      "app/api/login/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("does not flag auth login endpoints covered by broad auth middleware rate-limit matcher", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "export function middleware() {",
        "  const allowed = applyRateLimit();",
        "  if (!allowed) return Response.json({ error: 'too many requests' }, { status: 429 });",
        "}",
        "export const config = { matcher: ['/api/auth/:path*'] };"
      ].join("\n"),
      "app/api/auth/login/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("keeps login rate-limit findings when limiter appears only in an unrelated file", async () => {
    const result = await scanFixture({
      "lib/rate-limit.ts": "export function rateLimit() { return true; }",
      "app/api/login/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
  });

  it("does not treat login or register UI paths as authentication endpoints", async () => {
    const result = await scanFixture({
      "app/login/page.tsx": "export default function LoginPage() { return <form><input name='email' /></form>; }",
      "components/register-form.tsx": "export function RegisterForm() { return <form>Register</form>; }",
      "app/(auth)/signin/page.tsx": "export default function SignInPage() { return <main>Sign in</main>; }",
      "app/api/author/route.ts": "export async function GET() { return Response.json({ author: true }); }",
      "app/api/registering/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("ignores rate-limit words in comments and UI strings", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "// rateLimit, limiter, and status 429 are documented here only.",
        "export async function POST() {",
        "  const message = 'Too Many Requests';",
        "  return Response.json({ message });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
  });

  it("covers Pages Router auth endpoints and structural 429 responses", async () => {
    const result = await scanFixture({
      "pages/api/login.ts": [
        "export default function handler(req, res) {",
        "  if (blocked) return res.status(429).json({ error: 'blocked' });",
        "  return res.json({ ok: true });",
        "}"
      ].join("\n"),
      "src/pages/api/register.ts": [
        "export default function handler(req, res) {",
        "  res.statusCode = 429;",
        "  return res.end();",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("recognizes App Router new Response 429 responses", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "export async function POST() {",
        "  if (blocked) return new Response('Too Many Requests', { status: 429 });",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(false);
  });

  it("detects password handling without hashing libraries", async () => {
    const result = await scanFixture({ "app/api/register/route.ts": "const password = body.password;" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(true);
  });

  it("detects destructured password from request json without hashing", async () => {
    const result = await scanFixture({
      "app/api/register/route.ts": "const { password } = await request.json();"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(true);
  });

  it("detects formData password reads without hashing", async () => {
    const result = await scanFixture({
      "app/api/register/route.ts": 'const password = formData.get("password");'
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(true);
  });

  it("does not flag password handling when hashing is used in the file", async () => {
    const bcryptResult = await scanFixture({
      "app/api/register/route.ts": "const password = body.password; await bcrypt.hash(password, 12);"
    });
    const argonResult = await scanFixture({
      "app/api/register/route.ts": "const password = body.password; await argon2.hash(password);"
    });
    const scryptResult = await scanFixture({
      "app/api/register/route.ts": "const password = body.password; crypto.scrypt(password, salt, 64, () => {});"
    });

    for (const result of [bcryptResult, argonResult, scryptResult]) {
      expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(false);
    }
  });

  it("does not flag password UI labels, placeholders, props, or type fields", async () => {
    const result = await scanFixture({
      "app/components/password-field.tsx": [
        "type Props = { password?: string };",
        "interface LoginForm { password: string }",
        "export function PasswordField({ password }: Props) {",
        "  return <label>Password<input placeholder=\"Password\" value={password} /></label>;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(false);
  });

  it("does not flag unrelated URL credential validation as password hashing risk", async () => {
    const result = await scanFixture({
      "lib/github-url.ts": "const url = new URL(input); if (url.username || url.password) return false;"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(false);
  });

  it("flags password handling when bcrypt is installed but unused", async () => {
    const result = await scanFixture({
      "package.json": '{"dependencies":{"bcrypt":"latest"}}',
      "app/api/register/route.ts": "const password = body.password;"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/password-without-hashing-library")).toBe(true);
  });

  it("does not flag plain raw SQL template assignments without a query sink", async () => {
    const result = await scanFixture({ "app/api/users/route.ts": "const sql = `SELECT * FROM users WHERE id = ${id}`;" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("flags a raw SQL template after it reaches a query sink through a variable", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "const sql = `SELECT * FROM users WHERE id = ${id}`;",
        "db.query(sql);"
      ].join("\n")
    });

    const findings = result.findings.filter((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(1);
  });

  it("keeps tracking a raw SQL alias after a recognized sink", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "const sql = `SELECT * FROM users WHERE id = ${id}`;",
        "db.query(sql);",
        "db.execute(sql);"
      ].join("\n")
    });

    const findings = result.findings.filter((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(2);
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

  it("records a bounded request source path for a raw SQL query sink", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function GET(request) {",
        "  const body = await request.json();",
        "  const email = body.email;",
        "  db.query(`SELECT * FROM users WHERE email = ${email}`);",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(finding?.evidencePath).toBe("request.json() -> email");
  });

  it("tracks a raw SQL query value through two same-function aliases", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function GET(request) {",
        "  const body = await request.json();",
        "  const email = body.email;",
        "  const query = `SELECT * FROM users WHERE email = ${email}`;",
        "  const alias = query;",
        "  const second = alias;",
        "  db.query(second);",
        "}"
      ].join("\n")
    });

    const findings = result.findings.filter((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidencePath).toBe("request.json() -> email -> alias -> second");
  });

  it("detects SQL string concatenation at a recognized query sink", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function GET(request) {",
        "  const body = await request.json();",
        "  const id = body.id;",
        '  db.query("SELECT * FROM users WHERE id = " + id);',
        "}"
      ].join("\n")
    });

    const finding = result.findings.find((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(finding?.evidencePath).toBe("request.json() -> id");
  });

  it("records the supported request-source paths for raw SQL sinks", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function POST(request, { params }) {",
        "  const formData = await request.formData();",
        "  db.query(`SELECT * FROM users WHERE id = ${formData.get('id')}`);",
        "  db.query(`SELECT * FROM users WHERE id = ${request.body.id}`);",
        "  db.query(`SELECT * FROM users WHERE id = ${request.query.id}`);",
        "  db.query(`SELECT * FROM users WHERE id = ${searchParams.get('id')}`);",
        "  db.query(`SELECT * FROM users WHERE id = ${params.id}`);",
        "}"
      ].join("\n")
    });

    const findings = result.findings.filter((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(findings.map((finding) => finding.evidencePath)).toEqual([
      "request.formData() -> get()",
      "request.body -> id",
      "request.query -> id",
      "searchParams.get()",
      "params -> id"
    ]);
  });

  it("does not carry a raw SQL query value past reassignment or a function boundary", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function GET(request) {",
        "  const body = await request.json();",
        "  const id = body.id;",
        "  let query = `SELECT * FROM users WHERE id = ${id}`;",
        '  query = "SELECT * FROM users";',
        "  db.query(query);",
        "  function execute(value) { db.query(value); }",
        "  execute(`SELECT * FROM users WHERE id = ${id}`);",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((candidate) => candidate.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("does not carry a raw SQL query value through an unknown call escape", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "const query = `SELECT * FROM users WHERE id = ${id}`;",
        "sendToLogger(query);",
        "db.query(query);"
      ].join("\n")
    });

    expect(result.findings.some((candidate) => candidate.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("does not infer raw SQL flow beyond two aliases or across a function boundary", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "const query = `SELECT * FROM users WHERE id = ${id}`;",
        "const first = query;",
        "const second = first;",
        "const third = second;",
        "db.query(third);",
        "function execute() { db.query(query); }",
        "execute();"
      ].join("\n")
    });

    expect(result.findings.some((candidate) => candidate.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("detects raw SQL interpolation passed to common query sink names", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "db.query(`SELECT * FROM users WHERE id = ${id}`);",
        "connection.query(`SELECT * FROM users WHERE email = ${email}`);",
        "connection.execute(`UPDATE users SET name = ${name} WHERE id = ${id}`);",
        "pool.query(`DELETE FROM sessions WHERE user_id = ${userId}`);",
        "client.query(`INSERT INTO audit_logs (message) VALUES (${message})`);"
      ].join("\n")
    });

    const findings = result.findings.filter((finding) => finding.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(5);
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
      "app/api/users/route.ts": [
        "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;",
        "await prisma.$executeRaw`DELETE FROM users WHERE id = ${id}`;",
        "await db.$queryRaw`SELECT * FROM users WHERE email = ${email}`;",
        "await db.$executeRaw`UPDATE users SET name = ${name} WHERE id = ${id}`;"
      ].join("\n")
    });

    const findings = result.findings.filter((finding) => finding.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(4);
  });

  it("adds a bounded source path to a raw SQL tagged template when it is proven", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "export async function GET(request) {",
        "  await prisma.$queryRaw`SELECT * FROM users WHERE id = ${request.json()}`;",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(finding?.evidencePath).toBe("request.json()");
  });

  it("detects raw SQL passed to query-style raw APIs", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "prisma.$queryRaw(`SELECT * FROM users WHERE id = ${id}`);",
        "prisma.$executeRaw(`DELETE FROM users WHERE id = ${id}`);"
      ].join("\n")
    });

    const findings = result.findings.filter((candidate) => candidate.ruleId === "injection/raw-sql-concat");
    expect(findings).toHaveLength(2);
  });

  it("does not flag static or parameterized query calls", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        'db.query("SELECT * FROM users");',
        'db.query("SELECT * " + "FROM users");',
        'db.query("SELECT * FROM users WHERE id = ?", [id]);',
        'db.query("SELECT * FROM users WHERE id = $1", [id]);',
        'const query = "SELECT * FROM users WHERE id = $1";',
        'db.query(query, [id]);'
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("does not flag static SQL concatenated with a numeric literal", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": 'db.query("SELECT * FROM users LIMIT " + 10);'
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/raw-sql-concat")).toBe(false);
  });

  it("preserves raw SQL API risk and context tuning for non-production contexts", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "db.query(`SELECT * FROM users WHERE id = ${id}`);",
      "examples/demo/app/api/users/route.ts": "db.query(`SELECT * FROM users WHERE id = ${id}`);",
      "templates/default/app/api/users/route.ts": "db.query(`SELECT * FROM users WHERE id = ${id}`);",
      "apps/web/app/components/data-table.tsx": "db.query(`SELECT * FROM users WHERE id = ${id}`);"
    });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "app/api/users/route.ts",
          ruleId: "injection/raw-sql-concat",
          severity: "HIGH",
          confidence: "MEDIUM",
          context: "api-code"
        }),
        expect.objectContaining({
          filePath: "examples/demo/app/api/users/route.ts",
          ruleId: "injection/raw-sql-concat",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "example-code"
        }),
        expect.objectContaining({
          filePath: "templates/default/app/api/users/route.ts",
          ruleId: "injection/raw-sql-concat",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "template-code"
        }),
        expect.objectContaining({
          filePath: "apps/web/app/components/data-table.tsx",
          ruleId: "injection/raw-sql-concat",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "app-code"
        })
      ])
    );
  });

  it("keeps raw SQL context tuning off when requested", async () => {
    const result = await scanFixture(
      {
        "templates/default/app/api/users/route.ts": "db.query(`SELECT * FROM users WHERE id = ${id}`);"
      },
      { contextTuning: "off" }
    );
    const finding = result.findings.find((item) => item.ruleId === "injection/raw-sql-concat");

    expect(finding).toMatchObject({
      severity: "HIGH",
      confidence: "MEDIUM",
      context: "template-code"
    });
    expect(finding?.originalSeverity).toBeUndefined();
  });

  it("detects missing security headers in Next.js apps", async () => {
    const result = await scanFixture({ "package.json": '{"name":"demo"}', "app/page.tsx": "export default function Page() { return null; }" });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(true);
  });

  it("does not flag missing security headers when headers are configured", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default function Page() { return null; }",
      "next.config.js": [
        "module.exports = { async headers() { return [{ source: '/(.*)', headers: [",
        "{ key: 'Content-Security-Policy', value: \"default-src 'self'; frame-ancestors 'none'\" },",
        "{ key: 'X-Content-Type-Options', value: 'nosniff' },",
        "{ key: 'Referrer-Policy', value: 'no-referrer' },",
        "{ key: 'Permissions-Policy', value: 'camera=()' }",
        "] }] } }"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(false);
  });

  it("detects partial security headers in next config", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default function Page() { return null; }",
      "next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] } }"
    });
    const finding = result.findings.find((item) => item.ruleId === "headers/missing-security-headers");

    expect(finding).toMatchObject({
      description: expect.stringContaining("Content-Security-Policy")
    });
  });

  it("detects partial security headers in middleware", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default function Page() { return null; }",
      "middleware.ts": [
        "import { NextResponse } from 'next/server';",
        "export function middleware() {",
        "  const response = NextResponse.next();",
        "  response.headers.set('X-Frame-Options', 'DENY');",
        "  response.headers.set('X-Content-Type-Options', 'nosniff');",
        "  return response;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(true);
  });

  it("does not flag missing security headers when full headers are configured in middleware", async () => {
    const result = await scanFixture({
      "app/page.tsx": "export default function Page() { return null; }",
      "middleware.ts": [
        "import { NextResponse } from 'next/server';",
        "export function middleware() {",
        "  const response = NextResponse.next();",
        "  response.headers.set('Content-Security-Policy', \"default-src 'self'; frame-ancestors 'none'\");",
        "  response.headers.set('X-Content-Type-Options', 'nosniff');",
        "  response.headers.set('Referrer-Policy', 'no-referrer');",
        "  response.headers.set('Permissions-Policy', 'camera=()');",
        "  return response;",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "headers/missing-security-headers")).toBe(false);
  });

  it("detects NEXT_PUBLIC secret-like variables", async () => {
    const result = await scanFixture({ ".env": "NEXT_PUBLIC_STRIPE_SECRET=sk_test_123" });

    expect(result.findings.some((finding) => finding.ruleId === "secrets/next-public-secret")).toBe(true);
  });

  it("describes NEXT_PUBLIC matches as review signals", async () => {
    const result = await scanFixture({ ".env": "NEXT_PUBLIC_STRIPE_SECRET=sk_test_123" });
    const finding = result.findings.find((item) => item.ruleId === "secrets/next-public-secret");

    expect(finding).toBeDefined();
    expect(finding?.title).toBe("NEXT_PUBLIC secret-like value requires review");
    expect(finding?.severity).toBe("HIGH");
    expect(finding?.confidence).toBe("MEDIUM");
    expect(finding?.description).toContain("review signal");
    expect(finding?.description).toContain("not proof");
    expect(finding?.recommendation).toContain("Review the assigned value");
  });

  it("keeps intentionally public token names as reviewable false-positive candidates", async () => {
    const result = await scanFixture({ ".env": "NEXT_PUBLIC_ANALYTICS_TOKEN=public-client-id" });
    const finding = result.findings.find((item) => item.ruleId === "secrets/next-public-secret");

    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe("MEDIUM");
    expect(finding?.description).toContain("not proof");
    expect(finding?.recommendation).toContain("intentionally public");
  });

  it("detects register endpoints without rate limiting", async () => {
    const result = await scanFixture({ "app/api/register/route.ts": "export async function POST() { return Response.json({ ok: true }); }" });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(true);
  });

  it("does not flag register endpoints with rate limiting", async () => {
    const result = await scanFixture({
      "app/api/register/route.ts": [
        "export async function POST() {",
        "  const allowed = await checkRateLimit();",
        "  if (!allowed) return Response.json({}, { status: 429 });",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("does not flag register endpoints with route-level 429 rate-limit response", async () => {
    const result = await scanFixture({
      "app/api/register/route.ts": [
        "export async function POST() {",
        "  if (blocked) return Response.json({ error: 'too many requests' }, { status: 429 });",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("does not flag register endpoints covered by rate-limited middleware matcher", async () => {
    const result = await scanFixture({
      "src/middleware.ts": [
        "export function middleware() {",
        "  const limiter = redis;",
        "  const result = limiter.limit('ip');",
        "  return Response.json({ ok: result });",
        "}",
        "export const config = { matcher: '/api/register/:path*' };"
      ].join("\n"),
      "app/api/register/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/register-without-rate-limit")).toBe(false);
  });

  it("keeps login rate-limit findings when middleware rate-limit matcher does not cover the route", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "export function middleware() {",
        "  const allowed = rateLimit();",
        "  return Response.json({ ok: allowed });",
        "}",
        "export const config = { matcher: ['/api/admin/:path*'] };"
      ].join("\n"),
      "app/api/login/route.ts": "export async function POST() { return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
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

  it("detects imported exec calls", async () => {
    const result = await scanFixture({ "index.ts": "import { exec } from 'node:child_process';\nexec('ls');" });
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");

    expect(commandFindings).toHaveLength(2);
    expect(commandFindings.map((finding) => finding.evidence)).toEqual([
      "import { exec } from 'node:child_process';",
      "exec('ls');"
    ]);
  });

  it("records a bounded request JSON source path for command sinks", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  exec(command);",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "injection/command-exec" && candidate.evidence?.includes("exec(command)")
    );
    expect(finding?.evidencePath).toBe("request.json() -> command");
  });

  it("records a request form-data source path for command sinks", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const formData = await request.formData();",
        "  const command = formData.get('command');",
        "  exec(command);",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "injection/command-exec" && candidate.evidence?.includes("exec(command)")
    );
    expect(finding?.evidencePath).toBe("request.formData() -> get()");
  });

  it("records req query, search params, and route parameter sources", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function GET(req, { params }) {",
        "  const queryCommand = req.query.command;",
        "  const searchCommand = searchParams.get('command');",
        "  const { routeCommand } = params;",
        "  exec(queryCommand);",
        "  exec(searchCommand);",
        "  exec(routeCommand);",
        "}"
      ].join("\n")
    });

    const sinkFindings = result.findings.filter(
      (finding) => finding.ruleId === "injection/command-exec" && finding.evidence?.includes("exec(")
    );
    expect(sinkFindings.map((finding) => finding.evidencePath)).toEqual([
      "req.query -> command",
      "searchParams.get()",
      "params -> routeCommand"
    ]);
  });

  it("records a search params source behind a safe fallback", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function GET() {",
        "  const command = searchParams.get('command') || 'ls';",
        "  exec(command);",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "injection/command-exec" && candidate.evidence?.includes("exec(command)")
    );
    expect(finding?.evidencePath).toBe("searchParams.get()");
  });

  it("suppresses a request-derived command sink behind an explicit early-return allowlist guard", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (![\"git\", \"ls\"].includes(command)) return Response.json({ ok: false });",
        "  exec(command);",
        "}"
      ].join("\n")
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings[0]?.evidence).toContain("import { exec }");
  });

  it("suppresses a request-derived command sink inside a positive allowlist branch", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (allowedCommands.has(command)) {",
        "    exec(command);",
        "  }",
        "}"
      ].join("\n")
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings[0]?.evidence).toContain("import { exec }");
  });

  it("does not suppress a spawn sink when later arguments still carry request data", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { spawn } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (![\"git\"].includes(command)) return Response.json({ ok: false });",
        "  spawn(command, body.args);",
        "}"
      ].join("\n")
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings.some((finding) => finding.evidence?.includes("spawn(command, body.args)"))).toBe(true);
  });

  it("keeps short aliases but stops after reassignment", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  const alias = command;",
        "  alias = 'safe';",
        "  exec(alias);",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "injection/command-exec" && candidate.evidence?.includes("exec(alias)")
    );
    expect(finding).toBeDefined();
    expect(finding?.evidencePath).toBeUndefined();
  });

  it("does not carry source facts across a function boundary", async () => {
    const result = await scanFixture({
      "app/api/debug/route.ts": [
        "import { exec } from 'node:child_process';",
        "function run(command) { exec(command); }",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  run(body.command);",
        "}"
      ].join("\n")
    });

    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "injection/command-exec" && candidate.evidence?.includes("exec(command)")
    );
    expect(finding).toBeDefined();
    expect(finding?.evidencePath).toBeUndefined();
  });

  it("detects require destructuring command execution", async () => {
    const result = await scanFixture({ "index.ts": "const { exec: run } = require('child_process');\nrun('ls');" });
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");

    expect(commandFindings).toHaveLength(2);
    expect(commandFindings.map((finding) => finding.evidence)).toEqual([
      "const { exec: run } = require('child_process');",
      "run('ls');"
    ]);
  });

  it("detects namespace and alias command execution", async () => {
    const result = await scanFixture({
      "index.ts": [
        "import * as cp from 'node:child_process';",
        "const child_process = require('child_process');",
        "cp.exec('ls');",
        "child_process.spawn('git');"
      ].join("\n")
    });
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");

    expect(commandFindings.map((finding) => finding.evidence)).toEqual([
      "cp.exec('ls');",
      "child_process.spawn('git');"
    ]);
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

  it("does not flag unrelated local exec calls", async () => {
    const result = await scanFixture({
      "index.ts": 'function exec(command) { return command; }\nexec("ls");'
    });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(false);
  });

  it("detects imported command execution after a safe exec method call on the same line", async () => {
    const result = await scanFixture({
      "index.ts": 'import { exec } from "child_process";\nregex.exec(input); exec("ls");'
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(2);
    expect(commandFindings[1]?.evidence).toBe('regex.exec(input); exec("ls");');
  });

  it("detects imported spawn after a safe exec method call on the same line", async () => {
    const result = await scanFixture({
      "index.ts": 'const { spawn } = require("child_process");\nobject.exec(); spawn("ls");'
    });

    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");
    expect(commandFindings).toHaveLength(1);
    expect(commandFindings[0]?.evidence).toBe('object.exec(); spawn("ls");');
  });

  it("detects child_process imports", async () => {
    const result = await scanFixture({ "index.ts": "import { exec } from 'child_process';" });

    expect(result.findings.some((finding) => finding.ruleId === "injection/command-exec")).toBe(true);
  });

  it("keeps command execution findings high in API code", async () => {
    const result = await scanFixture({ "app/api/debug/route.ts": "import { exec } from 'child_process';\nexec('id');" });
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");

    expect(commandFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ context: "api-code", severity: "HIGH", confidence: "MEDIUM" })
      ])
    );
  });

  it("keeps release and CLI command execution context tuning with AST findings", async () => {
    const result = await scanFixture({
      ".github/changeset-version.js": "const { exec } = require('child_process');\nexec('pnpm changeset version');",
      "cli/src/helpers/git.ts": "import * as cp from 'node:child_process';\ncp.spawn('git');"
    });
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "injection/command-exec");

    expect(commandFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          context: "release-tooling",
          severity: "LOW",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM"
        }),
        expect.objectContaining({
          context: "cli-tooling",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          originalSeverity: "HIGH"
        })
      ])
    );
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

  it("does not flag frontend file input components as upload endpoints", async () => {
    const result = await scanFixture({
      "app/components/upload-button.tsx": [
        "export function UploadButton() {",
        "  return <input type=\"file\" accept=\"image/png\" />;",
        "}"
      ].join("\n"),
      "app/media/file-card.tsx": "export function FileCard({ file }) { return <div>{file.name}</div>; }"
    });

    expect(result.findings.some((finding) => finding.category === "upload")).toBe(false);
  });

  it("does not flag upload route examples or templates as production upload endpoints", async () => {
    const result = await scanFixture({
      "examples/demo/app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }",
      "templates/default/app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.category === "upload")).toBe(false);
  });

  it("detects pages API upload handlers without validation", async () => {
    const result = await scanFixture({
      "pages/api/upload.ts": "export default async function handler(req, res) { const file = req.body.file; res.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-type-validation")).toBe(true);
    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-size-limit")).toBe(true);
  });

  it("detects root App Router upload handlers", async () => {
    const result = await scanFixture({
      "app/api/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-type-validation")).toBe(true);
    expect(result.findings.some((finding) => finding.ruleId === "upload/missing-file-size-limit")).toBe(true);
  });

  it("detects API routes without input validation", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "export async function POST(req) { const body = await req.json(); return Response.json({ ok: true }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(true);
  });

  it("detects unvalidated dynamic route parameters with bounded evidence", async () => {
    const result = await scanFixture({
      "app/api/users/[id]/route.ts": [
        "export async function GET(request, { params }) {",
        "  return Response.json({ id: params.id });",
        "}"
      ].join("\n")
    });
    const finding = result.findings.find((item) => item.ruleId === "validation/api-route-without-validation");

    expect(finding).toMatchObject({
      filePath: "app/api/users/[id]/route.ts",
      evidencePath: "params -> id"
    });
    expect(finding?.line).toBeUndefined();
    expect(finding?.column).toBeUndefined();
  });

  it("detects unvalidated Pages Router query parameters", async () => {
    const result = await scanFixture({
      "pages/api/users/[id].js": "export default function handler(req, res) { res.json({ id: req.query.id }); }"
    });
    const finding = result.findings.find((item) => item.ruleId === "validation/api-route-without-validation");

    expect(finding?.evidencePath).toBe("req.query.id");
  });

  it("detects request nextUrl search parameters with bounded evidence", async () => {
    const result = await scanFixture({
      "app/api/search/route.ts": [
        "export async function GET(request) {",
        "  const query = request.nextUrl.searchParams.get(\"q\");",
        "  return Response.json({ query });",
        "}"
      ].join("\n")
    });
    const finding = result.findings.find((item) => item.ruleId === "validation/api-route-without-validation");

    expect(finding?.evidencePath).toBe("request.nextUrl.searchParams.get()");
  });

  it("does not flag dynamic route parameters guarded by a static allowlist", async () => {
    const result = await scanFixture({
      "app/api/users/[id]/route.ts": [
        "export async function GET(request, { params }) {",
        "  if (![\"public\", \"team\"].includes(params.id)) return Response.json({ ok: false }, { status: 404 });",
        "  return Response.json({ id: params.id });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("does not flag dynamic route parameters guarded by a Set allowlist", async () => {
    const result = await scanFixture({
      "app/api/users/[id]/route.ts": [
        "const ALLOWED_IDS = new Set([\"public\", \"team\"]);",
        "export async function GET(request, { params }) {",
        "  if (!ALLOWED_IDS.has(params.id)) return Response.json({ ok: false }, { status: 404 });",
        "  return Response.json({ id: params.id });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("does not flag dynamic route parameters guarded by a static comparison", async () => {
    const result = await scanFixture({
      "app/api/users/[id]/route.ts": [
        "export async function GET(request, { params }) {",
        "  if (params.id !== \"public\") return Response.json({ ok: false }, { status: 404 });",
        "  return Response.json({ id: params.id });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("does not flag dynamic route parameters behind a visible normalization guard", async () => {
    const result = await scanFixture({
      "app/api/users/[id]/route.ts": [
        "export async function GET(request, { params }) {",
        "  if (!normalizePath(params.id)) return Response.json({ ok: false }, { status: 404 });",
        "  return Response.json({ id: params.id });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("does not crash on malformed dynamic API route syntax", async () => {
    await expect(
      scanFixture({
        "app/api/users/[id]/route.ts": "export async function GET(request, { params ) { return Response.json({ id: params.id });"
      })
    ).resolves.toBeDefined();
  });

  it("does not treat dynamic page parameters as API input", async () => {
    const result = await scanFixture({
      "app/users/[id]/page.tsx": "export default function Page({ params }) { return <p>{params.id}</p>; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
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

  it("does not treat validation words in comments or unknown wrappers as validation", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": [
        "// zod schema and validate() are mentioned here only.",
        "function validatePayload(input) { return input; }",
        "export async function POST(req) {",
        "  const body = await req.json();",
        "  validatePayload(body);",
        "  return Response.json({ ok: true });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(true);
  });

  it("recognizes common validation calls without relying on keyword text", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "const schema = { safeParse(value) { return { success: Boolean(value) }; } }; export async function POST(req) { const body = await req.json(); const parsed = schema.safeParse(body); return Response.json({ ok: parsed.success }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("does not treat JSON.parse alone as API input validation", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "export async function POST(req) { const body = await req.json(); const parsed = JSON.parse(body.payload); return Response.json({ ok: Boolean(parsed) }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(true);
  });

  it("does not treat an API helper file without a route handler as an API endpoint", async () => {
    const result = await scanFixture({
      "app/api/users/parse-input.ts": "export function parseInput(req) { return req.body; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "validation/api-route-without-validation")).toBe(false);
  });

  it("detects admin routes without auth protection", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("detects exported const admin route handlers without auth protection", async () => {
    const result = await scanFixture({
      "app/api/admin/route.ts": "export const POST = async () => Response.json({ ok: true });"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("detects pages API admin routes without auth protection", async () => {
    const result = await scanFixture({
      "pages/api/admin/users.ts": "export default function handler(req, res) { res.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("does not flag admin routes with auth protection", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": "import { getServerSession } from 'next-auth'; export async function GET() { const session = await getServerSession(); return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not treat auth words in comments or generic role values as auth intent", async () => {
    const result = await scanFixture({
      "app/api/admin/commented/route.ts": [
        "// auth(), requireAuth, and getServerSession are mentioned in this comment.",
        "export async function GET() { return Response.json({ ok: true }); }"
      ].join("\n"),
      "app/api/admin/role/route.ts": "const role = 'admin'; export async function GET() { return Response.json({ role }); }",
      "app/api/admin/profile/route.ts": "const user = getAccount(); export async function GET() { return Response.json({ role: user.role }); }",
      "app/api/admin/guard/route.ts": "export async function GET() { const user = getAccount(); if (!user?.role) return Response.json({}, { status: 401 }); return Response.json({ ok: true }); }"
    });

    expect(
      result.findings
        .filter((finding) => finding.ruleId === "auth/admin-route-without-auth")
        .map((finding) => finding.filePath)
        .sort()
    ).toEqual(["app/api/admin/commented/route.ts", "app/api/admin/profile/route.ts", "app/api/admin/role/route.ts"]);
  });

  it("recognizes common auth intent calls without imports", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": "export async function GET() { const user = requireAuth(); if (!isAdmin(user)) return Response.json({ ok: false }, { status: 403 }); return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("keeps unknown local auth wrappers as review signals", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "import { auth } from '@/lib/auth';",
        "export async function GET() {",
        "  const session = await auth();",
        "  return Response.json({ ok: Boolean(session) });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("recognizes auth imported from a known provider module", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export async function GET() {",
        "  const session = await auth();",
        "  return Response.json({ ok: Boolean(session) });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not trust an unbound auth call", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "export async function GET() {",
        "  const session = await auth();",
        "  return Response.json({ ok: Boolean(session) });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("does not trust an unrelated named export aliased to auth", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "import { unrelated as auth } from '@clerk/nextjs/server';",
        "export async function GET() {",
        "  const session = await auth();",
        "  return Response.json({ ok: Boolean(session) });",
        "}"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("keeps an admin finding when one exported handler is unprotected", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export async function GET() { await auth(); return Response.json({ ok: true }); }",
        "export async function POST() { return Response.json({ ok: true }); }"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("keeps a login finding when one exported handler is not rate limited", async () => {
    const result = await scanFixture({
      "app/api/login/route.ts": [
        "export async function POST() { await checkRateLimit(); return Response.json({ ok: true }); }",
        "export async function GET() { return Response.json({ ok: true }); }"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/login-without-rate-limit")).toBe(true);
  });

  it("does not let an unused helper protect an admin route", async () => {
    const result = await scanFixture({
      "app/api/admin/users/route.ts": [
        "function getSession() { return requireAuth(); }",
        "export async function GET() { return Response.json({ users: [] }); }"
      ].join("\n")
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("does not flag admin routes covered by auth middleware matcher", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export function middleware() {",
        "  const session = auth();",
        "  if (!session || !session.role) return Response.json({ ok: false }, { status: 401 });",
        "}",
        "export const config = { matcher: ['/api/admin/:path*'] };"
      ].join("\n"),
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not flag admin routes covered by a same-app proxy matcher", async () => {
    const result = await scanFixture({
      "proxy.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export function proxy() { return auth(); }",
        "export const config = { matcher: '/api/admin/:path*' };"
      ].join("\n"),
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }",
      "apps/other/app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(
      result.findings
        .filter((finding) => finding.ruleId === "auth/admin-route-without-auth")
        .map((finding) => finding.filePath)
    ).toEqual(["apps/other/app/api/admin/route.ts"]);
  });

  it("does not flag admin routes covered by broad API auth middleware matcher", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "export function middleware() {",
        "  const user = currentUser();",
        "  if (!user?.permission) return Response.json({ ok: false }, { status: 401 });",
        "}",
        "export const config = { matcher: '/api/:path*' };"
      ].join("\n"),
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not treat an unknown auth middleware wrapper as route protection", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "import { auth } from '@/lib/auth';",
        "export function middleware() { return auth(); }",
        "export const config = { matcher: '/api/admin/:path*' };"
      ].join("\n"),
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("applies nested middleware only to routes in the same app", async () => {
    const result = await scanFixture({
      "apps/web/middleware.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export function middleware() { return auth(); }",
        "export const config = { matcher: '/api/admin/:path*' };"
      ].join("\n"),
      "apps/web/app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }",
      "apps/other/app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(
      result.findings
        .filter((finding) => finding.ruleId === "auth/admin-route-without-auth")
        .map((finding) => finding.filePath)
    ).toEqual(["apps/other/app/api/admin/route.ts"]);
  });

  it("keeps admin route findings when auth middleware matcher does not cover the route", async () => {
    const result = await scanFixture({
      "middleware.ts": [
        "import { auth } from '@clerk/nextjs/server';",
        "export function middleware() {",
        "  const session = auth();",
        "  return Response.json({ ok: Boolean(session) });",
        "}",
        "export const config = { matcher: ['/api/public/:path*'] };"
      ].join("\n"),
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ users: [] }); }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(true);
  });

  it("does not flag admin UI component paths as admin routes", async () => {
    const result = await scanFixture({
      "app/(app)/admin/components/sidebar.tsx": "export function AdminSidebar() { return <aside>Admin</aside>; }",
      "components/admin-card.tsx": "export function AdminCard() { return <section>Admin dashboard</section>; }",
      "app/dashboard/page.tsx": "export default function Dashboard() { return <main>Dashboard</main>; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not flag admin API files without route handler exports", async () => {
    const result = await scanFixture({
      "app/api/admin/helpers.ts": "export function getAdminLabel() { return 'admin'; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "auth/admin-route-without-auth")).toBe(false);
  });

  it("does not flag admin route examples or templates as production admin routes", async () => {
    const result = await scanFixture({
      "examples/demo/app/api/admin/route.ts": "export async function GET() { return Response.json({ ok: true }); }",
      "templates/default/app/api/admin/route.ts": "export async function GET() { return Response.json({ ok: true }); }"
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

  it("detects missing poweredByHeader in app-level monorepo Next.js configs", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"next":"latest"}}',
      "apps/web/next.config.js": "module.exports = { reactStrictMode: true };",
      "apps/web/app/page.tsx": "export default function Page() { return <main />; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/next-powered-by-header")).toBe(true);
  });

  it("does not flag example, template, or fixture Next.js configs as production app configs", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"next":"latest"}}',
      "examples/demo/next.config.js": "module.exports = { reactStrictMode: true };",
      "examples/demo/app/page.tsx": "export default function Page() { return <main />; }",
      "templates/default/next.config.js": "module.exports = { reactStrictMode: true };",
      "templates/default/app/page.tsx": "export default function Page() { return <main />; }",
      "packages/ui/fixtures/next-app/next.config.js": "module.exports = { reactStrictMode: true };",
      "packages/ui/fixtures/next-app/app/page.tsx": "export default function Page() { return <main />; }"
    });

    expect(result.findings.some((finding) => finding.ruleId === "config/next-powered-by-header")).toBe(false);
  });

  it("does not flag package-level Next.js configs without app structure", async () => {
    const result = await scanFixture({
      "package.json": '{"name":"demo","dependencies":{"next":"latest"}}',
      "packages/ui/next.config.js": "module.exports = { reactStrictMode: true };",
      "packages/ui/src/button.tsx": "export function Button() { return <button />; }"
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
