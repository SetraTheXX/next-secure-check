import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanProject } from "@next-secure-check/core";
import type { Finding, ScanOptions, ScanResult } from "@next-secure-check/core";
import { describe, expect, it } from "vitest";
import { getBuiltInRules } from "./index.js";

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-regression-"));
}

async function scanFixture(files: Record<string, string>, options: Pick<ScanOptions, "contextTuning"> = {}): Promise<ScanResult> {
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

function findingsFor(result: ScanResult, ruleId: string): Finding[] {
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

function filesFor(result: ScanResult, ruleId: string): string[] {
  return findingsFor(result, ruleId)
    .map((finding) => finding.filePath)
    .sort();
}

describe("v0.3 regression fixtures", () => {
  it("keeps shadcn-style monorepo component and registry paths separate from runtime API risk", async () => {
    const result = await scanFixture({
      "apps/v4/app/(app)/(styles)/admin-card.tsx": "export function AdminCard() { return <section>Admin upload settings</section>; }",
      "apps/v4/app/(app)/components/upload-dropzone.tsx": "export function UploadDropzone() { return <input type=\"file\" />; }",
      "apps/v4/app/(app)/components/preview.tsx": "export function Preview({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }",
      "apps/v4/registry/new-york/ui/admin-upload-card.tsx": "export function AdminUploadCard() { return <div>Admin Upload</div>; }",
      "apps/v4/registry/new-york/ui/preview.tsx": "export function RegistryPreview({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }"
    });

    expect(findingsFor(result, "auth/admin-route-without-auth")).toEqual([]);
    expect(result.findings.filter((finding) => finding.category === "upload")).toEqual([]);
    expect(findingsFor(result, "auth/password-without-hashing-library")).toEqual([]);
    expect(findingsFor(result, "xss/dangerously-set-inner-html")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "apps/v4/app/(app)/components/preview.tsx",
          context: "app-code",
          confidence: "LOW",
          originalConfidence: "HIGH"
        }),
        expect.objectContaining({
          filePath: "apps/v4/registry/new-york/ui/preview.tsx",
          context: "template-code",
          confidence: "LOW",
          originalConfidence: "HIGH"
        })
      ])
    );
  });

  it("keeps CLI tooling command execution tuned in standard mode and aggressive with tuning off", async () => {
    const files = {
      "cli/src/helpers/git.ts": "import * as cp from 'node:child_process';\ncp.spawn('git', ['status']);"
    };

    const standard = await scanFixture(files);
    const aggressive = await scanFixture(files, { contextTuning: "off" });

    expect(findingsFor(standard, "injection/command-exec")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "cli/src/helpers/git.ts",
          context: "cli-tooling",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          originalSeverity: "HIGH"
        })
      ])
    );
    expect(findingsFor(aggressive, "injection/command-exec")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "cli/src/helpers/git.ts",
          context: "cli-tooling",
          severity: "HIGH",
          confidence: "MEDIUM"
        })
      ])
    );
    expect(findingsFor(aggressive, "injection/command-exec").some((finding) => finding.originalSeverity !== undefined)).toBe(false);
  });

  it("keeps release tooling command execution low in standard mode and untuned with tuning off", async () => {
    const files = {
      ".github/changeset-version.js": "const { exec } = require('child_process');\nexec('pnpm changeset version');"
    };

    const standard = await scanFixture(files);
    const aggressive = await scanFixture(files, { contextTuning: "off" });

    for (const finding of findingsFor(standard, "injection/command-exec")) {
      expect(finding).toMatchObject({
        filePath: ".github/changeset-version.js",
        context: "release-tooling",
        severity: "LOW",
        confidence: "LOW",
        originalSeverity: "HIGH"
      });
    }
    for (const finding of findingsFor(aggressive, "injection/command-exec")) {
      expect(finding).toMatchObject({
        filePath: ".github/changeset-version.js",
        context: "release-tooling",
        severity: "HIGH"
      });
      expect(finding.originalSeverity).toBeUndefined();
    }
  });

  it("preserves dangerouslySetInnerHTML signal, sanitizer exclusions, and component confidence tuning", async () => {
    const result = await scanFixture({
      "app/profile/page.tsx": "export default function Page({ searchParams }) { return <main dangerouslySetInnerHTML={{ __html: searchParams.preview }} />; }",
      "app/static/page.tsx": "export default () => <div dangerouslySetInnerHTML={{ __html: \"<p>Static copy</p>\" }} />;",
      "app/sanitized/page.tsx": "export default function Page({ markdown }) { return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(markdown) }} />; }",
      "apps/v4/app/(app)/components/preview.tsx": "export function Preview({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }",
      "apps/v4/registry/new-york/ui/preview.tsx": "export function RegistryPreview({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }"
    });

    expect(filesFor(result, "xss/dangerously-set-inner-html")).toEqual([
      "app/profile/page.tsx",
      "apps/v4/app/(app)/components/preview.tsx",
      "apps/v4/registry/new-york/ui/preview.tsx"
    ]);
    expect(findingsFor(result, "xss/dangerously-set-inner-html")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "app/profile/page.tsx",
          context: "app-code",
          confidence: "HIGH"
        }),
        expect.objectContaining({
          filePath: "apps/v4/app/(app)/components/preview.tsx",
          context: "app-code",
          confidence: "LOW",
          originalConfidence: "HIGH"
        }),
        expect.objectContaining({
          filePath: "apps/v4/registry/new-york/ui/preview.tsx",
          context: "template-code",
          confidence: "LOW",
          originalConfidence: "HIGH"
        })
      ])
    );
  });

  it("preserves raw SQL sink-only detection", async () => {
    const result = await scanFixture({
      "app/api/users/route.ts": "db.query(`SELECT * FROM users WHERE email = ${email}`);",
      "app/api/plain-template/route.ts": "const sql = `SELECT * FROM users WHERE id = ${id}`;",
      "app/api/logs/route.ts": "console.log(`SELECT * FROM users WHERE id = ${id}`);",
      "app/api/parameterized/route.ts": "db.query(\"SELECT * FROM users WHERE id = $1\", [id]);"
    });

    expect(findingsFor(result, "injection/raw-sql-concat")).toEqual([
      expect.objectContaining({
        filePath: "app/api/users/route.ts",
        context: "api-code",
        severity: "HIGH"
      })
    ]);
  });

  it("preserves password handling signal and common UI/type/hash exclusions", async () => {
    const result = await scanFixture({
      "app/api/register/route.ts": "const body = await request.json();\nconst password = body.password;",
      "pages/api/register.ts": "export default function handler(req, res) { const password = req.body.password; res.json({ ok: true }); }",
      "app/components/password-field.tsx": [
        "type Props = { password?: string };",
        "interface LoginForm { password: string }",
        "export function PasswordField({ password }: Props) {",
        "  return <label>Password<input type=\"password\" placeholder=\"Password\" value={password} /></label>;",
        "}"
      ].join("\n"),
      "app/api/secure-register/route.ts": "const body = await request.json();\nconst password = body.password;\nawait bcrypt.hash(password, 12);"
    });

    expect(filesFor(result, "auth/password-without-hashing-library")).toEqual([
      "app/api/register/route.ts",
      "pages/api/register.ts"
    ]);
  });

  it("preserves admin route detection without flagging admin UI or authenticated handlers", async () => {
    const result = await scanFixture({
      "app/api/admin/route.ts": "export async function GET() { return Response.json({ ok: true }); }",
      "app/(app)/admin/components/sidebar.tsx": "export function AdminSidebar() { return <aside>Admin</aside>; }",
      "app/api/admin/secure/route.ts": "import { getServerSession } from 'next-auth';\nexport async function GET() { const session = await getServerSession(); return Response.json({ ok: Boolean(session) }); }"
    });

    expect(filesFor(result, "auth/admin-route-without-auth")).toEqual(["app/api/admin/route.ts"]);
  });

  it("preserves upload endpoint validation without flagging frontend upload components", async () => {
    const result = await scanFixture({
      "app/api/upload/route.ts": "export async function POST(req) { const data = await req.formData(); return Response.json({ ok: true }); }",
      "app/components/upload-dropzone.tsx": "export function UploadDropzone() { return <input type=\"file\" accept=\"image/png\" />; }",
      "app/api/secure-upload/route.ts": "export async function POST(req) { const data = await req.formData(); if (file.type === 'image/png' && file.size < 1000000) return Response.json({ ok: true }); }"
    });

    expect(findingsFor(result, "upload/missing-file-size-limit")).toEqual([
      expect.objectContaining({ filePath: "app/api/upload/route.ts" })
    ]);
    expect(findingsFor(result, "upload/missing-file-type-validation")).toEqual([
      expect.objectContaining({ filePath: "app/api/upload/route.ts" })
    ]);
  });

  it("preserves powered-by-header config scope for app configs while ignoring examples, templates, fixtures, and packages", async () => {
    const result = await scanFixture({
      "package.json": "{\"name\":\"demo\",\"dependencies\":{\"next\":\"latest\"}}",
      "app/page.tsx": "export default function Page() { return <main />; }",
      "next.config.js": "module.exports = { reactStrictMode: true };",
      "apps/web/app/page.tsx": "export default function Page() { return <main />; }",
      "apps/web/next.config.js": "module.exports = { reactStrictMode: true };",
      "examples/demo/app/page.tsx": "export default function Page() { return <main />; }",
      "examples/demo/next.config.js": "module.exports = { reactStrictMode: true };",
      "templates/default/app/page.tsx": "export default function Page() { return <main />; }",
      "templates/default/next.config.js": "module.exports = { reactStrictMode: true };",
      "packages/ui/fixtures/next-app/app/page.tsx": "export default function Page() { return <main />; }",
      "packages/ui/fixtures/next-app/next.config.js": "module.exports = { reactStrictMode: true };",
      "packages/ui/next.config.js": "module.exports = { reactStrictMode: true };",
      "packages/ui/src/button.tsx": "export function Button() { return <button />; }"
    });

    expect(filesFor(result, "config/next-powered-by-header")).toEqual(["apps/web/next.config.js", "next.config.js"]);
  });
});
