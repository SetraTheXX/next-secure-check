import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
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
  try {
    await Promise.all(
      Object.entries(files).map(async ([filePath, content]) => {
        const absolutePath = path.join(root, filePath);
        await mkdir(path.dirname(absolutePath), { recursive: true });
        await writeFile(absolutePath, content);
      })
    );

    return await scanProject(root, { contextTuning: options.contextTuning, rules: getBuiltInRules() });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function findingsFor(result: ScanResult, ruleId: string): Finding[] {
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

function filesFor(result: ScanResult, ruleId: string): string[] {
  return findingsFor(result, ruleId)
    .map((finding) => finding.filePath)
    .sort();
}

type CommandFlowFixture = {
  name: string;
  filePath: string;
  content: string;
  sinkMarker: string;
  expectedFinding?: boolean;
  expectedEvidencePath?: string;
};

const COMMAND_FLOW_FIXTURES: CommandFlowFixture[] = [
  {
    name: "direct request json",
    filePath: "app/api/direct-json/route.ts",
    content: "import { exec } from 'node:child_process';\nexec(request.json());",
    sinkMarker: "exec(request.json())",
    expectedEvidencePath: "request.json()"
  },
  {
    name: "request json property",
    filePath: "app/api/json-property/route.ts",
    content: "import { exec } from 'node:child_process';\nconst body = await request.json();\nexec(body.command);",
    sinkMarker: "exec(body.command)",
    expectedEvidencePath: "request.json() -> command"
  },
  {
    name: "one identifier alias",
    filePath: "app/api/json-alias/route.ts",
    content: "import { exec } from 'node:child_process';\nconst body = await request.json();\nconst command = body.command;\nconst alias = command;\nexec(alias);",
    sinkMarker: "exec(alias)",
    expectedEvidencePath: "request.json() -> command -> alias"
  },
  {
    name: "two identifier aliases",
    filePath: "app/api/json-two-alias/route.ts",
    content: "import { exec } from 'node:child_process';\nconst body = await request.json();\nconst command = body.command;\nconst alias = command;\nconst second = alias;\nexec(second);",
    sinkMarker: "exec(second)",
    expectedEvidencePath: "request.json() -> command -> alias -> second"
  },
  {
    name: "direct form data",
    filePath: "app/api/direct-form/route.ts",
    content: "import { exec } from 'node:child_process';\nexec(request.formData());",
    sinkMarker: "exec(request.formData())",
    expectedEvidencePath: "request.formData()"
  },
  {
    name: "form data get",
    filePath: "app/api/form-get/route.ts",
    content: "import { exec } from 'node:child_process';\nconst formData = await request.formData();\nconst command = formData.get('command');\nexec(command);",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "request.formData() -> get()"
  },
  {
    name: "request body member",
    filePath: "app/api/request-body/route.ts",
    content: "import { exec } from 'node:child_process';\nexec(request.body.command);",
    sinkMarker: "exec(request.body.command)",
    expectedEvidencePath: "request.body -> command"
  },
  {
    name: "request query member",
    filePath: "app/api/request-query/route.ts",
    content: "import { exec } from 'node:child_process';\nexec(request.query.command);",
    sinkMarker: "exec(request.query.command)",
    expectedEvidencePath: "request.query -> command"
  },
  {
    name: "search params get",
    filePath: "app/api/search-params/route.ts",
    content: "import { exec } from 'node:child_process';\nconst command = searchParams.get('command');\nexec(command);",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "searchParams.get()"
  },
  {
    name: "search params fallback",
    filePath: "app/api/search-fallback/route.ts",
    content: "import { exec } from 'node:child_process';\nconst command = searchParams.get('command') || 'ls';\nexec(command);",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "searchParams.get()"
  },
  {
    name: "route params member",
    filePath: "app/api/route-params/route.ts",
    content: "import { exec } from 'node:child_process';\nexec(params.command);",
    sinkMarker: "exec(params.command)",
    expectedEvidencePath: "params -> command"
  },
  {
    name: "pages router query",
    filePath: "pages/api/query.ts",
    content: "import { exec } from 'node:child_process';\nexport default function handler(req) { exec(req.query.command); }",
    sinkMarker: "exec(req.query.command)",
    expectedEvidencePath: "req.query -> command"
  },
  {
    name: "destructured route params",
    filePath: "app/api/destructured-params/route.ts",
    content: "import { exec } from 'node:child_process';\nconst { command } = params;\nexec(command);",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "params -> command"
  },
  {
    name: "unrelated object method",
    filePath: "app/components/object-method.ts",
    content: "const object = { exec() {} };\nobject.exec();",
    sinkMarker: "object.exec()",
    expectedFinding: false
  },
  {
    name: "exec sync",
    filePath: "app/api/exec-sync/route.ts",
    content: "import { execSync } from 'node:child_process';\nconst command = req.body.command;\nexecSync(command);",
    sinkMarker: "execSync(command)",
    expectedEvidencePath: "req.body -> command"
  },
  {
    name: "spawn",
    filePath: "app/api/spawn/route.ts",
    content: "import { spawn } from 'node:child_process';\nconst command = request.query.command;\nspawn(command);",
    sinkMarker: "spawn(command)",
    expectedEvidencePath: "request.query -> command"
  },
  {
    name: "spawn sync",
    filePath: "app/api/spawn-sync/route.ts",
    content: "import { spawnSync } from 'node:child_process';\nconst command = params.command;\nspawnSync(command);",
    sinkMarker: "spawnSync(command)",
    expectedEvidencePath: "params -> command"
  },
  {
    name: "namespace import",
    filePath: "app/api/namespace/route.ts",
    content: "import * as cp from 'node:child_process';\nconst body = await request.json();\ncp.exec(body.command);",
    sinkMarker: "cp.exec(body.command)",
    expectedEvidencePath: "request.json() -> command"
  },
  {
    name: "require destructuring",
    filePath: "app/api/require-destructure/route.ts",
    content: "const { exec: run } = require('child_process');\nconst command = req.body.command;\nrun(command);",
    sinkMarker: "run(command)",
    expectedEvidencePath: "req.body -> command"
  },
  {
    name: "require namespace",
    filePath: "app/api/require-namespace/route.ts",
    content: "const cp = require('child_process');\nconst command = req.query.command;\ncp.spawn(command);",
    sinkMarker: "cp.spawn(command)",
    expectedEvidencePath: "req.query -> command"
  },
  {
    name: "javascript source flow",
    filePath: "app/api/javascript/route.js",
    content: "const { exec } = require('child_process');\nconst command = req.query.command;\nexec(command);",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "req.query -> command"
  },
  {
    name: "jsx callback boundary",
    filePath: "app/api/jsx-callback/route.jsx",
    content: "import { exec } from 'node:child_process';\nexport function Tool({ request }) { const body = request.body; return <button onClick={() => exec(body.command)}>Run</button>; }",
    sinkMarker: "exec(body.command)"
  },
  {
    name: "tsx same-function flow",
    filePath: "app/api/tsx-route/route.tsx",
    content: "import { exec } from 'node:child_process';\nexport function Tool({ request }) { const body = request.body; exec(body.command); return <div />; }",
    sinkMarker: "exec(body.command)",
    expectedEvidencePath: "request.body -> command"
  },
  {
    name: "pages router javascript",
    filePath: "pages/api/javascript.js",
    content: "const { exec } = require('child_process');\nexport default function handler(req) { const command = req.query.command; exec(command); }",
    sinkMarker: "exec(command)",
    expectedEvidencePath: "req.query -> command"
  },
  {
    name: "safe literal",
    filePath: "app/api/safe-literal/route.ts",
    content: "import { exec } from 'node:child_process';\nexec('ls');",
    sinkMarker: "exec('ls')"
  },
  {
    name: "argument array without source",
    filePath: "app/api/argument-array/route.ts",
    content: "import { spawn } from 'node:child_process';\nspawn('git', ['status']);",
    sinkMarker: "spawn('git', ['status'])",
    expectedFinding: false
  },
  {
    name: "reassignment stop",
    filePath: "app/api/reassignment/route.ts",
    content: "import { exec } from 'node:child_process';\nconst command = req.body.command;\ncommand = 'ls';\nexec(command);",
    sinkMarker: "exec(command)"
  },
  {
    name: "mutation stop",
    filePath: "app/api/mutation/route.ts",
    content: "import { exec } from 'node:child_process';\nconst command = req.body.command;\ncommand += ' --safe';\nexec(command);",
    sinkMarker: "exec(command)"
  },
  {
    name: "callback escape",
    filePath: "app/api/callback/route.ts",
    content: "import { exec } from 'node:child_process';\nconst body = await request.json();\nsetTimeout(() => exec(body.command), 0);",
    sinkMarker: "exec(body.command)"
  },
  {
    name: "cross function boundary",
    filePath: "app/api/cross-function/route.ts",
    content: "import { exec } from 'node:child_process';\nfunction run(command) { exec(command); }\nconst body = await request.json();\nrun(body.command);",
    sinkMarker: "exec(command)"
  }
];

const SAFE_STATIC_SPAWN_FIXTURES = {
  "cli/src/helpers/git.ts": "import { spawn } from 'node:child_process';\nspawn('git', ['status']);",
  "cli/src/helpers/git-sync.ts": "const cp = require('child_process');\ncp.spawnSync('git', ['status']);",
  ".github/scripts/pnpm-version.ts": "import * as cp from 'node:child_process';\ncp.spawn('pnpm', ['--version'], { shell: false });",
  "scripts/release/node-version.ts": "const child_process = require('child_process');\nchild_process.spawnSync('node', ['--version'], { shell: false });",
  "packages/tooling/src/git.ts": "const cp = require('child_process');\ncp.spawn('git', ['diff', '--stat'], { stdio: 'ignore' });"
};

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
      "cli/src/helpers/git.ts": "import * as cp from 'node:child_process';\nconst command = process.argv[2] ?? 'git';\ncp.spawn(command);"
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

  it("preserves fixture-level XSS expectations", async () => {
    const vulnerable = await scanProject(path.resolve("examples/vulnerable-next-app"), {
      contextTuning: "off",
      rules: getBuiltInRules()
    });
    const secure = await scanProject(path.resolve("examples/secure-next-app"), {
      rules: getBuiltInRules()
    });

    expect(findingsFor(vulnerable, "xss/dangerously-set-inner-html")).toEqual([
      expect.objectContaining({
        filePath: "app/profile/page.tsx",
        context: "app-code",
        severity: "MEDIUM"
      })
    ]);
    expect(findingsFor(secure, "xss/dangerously-set-inner-html")).toEqual([]);
  });
});

describe("v0.4 bounded command-flow gate", () => {
  it("covers the 30-case syntax-only command source-to-sink matrix", async () => {
    const result = await scanFixture(
      Object.fromEntries(COMMAND_FLOW_FIXTURES.map((fixture) => [fixture.filePath, fixture.content]))
    );

    expect(COMMAND_FLOW_FIXTURES).toHaveLength(30);

    for (const fixture of COMMAND_FLOW_FIXTURES) {
      const sinkFinding = findingsFor(result, "injection/command-exec").find(
        (finding) => finding.filePath === fixture.filePath && finding.evidence?.includes(fixture.sinkMarker)
      );

      if (fixture.expectedFinding === false) {
        expect(sinkFinding, fixture.name).toBeUndefined();
        continue;
      }

      expect(sinkFinding, fixture.name).toBeDefined();
      expect(sinkFinding?.evidencePath, fixture.name).toBe(fixture.expectedEvidencePath);
    }
  });

  it("measures small and medium syntax scans within the Phase 6 budget", async () => {
    const root = await tempProject();
    const files = Object.fromEntries(
      Array.from({ length: 100 }, (_, index) => [`src/fixture-${index}.ts`, "export const value = 1;\n"])
    );

    await Promise.all(
      Object.entries(files).map(async ([filePath, content]) => {
        const absolutePath = path.join(root, filePath);
        await mkdir(path.dirname(absolutePath), { recursive: true });
        await writeFile(absolutePath, content);
      })
    );

    try {
      const coldStart = performance.now();
      const cold = await scanProject(root, { rules: getBuiltInRules() });
      const coldMs = performance.now() - coldStart;

      const warmStart = performance.now();
      const warm = await scanProject(root, { rules: getBuiltInRules() });
      const warmMs = performance.now() - warmStart;

      expect(cold.findings).toEqual([]);
      expect(warm.findings).toEqual([]);
      expect(coldMs).toBeLessThan(8000);
      expect(warmMs).toBeLessThan(8000);
      console.info(`[phase6] syntax scan timing: 100-file cold=${coldMs.toFixed(1)}ms warm=${warmMs.toFixed(1)}ms`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("recognizes explicit same-function command allowlist guards", async () => {
    const result = await scanFixture({
      "app/api/guarded/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (![\"git\", \"ls\"].includes(command)) return Response.json({ ok: false });",
        "  exec(command);",
        "}"
      ].join("\n"),
      "app/api/branch-guard/route.ts": [
        "import { exec } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (allowedCommands.has(command)) {",
        "    exec(command);",
        "  }",
        "}"
      ].join("\n"),
      "app/api/unsafe-args/route.ts": [
        "import { spawn } from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  const command = body.command;",
        "  if (![\"git\"].includes(command)) return Response.json({ ok: false });",
        "  spawn(command, body.args);",
        "}"
      ].join("\n")
    });

    const commandFindings = findingsFor(result, "injection/command-exec");
    expect(commandFindings.some((finding) => finding.filePath === "app/api/guarded/route.ts" && finding.evidence?.includes("exec(command)"))).toBe(false);
    expect(commandFindings.some((finding) => finding.filePath === "app/api/branch-guard/route.ts" && finding.evidence?.includes("exec(command)"))).toBe(false);
    expect(commandFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "app/api/unsafe-args/route.ts",
          evidence: "spawn(command, body.args);",
          evidencePath: "request.json() -> command"
        })
      ])
    );
  });

  it("reduces five safe static non-shell spawn false positives", async () => {
    const result = await scanFixture(SAFE_STATIC_SPAWN_FIXTURES);

    expect(Object.keys(SAFE_STATIC_SPAWN_FIXTURES)).toHaveLength(5);
    expect(findingsFor(result, "injection/command-exec")).toEqual([]);
  });

  it("keeps dynamic and shell-enabled spawn calls detectable", async () => {
    const result = await scanFixture({
      "app/api/dynamic-spawn/route.ts": [
        "import * as cp from 'node:child_process';",
        "export async function POST(request) {",
        "  const body = await request.json();",
        "  cp.spawn(body.command, ['--version']);",
        "}"
      ].join("\n"),
      "app/api/shell-spawn/route.ts": "import * as cp from 'node:child_process';\ncp.spawn('git', ['status'], { shell: true });"
    });

    expect(findingsFor(result, "injection/command-exec")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ filePath: "app/api/dynamic-spawn/route.ts" }),
        expect.objectContaining({ filePath: "app/api/shell-spawn/route.ts" })
      ])
    );
  });
});
