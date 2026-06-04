import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { resolveProjectPath, scanProject } from "./scanner.js";
import type { MiddlewareSignal, Rule } from "./types.js";

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-scanner-"));
}

describe("resolveProjectPath", () => {
  it("rejects files as scan targets", async () => {
    const root = await tempProject();
    const file = path.join(root, "file.ts");
    await writeFile(file, "export {};");

    await expect(resolveProjectPath(file)).rejects.toThrow("Scan target must be a directory");
  });
});

describe("scanProject", () => {
  it("runs supplied rules", async () => {
    const root = await tempProject();
    await writeFile(path.join(root, "index.ts"), "export {};");
    const rule: Rule = {
      id: "test/rule",
      title: "Test rule",
      severity: "LOW",
      category: "test",
      scan: (context) => [
        {
          id: "test",
          ruleId: "test/rule",
          title: "Test rule",
          severity: "LOW",
          confidence: "HIGH",
          category: "test",
          filePath: context.files[0]?.path ?? "unknown",
          description: "description",
          recommendation: "recommendation"
        }
      ]
    };

    const result = await scanProject(root, { rules: [rule] });

    expect(result.findings).toHaveLength(1);
    expect(result.summary.low).toBe(1);
    expect(result.findings[0]).toMatchObject({
      context: "unknown",
      contextReason: "no known file context pattern matched"
    });
  });

  it("filters rules by category", async () => {
    const root = await tempProject();
    await writeFile(path.join(root, "index.ts"), "export {};");
    const rule: Rule = {
      id: "test/rule",
      title: "Test rule",
      severity: "LOW",
      category: "test",
      scan: () => []
    };

    const result = await scanProject(root, { rules: [rule], categories: ["secrets"] });

    expect(result.findings).toEqual([]);
  });

  it("extracts middleware auth, rate-limit, and matcher signals for rules", async () => {
    const root = await tempProject();
    await writeProjectFile(
      root,
      "middleware.ts",
      [
        "export function middleware() {",
        "  const session = auth();",
        "  const allowed = rateLimit();",
        "  if (!allowed) return Response.json({}, { status: 429 });",
        "  return Response.json({ ok: Boolean(session) });",
        "}",
        "export const config = { matcher: ['/api/admin/:path*', '/api/login/:path*'] };"
      ].join("\n")
    );
    let middlewareSignals: MiddlewareSignal[] | undefined;
    const rule: Rule = {
      id: "test/middleware",
      title: "Middleware",
      severity: "LOW",
      category: "test",
      scan: (context) => {
        middlewareSignals = context.middleware;
        return [];
      }
    };

    await scanProject(root, { rules: [rule] });

    expect(middlewareSignals).toEqual([
      {
        filePath: "middleware.ts",
        hasAuthSignal: true,
        hasRateLimitSignal: true,
        matchers: ["/api/admin/:path*", "/api/login/:path*"]
      }
    ]);
  });

  it("passes all files to rules when excludePaths is not set", async () => {
    const root = await tempProject();
    await writeFile(path.join(root, "index.ts"), "export {};");
    await writeFile(path.join(root, "index.test.ts"), "export {};");

    const result = await scanProject(root, {
      rules: [createFileListRule()]
    });

    expect(result.findings.map((finding) => finding.filePath)).toEqual(["index.test.ts", "index.ts"]);
  });

  it("excludes files before rules run", async () => {
    const root = await tempProject();
    await writeFile(path.join(root, "index.ts"), "export {};");
    await writeFile(path.join(root, "index.test.ts"), "export {};");

    const result = await scanProject(root, {
      excludePaths: ["**/*.test.ts"],
      rules: [createFileListRule()]
    });

    expect(result.findings.map((finding) => finding.filePath)).toEqual(["index.ts"]);
  });

  it("calculates score and risk from tuned finding severity by default", async () => {
    const root = await tempProject();
    await mkdir(path.join(root, ".github"));
    await writeFile(path.join(root, ".github/changeset-version.js"), "exec('pnpm changeset version');");

    const result = await scanProject(root, {
      rules: [createSingleFindingRule(".github/changeset-version.js", "injection/command-exec")]
    });

    expect(result.findings[0]).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "HIGH",
      context: "release-tooling"
    });
    expect(result.summary).toMatchObject({
      high: 0,
      low: 1,
      score: 99,
      riskLevel: "excellent"
    });
  });

  it("can disable context tuning", async () => {
    const root = await tempProject();
    await mkdir(path.join(root, ".github"));
    await writeFile(path.join(root, ".github/changeset-version.js"), "exec('pnpm changeset version');");

    const result = await scanProject(root, {
      contextTuning: "off",
      rules: [createSingleFindingRule(".github/changeset-version.js", "injection/command-exec")]
    });

    expect(result.findings[0]).toMatchObject({
      severity: "HIGH",
      confidence: "HIGH",
      context: "release-tooling"
    });
    expect(result.findings[0]?.originalSeverity).toBeUndefined();
    expect(result.summary).toMatchObject({
      high: 1,
      score: 85,
      riskLevel: "good"
    });
  });

  it("regresses release tooling command execution tuning", async () => {
    const root = await tempProject();
    await writeProjectFile(root, ".github/changeset-version.js", "exec('pnpm changeset version');");
    const rule = createMatchingFindingRule(".github/changeset-version.js", "injection/command-exec", "HIGH", "MEDIUM");

    const standard = await scanProject(root, { rules: [rule] });
    const strict = await scanProject(root, { contextTuning: "off", rules: [rule] });

    expect(standard.findings[0]).toMatchObject({
      severity: "LOW",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "MEDIUM",
      context: "release-tooling",
      contextAdjustmentReason: "lowered command execution finding in release/tooling context"
    });
    expect(strict.findings[0]).toMatchObject({
      severity: "HIGH",
      confidence: "MEDIUM",
      context: "release-tooling"
    });
    expect(strict.findings[0]?.originalSeverity).toBeUndefined();
  });

  it("regresses CLI tooling command execution tuning", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "cli/src/helpers/git.ts", "spawn('git', ['status']);");

    const result = await scanProject(root, {
      rules: [createMatchingFindingRule("cli/src/helpers/git.ts", "injection/command-exec", "HIGH", "MEDIUM")]
    });

    expect(result.findings[0]).toMatchObject({
      severity: "MEDIUM",
      confidence: "MEDIUM",
      originalSeverity: "HIGH",
      context: "cli-tooling",
      contextAdjustmentReason: "lowered command execution finding in CLI tooling context"
    });
    expect(result.findings[0]?.originalConfidence).toBeUndefined();
  });

  it("keeps app runtime API findings at their original risk", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "app/api/admin/route.ts", "exec('id'); await request.json();");

    const result = await scanProject(root, {
      rules: [
        createMatchingFindingRule("app/api/admin/route.ts", "injection/command-exec", "HIGH", "MEDIUM"),
        createMatchingFindingRule("app/api/admin/route.ts", "auth/admin-route-without-auth", "HIGH", "MEDIUM"),
        createMatchingFindingRule("app/api/admin/route.ts", "validation/api-route-without-validation", "MEDIUM", "MEDIUM")
      ]
    });

    expect(result.findings).toHaveLength(3);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId: "injection/command-exec", severity: "HIGH", confidence: "MEDIUM", context: "api-code" }),
        expect.objectContaining({ ruleId: "auth/admin-route-without-auth", severity: "HIGH", confidence: "MEDIUM", context: "api-code" }),
        expect.objectContaining({ ruleId: "validation/api-route-without-validation", severity: "MEDIUM", confidence: "MEDIUM", context: "api-code" })
      ])
    );
    expect(result.findings.some((finding) => finding.originalSeverity !== undefined)).toBe(false);
  });

  it("lowers admin route noise in non-API app components", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "apps/v4/app/(app)/(styles)/admin-card.tsx", "export function AdminCard() { return null; }");

    const result = await scanProject(root, {
      rules: [createMatchingFindingRule("apps/v4/app/(app)/(styles)/admin-card.tsx", "auth/admin-route-without-auth", "HIGH", "MEDIUM")]
    });

    expect(result.findings[0]).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      originalConfidence: "MEDIUM",
      context: "app-code",
      contextAdjustmentReason: "lowered admin route finding in non-API app component context"
    });
  });

  it("keeps monorepo API admin routes at high risk", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "apps/v4/app/api/admin/route.ts", "export async function GET() { return Response.json({ ok: true }); }");

    const result = await scanProject(root, {
      rules: [createMatchingFindingRule("apps/v4/app/api/admin/route.ts", "auth/admin-route-without-auth", "HIGH", "MEDIUM")]
    });

    expect(result.findings[0]).toMatchObject({
      severity: "HIGH",
      confidence: "MEDIUM",
      context: "api-code"
    });
    expect(result.findings[0]?.originalSeverity).toBeUndefined();
  });

  it("regresses example admin API tuning", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "examples/demo/app/api/admin/route.ts", "await request.json();");

    const result = await scanProject(root, {
      rules: [
        createMatchingFindingRule("examples/demo/app/api/admin/route.ts", "auth/admin-route-without-auth", "HIGH", "MEDIUM"),
        createMatchingFindingRule("examples/demo/app/api/admin/route.ts", "validation/api-route-without-validation", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("examples/demo/app/api/admin/route.ts", "auth/login-without-rate-limit", "MEDIUM", "MEDIUM")
      ]
    });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "auth/admin-route-without-auth",
          severity: "LOW",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "example-code"
        }),
        expect.objectContaining({
          ruleId: "validation/api-route-without-validation",
          severity: "LOW",
          confidence: "LOW",
          originalSeverity: "MEDIUM",
          originalConfidence: "MEDIUM",
          context: "example-code"
        }),
        expect.objectContaining({
          ruleId: "auth/login-without-rate-limit",
          severity: "LOW",
          confidence: "LOW",
          originalSeverity: "MEDIUM",
          originalConfidence: "MEDIUM",
          context: "example-code"
        })
      ])
    );
  });

  it("regresses template API tuning", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "templates/default/app/api/route.ts", "await request.json();");

    const result = await scanProject(root, {
      rules: [
        createMatchingFindingRule("templates/default/app/api/route.ts", "validation/api-route-without-validation", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("templates/default/app/api/route.ts", "injection/command-exec", "HIGH", "MEDIUM")
      ]
    });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "validation/api-route-without-validation",
          severity: "LOW",
          confidence: "LOW",
          originalSeverity: "MEDIUM",
          context: "template-code"
        }),
        expect.objectContaining({
          ruleId: "injection/command-exec",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "template-code"
        })
      ])
    );
  });

  it("regresses raw SQL tuning in template code while preserving app API severity", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "templates/default/app/api/route.ts", "const sql = `SELECT * FROM users WHERE id = ${id}`;");
    await writeProjectFile(root, "app/api/users/route.ts", "const sql = `SELECT * FROM users WHERE id = ${id}`;");
    const templateRule = createMatchingFindingRule("templates/default/app/api/route.ts", "injection/raw-sql-concat", "HIGH", "MEDIUM");
    const appRule = createMatchingFindingRule("app/api/users/route.ts", "injection/raw-sql-concat", "HIGH", "MEDIUM");

    const result = await scanProject(root, { rules: [templateRule, appRule] });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "templates/default/app/api/route.ts",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "template-code"
        }),
        expect.objectContaining({
          filePath: "app/api/users/route.ts",
          severity: "HIGH",
          confidence: "MEDIUM",
          context: "api-code"
        })
      ])
    );
  });

  it("regresses targeted app component tuning while preserving API runtime risks", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "apps/v4/app/(app)/components/password-field.tsx", "export function PasswordField() { return null; }");
    await writeProjectFile(root, "apps/v4/app/(app)/components/file-filter.tsx", "export function FileFilter() { return null; }");
    await writeProjectFile(root, "apps/v4/app/(app)/components/data-table.tsx", "export function DataTable() { return null; }");
    await writeProjectFile(root, "app/api/upload/route.ts", "await request.formData();");
    await writeProjectFile(root, "app/api/register/route.ts", "const password = body.password;");
    await writeProjectFile(root, "app/api/users/route.ts", "const sql = `SELECT * FROM users WHERE id = ${id}`;");

    const result = await scanProject(root, {
      rules: [
        createMatchingFindingRule("apps/v4/app/(app)/components/password-field.tsx", "auth/password-without-hashing-library", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("apps/v4/app/(app)/components/file-filter.tsx", "upload/missing-file-size-limit", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("apps/v4/app/(app)/components/data-table.tsx", "injection/raw-sql-concat", "HIGH", "MEDIUM"),
        createMatchingFindingRule("app/api/upload/route.ts", "upload/missing-file-size-limit", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("app/api/register/route.ts", "auth/password-without-hashing-library", "MEDIUM", "MEDIUM"),
        createMatchingFindingRule("app/api/users/route.ts", "injection/raw-sql-concat", "HIGH", "MEDIUM")
      ]
    });

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "apps/v4/app/(app)/components/password-field.tsx",
          severity: "MEDIUM",
          confidence: "LOW",
          originalConfidence: "MEDIUM",
          context: "app-code"
        }),
        expect.objectContaining({
          filePath: "apps/v4/app/(app)/components/file-filter.tsx",
          severity: "MEDIUM",
          confidence: "LOW",
          originalConfidence: "MEDIUM",
          context: "app-code"
        }),
        expect.objectContaining({
          filePath: "apps/v4/app/(app)/components/data-table.tsx",
          severity: "MEDIUM",
          confidence: "LOW",
          originalSeverity: "HIGH",
          originalConfidence: "MEDIUM",
          context: "app-code"
        }),
        expect.objectContaining({
          filePath: "app/api/upload/route.ts",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          context: "api-code"
        }),
        expect.objectContaining({
          filePath: "app/api/register/route.ts",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          context: "api-code"
        }),
        expect.objectContaining({
          filePath: "app/api/users/route.ts",
          severity: "HIGH",
          confidence: "MEDIUM",
          context: "api-code"
        })
      ])
    );
  });

  it("uses tuned severity when scoring targeted component noise", async () => {
    const root = await tempProject();
    await writeProjectFile(root, "apps/v4/app/(app)/components/data-table.tsx", "export function DataTable() { return null; }");

    const standard = await scanProject(root, {
      rules: [createMatchingFindingRule("apps/v4/app/(app)/components/data-table.tsx", "injection/raw-sql-concat", "HIGH", "MEDIUM")]
    });
    const strict = await scanProject(root, {
      contextTuning: "off",
      rules: [createMatchingFindingRule("apps/v4/app/(app)/components/data-table.tsx", "injection/raw-sql-concat", "HIGH", "MEDIUM")]
    });

    expect(standard.findings[0]).toMatchObject({
      severity: "MEDIUM",
      confidence: "LOW",
      originalSeverity: "HIGH",
      context: "app-code"
    });
    expect(standard.summary).toMatchObject({
      high: 0,
      medium: 1,
      score: 97,
      riskLevel: "excellent"
    });
    expect(strict.findings[0]).toMatchObject({
      severity: "HIGH",
      confidence: "MEDIUM",
      context: "app-code"
    });
    expect(strict.findings[0]?.originalSeverity).toBeUndefined();
    expect(strict.summary).toMatchObject({
      high: 1,
      score: 90,
      riskLevel: "excellent"
    });
  });

  it("regresses app preset path exclusions at scanner level", async () => {
    const root = await tempProject();
    await writeProjectFile(root, ".github/changeset-version.js", "exec('pnpm changeset version');");
    await writeProjectFile(root, "examples/demo/app/api/admin/route.ts", "await request.json();");
    await writeProjectFile(root, "docs/security.md", "const sql = `SELECT * FROM users WHERE id = ${id}`;");
    await writeProjectFile(root, "generated/client.ts", "exec('generated');");
    await writeProjectFile(root, "app/api/admin/route.ts", "exec('id');");

    const result = await scanProject(root, {
      excludePaths: [".github/**", "examples/**", "docs/**", "generated/**"],
      rules: [createFileListRule()]
    });

    expect(result.findings.map((finding) => finding.filePath)).toEqual(["app/api/admin/route.ts"]);
  });
});

async function writeProjectFile(root: string, relativePath: string, content: string): Promise<void> {
  const absolutePath = path.join(root, relativePath);
  await mkdir(path.dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, content);
}

function createFileListRule(): Rule {
  return {
    id: "test/file-list",
    title: "File list",
    severity: "LOW",
    category: "test",
    scan: (context) =>
      context.files.map((file) => ({
        id: `test/file-list:${file.path}`,
        ruleId: "test/file-list",
        title: "File list",
        severity: "LOW",
        confidence: "HIGH",
        category: "test",
        filePath: file.path,
        description: "description",
        recommendation: "recommendation"
      }))
  };
}

function createSingleFindingRule(filePath: string, ruleId: string): Rule {
  return {
    id: ruleId,
    title: "Finding",
    severity: "HIGH",
    category: ruleId.split("/")[0] ?? "test",
    confidence: "HIGH",
    scan: () => [
      {
        id: `${ruleId}:${filePath}:1:1`,
        ruleId,
        title: "Finding",
        severity: "HIGH",
        confidence: "HIGH",
        category: ruleId.split("/")[0] ?? "test",
        filePath,
        line: 1,
        column: 1,
        description: "description",
        recommendation: "recommendation"
      }
    ]
  };
}

function createMatchingFindingRule(filePath: string, ruleId: string, severity: Rule["severity"], confidence: "HIGH" | "MEDIUM" | "LOW"): Rule {
  return {
    id: `${ruleId}:${filePath}`,
    title: "Finding",
    severity,
    category: ruleId.split("/")[0] ?? "test",
    confidence,
    scan: (context) =>
      context.files
        .filter((file) => file.path === filePath)
        .map((file) => ({
          id: `${ruleId}:${file.path}:1:1`,
          ruleId,
          title: "Finding",
          severity,
          confidence,
          category: ruleId.split("/")[0] ?? "test",
          filePath: file.path,
          line: 1,
          column: 1,
          description: "description",
          recommendation: "recommendation"
        }))
  };
}
