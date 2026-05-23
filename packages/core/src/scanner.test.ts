import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { resolveProjectPath, scanProject } from "./scanner.js";
import type { Rule } from "./types.js";

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
});

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
