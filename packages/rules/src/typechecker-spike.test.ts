import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanProject } from "@next-secure-check/core";
import type { ScanResult, SourceFile } from "@next-secure-check/core";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { findCommandExecutionMatches } from "./ast-utils.js";
import { getBuiltInRules } from "./index.js";

type SpikeProject = {
  mode: "typechecker" | "syntax-fallback";
  reason: string;
  program?: ts.Program;
  checker?: ts.TypeChecker;
};

type SpikeResult = SpikeProject & {
  syntaxResult?: ScanResult;
};

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-typechecker-spike-"));
}

async function writeFixture(root: string, files: Record<string, string>): Promise<void> {
  await Promise.all(
    Object.entries(files).map(async ([filePath, content]) => {
      const absolutePath = path.join(root, filePath);
      await mkdir(path.dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, content);
    })
  );
}

function loadTypeCheckerProject(root: string): SpikeProject {
  const configPath = path.join(root, "tsconfig.json");
  if (!ts.sys.fileExists(configPath)) {
    return { mode: "syntax-fallback", reason: "tsconfig-not-found" };
  }

  let configFile: ts.ParsedCommandLine | ts.ReadConfigFileResult;
  try {
    configFile = ts.readConfigFile(configPath, ts.sys.readFile);
  } catch {
    return { mode: "syntax-fallback", reason: "tsconfig-read-error" };
  }

  if ("config" in configFile && configFile.error) {
    return { mode: "syntax-fallback", reason: "tsconfig-read-error" };
  }

  if (!("config" in configFile)) {
    return { mode: "syntax-fallback", reason: "tsconfig-read-error" };
  }

  const references = configFile.config?.references;
  if (Array.isArray(references) && references.length > 1) {
    return { mode: "syntax-fallback", reason: "multiple-project-references" };
  }

  let parsed: ts.ParsedCommandLine;
  try {
    parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, root);
  } catch {
    return { mode: "syntax-fallback", reason: "tsconfig-parse-error" };
  }
  if (parsed.errors.length > 0) {
    return { mode: "syntax-fallback", reason: "tsconfig-parse-error" };
  }

  if (parsed.fileNames.length === 0) {
    return { mode: "syntax-fallback", reason: "tsconfig-no-input-files" };
  }

  const program = ts.createProgram({
    rootNames: parsed.fileNames,
    options: parsed.options,
    projectReferences: parsed.projectReferences
  });

  return {
    mode: "typechecker",
    reason: "program-loaded",
    program,
    checker: program.getTypeChecker()
  };
}

async function runSpike(root: string): Promise<SpikeResult> {
  const project = loadTypeCheckerProject(root);
  if (project.mode === "typechecker") {
    return project;
  }

  return {
    ...project,
    syntaxResult: await scanProject(root, { rules: getBuiltInRules() })
  };
}

function sourceFile(root: string, relativePath: string, content: string): SourceFile {
  const absolutePath = path.join(root, relativePath);
  return {
    path: relativePath,
    absolutePath,
    content,
    lines: content.split(/\r?\n/)
  };
}

function findResolvedChildProcessCalls(program: ts.Program, checker: ts.TypeChecker, root: string): string[] {
  const matches: string[] = [];

  for (const sourceFile of program.getSourceFiles()) {
    const normalizedSourcePath = path.resolve(sourceFile.fileName).toLowerCase();
    const normalizedRoot = `${path.resolve(root).toLowerCase()}${path.sep}`;
    if (!normalizedSourcePath.startsWith(normalizedRoot) || sourceFile.isDeclarationFile) {
      continue;
    }

    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const symbol = checker.getSymbolAtLocation(node.expression);
        const resolved = symbol && symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
        const isChildProcessSymbol = resolved?.declarations?.some((declaration) =>
          declaration.getSourceFile().fileName.endsWith("child-process.d.ts")
        );

        if (isChildProcessSymbol) {
          matches.push(path.relative(root, sourceFile.fileName).replace(/\\/g, "/"));
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  return matches.sort();
}

describe("v0.4 opt-in TypeChecker spike", () => {
  it("compares syntax matching with type-aware alias and shadow resolution", async () => {
    const root = await tempProject();
    const apiContent = [
      "import { exec as run } from 'child_process';",
      "export function handle(request) { run(request.body.command); }"
    ].join("\n");
    const shadowContent = [
      "import { exec as run } from 'child_process';",
      "export function render(run: (value: string) => void) { run('safe'); }"
    ].join("\n");

    try {
      await writeFixture(root, {
        "tsconfig.json": JSON.stringify({
          compilerOptions: { target: "ES2022", module: "CommonJS", strict: true },
          include: ["src/**/*.ts"]
        }),
        "src/child-process.d.ts": "declare module 'child_process' { export function exec(command: string): void; }",
        "src/api.ts": apiContent,
        "src/shadow.ts": shadowContent
      });

      const spike = await runSpike(root);
      expect(spike.mode).toBe("typechecker");
      expect(spike.checker).toBeDefined();
      expect(findResolvedChildProcessCalls(spike.program!, spike.checker!, root)).toEqual(["src/api.ts"]);

      const syntaxMatches = [
        ...findCommandExecutionMatches(sourceFile(root, "src/api.ts", apiContent)),
        ...findCommandExecutionMatches(sourceFile(root, "src/shadow.ts", shadowContent))
      ].filter((match) => match.evidence.includes("run("));
      expect(syntaxMatches).toHaveLength(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("falls back to syntax mode for missing, malformed, and multi-project configs", async () => {
    const cases = [
      { files: { "src/index.ts": "export const value = 1;" }, reason: "tsconfig-not-found" },
      { files: { "tsconfig.json": "{", "src/index.ts": "export const value = 1;" }, reason: "tsconfig-read-error" },
      {
        files: {
          "tsconfig.json": JSON.stringify({ references: [{ path: "packages/a" }, { path: "packages/b" }] }),
          "src/index.ts": "export const value = 1;"
        },
        reason: "multiple-project-references"
      }
    ];

    for (const testCase of cases) {
      const root = await tempProject();
      try {
        await writeFixture(root, testCase.files);
        const spike = await runSpike(root);
        expect(spike.mode).toBe("syntax-fallback");
        expect(spike.reason).toBe(testCase.reason);
        expect(spike.syntaxResult?.findings).toEqual([]);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  it("measures small and medium Program startup within the opt-in budget", async () => {
    const roots = [await tempProject(), await tempProject()];

    try {
      await writeFixture(roots[0], {
        "tsconfig.json": JSON.stringify({ compilerOptions: { target: "ES2022", module: "CommonJS" }, include: ["src/**/*.ts"] }),
        ...Object.fromEntries(Array.from({ length: 12 }, (_, index) => [`src/small-${index}.ts`, `export const value${index} = ${index};\n`]))
      });
      await writeFixture(roots[1], {
        "tsconfig.json": JSON.stringify({ compilerOptions: { target: "ES2022", module: "CommonJS" }, include: ["src/**/*.ts"] }),
        ...Object.fromEntries(Array.from({ length: 120 }, (_, index) => [`src/medium-${index}.ts`, `export const value${index} = ${index};\n`]))
      });

      const smallStart = performance.now();
      const small = loadTypeCheckerProject(roots[0]);
      const smallMs = performance.now() - smallStart;
      const mediumStart = performance.now();
      const medium = loadTypeCheckerProject(roots[1]);
      const mediumMs = performance.now() - mediumStart;

      expect(small.mode).toBe("typechecker");
      expect(medium.mode).toBe("typechecker");
      expect(smallMs).toBeLessThan(2000);
      expect(mediumMs).toBeLessThan(8000);
      console.info(`[phase7] TypeChecker startup: small=${smallMs.toFixed(1)}ms medium=${mediumMs.toFixed(1)}ms`);
    } finally {
      await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
    }
  });
});
