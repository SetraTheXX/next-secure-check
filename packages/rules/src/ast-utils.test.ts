import type { SourceFile } from "@next-secure-check/core";
import { describe, expect, it, beforeEach } from "vitest";
import {
  findCommandExecutionMatches,
  findRouteHandlerExports,
  getAnalysisFacts,
  getAnalysisFactsCacheStats,
  hasAuthIntentSignal,
  hasValidationIntentSignal,
  resetAnalysisFactsCacheForTests
} from "./ast-utils.js";

function sourceFile(content: string, path = "app/api/example/route.ts"): SourceFile {
  return {
    path,
    absolutePath: `C:/fixture/${path}`,
    content,
    lines: content.split(/\r?\n/)
  };
}

describe("analysis facts cache", () => {
  beforeEach(() => {
    resetAnalysisFactsCacheForTests();
  });

  it("exposes shared bounded-flow facts for a direct source and two aliases", () => {
    const file = sourceFile([
      'import { exec } from "node:child_process";',
      "export async function POST(request) {",
      "  const body = await request.json();",
      "  const command = body.command;",
      "  const alias = command;",
      "  const second = alias;",
      "  exec(second);",
      "}"
    ].join("\n"));

    const facts = getAnalysisFacts(file).boundedFlow;

    expect(facts.sources.map((source) => source.path)).toEqual(["request.json()"]);
    expect(facts.sinks).toHaveLength(1);
    expect(facts.aliases.map((alias) => [alias.from, alias.to, alias.depth])).toEqual([
      ["command", "alias", 1],
      ["alias", "second", 2]
    ]);
    expect([...facts.evidencePaths.values()]).toEqual(["request.json() -> command -> alias -> second"]);
    expect(facts.guards).toHaveLength(0);
  });

  it("records a direct route-parameter source in bounded-flow facts", () => {
    const file = sourceFile([
      'import { exec } from "node:child_process";',
      "export function GET(params) {",
      "  exec(params);",
      "}"
    ].join("\n"));

    const facts = getAnalysisFacts(file).boundedFlow;

    expect(facts.sources.map((source) => source.path)).toEqual(["params"]);
    expect([...facts.evidencePaths.values()]).toEqual(["params"]);
  });

  it("records guards, invalidations, and function boundaries without widening flow", () => {
    const file = sourceFile([
      'import { exec } from "node:child_process";',
      "export async function POST(request) {",
      "  const body = await request.json();",
      "  let reassigned = body.command;",
      '  reassigned = "git";',
      "  exec(reassigned);",
      "  let mutated = body.command;",
      '  mutated += " --version";',
      "  exec(mutated);",
      "  const guarded = body.command;",
      '  if (!["git"].includes(guarded)) return Response.json({ ok: false });',
      "  exec(guarded);",
      "  setTimeout(() => exec(body.command), 0);",
      "  function invoke(command) { exec(command); }",
      "  invoke(body.command);",
      "}"
    ].join("\n"));

    const facts = getAnalysisFacts(file).boundedFlow;

    expect(facts.evidencePaths.size).toBe(0);
    expect(facts.guards.map((guard) => [guard.kind, guard.identifier])).toEqual([
      ["command-allowlist", "guarded"]
    ]);
    expect(facts.invalidations.map((invalidation) => invalidation.reason)).toEqual(
      expect.arrayContaining(["reassignment", "mutation", "call-escape"])
    );
    expect(facts.functionBoundaries.length).toBeGreaterThanOrEqual(3);
  });

  it("does not crash while collecting facts from malformed JS, JSX, TS, or TSX", () => {
    for (const extension of ["js", "jsx", "ts", "tsx"]) {
      const file = sourceFile(
        "export function broken( { const value = request.json();",
        `app/api/broken.${extension}`
      );

      expect(() => findCommandExecutionMatches(file)).not.toThrow();
    }
  });

  it("records one parse miss and a cache hit for repeated access to one source file", () => {
    const file = sourceFile("export async function GET() { return Response.json({ ok: true }); }");

    const first = getAnalysisFacts(file);
    const second = getAnalysisFacts(file);

    expect(second).toBe(first);
    expect(getAnalysisFactsCacheStats()).toEqual({ cacheHits: 1, cacheMisses: 1 });
  });

  it("shares one parsed AST across rule helpers for one source file", () => {
    const file = sourceFile([
      'import { exec } from "node:child_process";',
      "export async function POST(request) {",
      "  const body = await request.json();",
      "  const parsed = schema.safeParse(body);",
      "  const user = requireAuth();",
      "  exec(user.command);",
      "  return Response.json({ ok: Boolean(parsed.success) });",
      "}"
    ].join("\n"));

    expect(findCommandExecutionMatches(file)).not.toHaveLength(0);
    expect(findRouteHandlerExports(file)).toHaveLength(1);
    expect(hasAuthIntentSignal(file)).toBe(true);
    expect(hasValidationIntentSignal(file)).toBe(true);

    const stats = getAnalysisFactsCacheStats();
    expect(stats.cacheMisses).toBe(1);
    expect(stats.cacheHits).toBe(3);
  });

  it("keeps distinct source-file objects isolated", () => {
    const firstFile = sourceFile("export const GET = () => Response.json({ ok: true });");
    const secondFile = sourceFile("export const GET = () => Response.json({ ok: true });");

    getAnalysisFacts(firstFile);
    getAnalysisFacts(secondFile);

    expect(getAnalysisFactsCacheStats()).toEqual({ cacheHits: 0, cacheMisses: 2 });
  });
});
