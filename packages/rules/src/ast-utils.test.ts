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
