import type { SourceFile } from "@next-secure-check/core";
import { describe, expect, it } from "vitest";
import { findMatches } from "./rule-utils.js";

function sourceFile(content: string): SourceFile {
  return {
    path: "index.ts",
    absolutePath: "/project/index.ts",
    content,
    lines: content.split(/\r?\n/)
  };
}

describe("findMatches", () => {
  it("returns multiple matches on the same line", () => {
    const matches = findMatches(sourceFile("eval('a'); eval('b');"), /\beval\s*\(/);

    expect(matches).toEqual([
      { line: 1, column: 1, evidence: "eval('a'); eval('b');" },
      { line: 1, column: 12, evidence: "eval('a'); eval('b');" }
    ]);
  });

  it("returns matches across different lines", () => {
    const matches = findMatches(sourceFile("eval('a');\nconst safe = true;\neval('b');"), /\beval\s*\(/);

    expect(matches).toEqual([
      { line: 1, column: 1, evidence: "eval('a');" },
      { line: 3, column: 1, evidence: "eval('b');" }
    ]);
  });

  it("works with a global regex", () => {
    const matches = findMatches(sourceFile("eval('a'); eval('b');"), /\beval\s*\(/g);

    expect(matches).toHaveLength(2);
    expect(matches.map((match) => match.column)).toEqual([1, 12]);
  });

  it("works with a non-global regex", () => {
    const matches = findMatches(sourceFile("eval('a'); eval('b');"), /\beval\s*\(/);

    expect(matches).toHaveLength(2);
    expect(matches.map((match) => match.column)).toEqual([1, 12]);
  });

  it("does not leak lastIndex state when a regex is reused", () => {
    const pattern = /\beval\s*\(/g;

    expect(findMatches(sourceFile("eval('a');"), pattern)).toEqual([
      { line: 1, column: 1, evidence: "eval('a');" }
    ]);
    expect(findMatches(sourceFile("const safe = true;\neval('b');"), pattern)).toEqual([
      { line: 2, column: 1, evidence: "eval('b');" }
    ]);
    expect(pattern.lastIndex).toBe(0);
  });

  it("advances safely for zero-length matches", () => {
    const matches = findMatches(sourceFile("abc"), /(?=b)/g);

    expect(matches).toEqual([{ line: 1, column: 2, evidence: "abc" }]);
  });
});
