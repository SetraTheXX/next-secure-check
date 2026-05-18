import { describe, expect, it } from "vitest";
import { DEFAULT_WEB_EXCLUDE_PATHS, validateExcludePaths } from "./scan-excludes";

describe("scan exclude path validation", () => {
  it("keeps the default web exclude list aligned with production-like scans", () => {
    expect(DEFAULT_WEB_EXCLUDE_PATHS).toEqual([
      "**/*.test.ts",
      "**/*.test.tsx",
      "**/*.spec.ts",
      "**/*.spec.tsx",
      "examples/**"
    ]);
  });

  it("accepts safe relative glob patterns", () => {
    expect(validateExcludePaths(["**/*.test.ts", "examples/**"])).toEqual([
      "**/*.test.ts",
      "examples/**"
    ]);
  });

  it("treats omitted exclude paths as full scan behavior", () => {
    expect(validateExcludePaths(undefined)).toEqual([]);
  });

  it("rejects unsafe exclude path values", () => {
    expect(validateExcludePaths(["../secret"])).toBeNull();
    expect(validateExcludePaths(["C:/repo/**"])).toBeNull();
    expect(validateExcludePaths(["/absolute/**"])).toBeNull();
    expect(validateExcludePaths(["line\nbreak"])).toBeNull();
  });
});
