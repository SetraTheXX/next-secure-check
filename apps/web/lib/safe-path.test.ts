import { describe, expect, it } from "vitest";
import { isSafeArchiveEntryPath, normalizeArchiveEntryPath } from "./safe-path";

describe("safe path helpers", () => {
  it("accepts src/index.ts", () => {
    expect(normalizeArchiveEntryPath("src/index.ts")).toBe("src/index.ts");
    expect(isSafeArchiveEntryPath("src/index.ts")).toBe(true);
  });

  it("accepts app/api/route.ts", () => {
    expect(normalizeArchiveEntryPath("app/api/route.ts")).toBe("app/api/route.ts");
  });

  it("normalizes backslashes", () => {
    expect(normalizeArchiveEntryPath("src\\components\\page.tsx")).toBe("src/components/page.tsx");
  });

  it("rejects parent traversal", () => {
    expect(normalizeArchiveEntryPath("../secret.txt")).toBeNull();
    expect(normalizeArchiveEntryPath("src/../../secret.txt")).toBeNull();
  });

  it("rejects absolute paths", () => {
    expect(normalizeArchiveEntryPath("/etc/passwd")).toBeNull();
  });

  it("rejects windows drive paths", () => {
    expect(normalizeArchiveEntryPath("C:\\Windows\\system32")).toBeNull();
  });

  it("rejects empty and special paths", () => {
    expect(normalizeArchiveEntryPath("")).toBeNull();
    expect(normalizeArchiveEntryPath("\u0000")).toBeNull();
    expect(normalizeArchiveEntryPath(".")).toBeNull();
    expect(normalizeArchiveEntryPath("/")).toBeNull();
  });
});