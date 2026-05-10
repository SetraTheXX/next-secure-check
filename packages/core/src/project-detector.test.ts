import { describe, expect, it } from "vitest";
import { detectProject } from "./project-detector.js";
import type { SourceFile } from "./types.js";

function file(path: string, content = ""): SourceFile {
  return {
    path,
    absolutePath: path,
    content,
    lines: content.split(/\r?\n/)
  };
}

describe("detectProject", () => {
  it("detects a Next.js app router project from app files", () => {
    const result = detectProject([file("package.json", '{"name":"demo"}'), file("app/page.tsx")], "/tmp/demo");

    expect(result.project.name).toBe("demo");
    expect(result.project.framework).toBe("nextjs");
    expect(result.project.router).toBe("app");
  });

  it("detects a pages router project", () => {
    const result = detectProject([file("pages/api/login.ts")], "/tmp/demo");

    expect(result.project.framework).toBe("nextjs");
    expect(result.project.router).toBe("pages");
  });

  it("detects mixed TypeScript and JavaScript", () => {
    const result = detectProject([file("src/index.ts"), file("src/index.js")], "/tmp/demo");

    expect(result.project.language).toBe("mixed");
  });
});
