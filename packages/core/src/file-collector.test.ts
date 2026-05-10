import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { collectFiles } from "./file-collector.js";

async function tempProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "nsc-file-collector-"));
}

describe("collectFiles", () => {
  it("collects supported source files", async () => {
    const root = await tempProject();
    await mkdir(path.join(root, "app"), { recursive: true });
    await writeFile(path.join(root, "package.json"), "{}");
    await writeFile(path.join(root, "app", "page.tsx"), "export default function Page() { return null; }");

    const files = await collectFiles(root);

    expect(files.map((file) => file.path)).toEqual(["app/page.tsx", "package.json"]);
  });

  it("ignores build and dependency directories", async () => {
    const root = await tempProject();
    await mkdir(path.join(root, "node_modules", "pkg"), { recursive: true });
    await mkdir(path.join(root, ".next"), { recursive: true });
    await writeFile(path.join(root, "node_modules", "pkg", "index.js"), "eval('x')");
    await writeFile(path.join(root, ".next", "server.js"), "eval('x')");
    await writeFile(path.join(root, "index.ts"), "export {};");

    const files = await collectFiles(root);

    expect(files.map((file) => file.path)).toEqual(["index.ts"]);
  });

  it("normalizes paths to forward slashes", async () => {
    const root = await tempProject();
    await mkdir(path.join(root, "src", "app"), { recursive: true });
    await writeFile(path.join(root, "src", "app", "route.ts"), "export {};");

    const [file] = await collectFiles(root);

    expect(file?.path).toBe("src/app/route.ts");
  });
});
