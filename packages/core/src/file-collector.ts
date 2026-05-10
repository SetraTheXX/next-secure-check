import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { SourceFile } from "./types.js";

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".next",
  ".turbo",
  ".vercel",
  "build",
  "coverage",
  "dist",
  "node_modules"
]);

const INCLUDED_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".json"]);
const INCLUDED_FILENAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.example",
  "middleware.js",
  "middleware.ts",
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "package.json"
]);

export async function collectFiles(rootPath: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  await walk(rootPath, rootPath, files);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function walk(rootPath: string, currentPath: string, files: SourceFile[]): Promise<void> {
  const entries = await readdir(currentPath, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) {
      continue;
    }

    const absolutePath = path.join(currentPath, entry.name);

    if (entry.isDirectory()) {
      await walk(rootPath, absolutePath, files);
      continue;
    }

    if (!entry.isFile() || !shouldInclude(entry.name)) {
      continue;
    }

    const fileStat = await stat(absolutePath);
    if (fileStat.size > 1024 * 1024) {
      continue;
    }

    const content = await readFile(absolutePath, "utf8");
    files.push({
      path: normalizePath(path.relative(rootPath, absolutePath)),
      absolutePath,
      content,
      lines: content.split(/\r?\n/)
    });
  }
}

function shouldInclude(fileName: string): boolean {
  if (INCLUDED_FILENAMES.has(fileName)) {
    return true;
  }

  return INCLUDED_EXTENSIONS.has(path.extname(fileName));
}

export function normalizePath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}
