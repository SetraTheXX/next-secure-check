import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { SourceFile } from "./types.js";

type CollectFilesOptions = {
  excludePaths?: string[];
};

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

export async function collectFiles(rootPath: string, options: CollectFilesOptions = {}): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  const excludeMatchers = createExcludeMatchers(options.excludePaths);
  await walk(rootPath, rootPath, files, excludeMatchers);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function walk(
  rootPath: string,
  currentPath: string,
  files: SourceFile[],
  excludeMatchers: RegExp[]
): Promise<void> {
  const entries = await readdir(currentPath, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) {
      continue;
    }

    const absolutePath = path.join(currentPath, entry.name);

    if (entry.isDirectory()) {
      await walk(rootPath, absolutePath, files, excludeMatchers);
      continue;
    }

    if (!entry.isFile() || !shouldInclude(entry.name)) {
      continue;
    }

    const relativePath = normalizePath(path.relative(rootPath, absolutePath));
    if (isExcluded(relativePath, excludeMatchers)) {
      continue;
    }

    const fileStat = await stat(absolutePath);
    if (fileStat.size > 1024 * 1024) {
      continue;
    }

    const content = await readFile(absolutePath, "utf8");
    files.push({
      path: relativePath,
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

function isExcluded(relativePath: string, excludeMatchers: RegExp[]): boolean {
  return excludeMatchers.some((matcher) => matcher.test(relativePath));
}

function createExcludeMatchers(patterns: string[] | undefined): RegExp[] {
  return (patterns ?? [])
    .map((pattern) => normalizeExcludePattern(pattern))
    .filter((pattern) => pattern.length > 0)
    .map((pattern) => globToRegExp(pattern));
}

function normalizeExcludePattern(pattern: string): string {
  return pattern.trim().replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

function globToRegExp(pattern: string): RegExp {
  let source = "^";

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];
    const afterNext = pattern[index + 2];

    if (char === "*" && next === "*" && afterNext === "/") {
      source += "(?:.*/)?";
      index += 2;
      continue;
    }

    if (char === "*" && next === "*") {
      source += ".*";
      index += 1;
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    if (char === "?") {
      source += "[^/]";
      continue;
    }

    source += escapeRegExp(char);
  }

  return new RegExp(`${source}$`);
}

function escapeRegExp(char: string): string {
  return /[\\^$.*+?()[\]{}|]/.test(char) ? `\\${char}` : char;
}
