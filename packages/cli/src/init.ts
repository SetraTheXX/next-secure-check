import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { CONFIG_FILE_NAME } from "./config.js";

export const NEXT_SECURE_CHECK_WORKFLOW_PATH = ".github/workflows/next-secure-check.yml";

export type InitFileStatus = "created" | "overwritten" | "skipped";

export type InitFileResult = {
  path: string;
  status: InitFileStatus;
};

export type InitProjectOptions = {
  force?: boolean;
};

const DEFAULT_CONFIG = `${JSON.stringify({ preset: "app", format: "terminal", failOn: "high" }, null, 2)}\n`;

const DEFAULT_WORKFLOW = `name: next-secure-check

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run next-secure-check
        run: npx --yes next-secure-check@0.3.0 scan . --preset app --format github --fail-on high
`;

const INIT_FILES = [
  {
    content: DEFAULT_CONFIG,
    path: CONFIG_FILE_NAME
  },
  {
    content: DEFAULT_WORKFLOW,
    path: NEXT_SECURE_CHECK_WORKFLOW_PATH
  }
] as const;

export async function initProject(targetPath: string, options: InitProjectOptions = {}): Promise<InitFileResult[]> {
  const root = path.resolve(targetPath);
  const results: InitFileResult[] = [];

  for (const file of INIT_FILES) {
    results.push(await writeInitFile(root, file.path, file.content, options.force === true));
  }

  return results;
}

export function formatInitResults(results: InitFileResult[]): string {
  return results.map((result) => `${formatStatus(result.status)}: ${result.path}`).join("\n");
}

async function writeInitFile(root: string, relativePath: string, content: string, force: boolean): Promise<InitFileResult> {
  const filePath = path.join(root, relativePath);

  if (!force && (await fileExists(filePath))) {
    return { path: relativePath, status: "skipped" };
  }

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, content, "utf8");

  return { path: relativePath, status: force ? "overwritten" : "created" };
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function formatStatus(status: InitFileStatus): string {
  switch (status) {
    case "created":
      return "created";
    case "overwritten":
      return "overwritten";
    case "skipped":
      return "already exists, skipped";
  }
}
