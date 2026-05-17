import { access, stat } from "node:fs/promises";
import path from "node:path";
import { collectFiles } from "./file-collector.js";
import { detectProject } from "./project-detector.js";
import { summarizeFindings } from "./score.js";
import type { Finding, Rule, ScanContext, ScanOptions, ScanResult } from "./types.js";

export async function scanProject(targetPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = Date.now();
  const rootPath = await resolveProjectPath(targetPath);
  const files = await collectFiles(rootPath, {
    excludePaths: options.excludePaths
  });
  const detection = detectProject(files, rootPath);
  const categories = normalizeCategories(options.categories);
  const rules = (options.rules ?? []).filter((rule) => categories.size === 0 || categories.has(rule.category));
  const context: ScanContext = {
    targetPath,
    rootPath,
    files,
    project: detection.project,
    packageJson: detection.packageJson
  };
  const findings = sortFindings(await runRules(rules, context));

  return {
    project: detection.project,
    summary: summarizeFindings(findings),
    findings,
    metadata: {
      scannedAt: new Date(startedAt).toISOString(),
      durationMs: Date.now() - startedAt,
      toolVersion: options.toolVersion ?? "0.0.0"
    }
  };
}

export async function resolveProjectPath(targetPath: string): Promise<string> {
  const rootPath = path.resolve(targetPath);
  await access(rootPath);
  const rootStat = await stat(rootPath);

  if (!rootStat.isDirectory()) {
    throw new Error(`Scan target must be a directory: ${targetPath}`);
  }

  return rootPath;
}

async function runRules(rules: Rule[], context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const rule of rules) {
    findings.push(...(await rule.scan(context)));
  }

  return findings;
}

function normalizeCategories(categories?: string[]): Set<string> {
  return new Set((categories ?? []).map((category) => category.trim()).filter(Boolean));
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const fileCompare = a.filePath.localeCompare(b.filePath);
    if (fileCompare !== 0) {
      return fileCompare;
    }

    return (a.line ?? 0) - (b.line ?? 0) || a.ruleId.localeCompare(b.ruleId);
  });
}
