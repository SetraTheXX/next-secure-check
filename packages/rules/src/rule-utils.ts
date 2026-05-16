import type { Confidence, Finding, Rule, ScanContext, SourceFile } from "@next-secure-check/core";

export type FindingInput = {
  rule: Pick<Rule, "id" | "title" | "severity" | "category"> & { confidence?: Confidence };
  file: Pick<SourceFile, "path" | "content" | "lines">;
  line?: number;
  column?: number;
  evidence?: string;
  description: string;
  recommendation: string;
  confidence?: Confidence;
  references?: string[];
};

export function createFinding(input: FindingInput): Finding {
  return {
    id: `${input.rule.id}:${input.file.path}:${input.line ?? 0}:${input.column ?? 0}`,
    ruleId: input.rule.id,
    title: input.rule.title,
    severity: input.rule.severity,
    confidence: input.confidence ?? input.rule.confidence ?? "MEDIUM",
    category: input.rule.category,
    filePath: input.file.path,
    line: input.line,
    column: input.column,
    evidence: input.evidence,
    description: input.description,
    recommendation: input.recommendation,
    references: input.references
  };
}

export function findMatches(file: SourceFile, pattern: RegExp): Array<{ line: number; column: number; evidence: string }> {
  const matches: Array<{ line: number; column: number; evidence: string }> = [];
  const matcher = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);

  file.lines.forEach((lineContent, lineIndex) => {
    matcher.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = matcher.exec(lineContent)) !== null) {
      matches.push({
        line: lineIndex + 1,
        column: match.index + 1,
        evidence: lineContent.trim()
      });

      if (match[0].length === 0) {
        matcher.lastIndex += 1;
      }
    }
  });

  pattern.lastIndex = 0;

  return matches;
}

export function hasDependency(context: ScanContext, packageNames: string[]): boolean {
  const dependencies = {
    ...(context.packageJson?.dependencies ?? {}),
    ...(context.packageJson?.devDependencies ?? {})
  };

  return packageNames.some((packageName) => packageName in dependencies);
}

export function projectContains(context: ScanContext, pattern: RegExp): boolean {
  return context.files.some((file) => {
    pattern.lastIndex = 0;
    return pattern.test(file.content);
  });
}

export function codeFiles(context: ScanContext): SourceFile[] {
  return context.files.filter((file) => /\.(ts|tsx|js|jsx)$/.test(file.path));
}

export function configFiles(context: ScanContext): SourceFile[] {
  return context.files.filter((file) => /(^|\/)(next\.config\.(js|mjs|ts)|middleware\.(js|ts))$/.test(file.path));
}
