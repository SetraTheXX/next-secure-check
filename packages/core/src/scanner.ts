import { access, stat } from "node:fs/promises";
import path from "node:path";
import { classifyFileContext } from "./context-classifier.js";
import { applyContextTuning } from "./context-tuning.js";
import { collectFiles } from "./file-collector.js";
import { detectProject } from "./project-detector.js";
import { summarizeFindings } from "./score.js";
import type { Finding, MiddlewareSignal, Rule, ScanContext, ScanOptions, ScanResult, SourceFile } from "./types.js";

const KNOWN_AUTH_MODULE_PATTERN = /(?:^|["'\s])(?:next-auth(?:\/|["'])|@auth(?:\/|["'])|@clerk\/nextjs(?:\/|["'])|@supabase\/(?:ssr|auth-helpers-nextjs)(?:\/|["'])|better-auth(?:\/|["']))/i;
const KNOWN_RATE_LIMIT_MODULE_PATTERN = /(?:^|["'\s])(?:@upstash\/ratelimit|rate-limiter-flexible|express-rate-limit|@arcjet\/next)(?:\/|["'])/i;

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
    middleware: extractMiddlewareSignals(files),
    packageJson: detection.packageJson
  };
  const findings = sortFindings(
    applyContextTuningToFindings(
      enrichFindingsWithContext(await runRules(rules, context)),
      options.contextTuning ?? "standard"
    )
  );

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

function enrichFindingsWithContext(findings: Finding[]): Finding[] {
  return findings.map((finding) => {
    const classification = classifyFileContext(finding.filePath);

    return {
      ...finding,
      context: classification.context,
      contextReason: classification.contextReason
    };
  });
}

function applyContextTuningToFindings(findings: Finding[], contextTuning: NonNullable<ScanOptions["contextTuning"]>): Finding[] {
  if (contextTuning === "off") {
    return findings;
  }

  return findings.map((finding) => applyContextTuning(finding));
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

function extractMiddlewareSignals(files: SourceFile[]): MiddlewareSignal[] {
  return files.filter(isMiddlewareFile).map((file) => ({
    filePath: file.path,
    hasAuthSignal: hasMiddlewareAuthSignal(file.content),
    hasRateLimitSignal: hasMiddlewareRateLimitSignal(file.content),
    matchers: extractMiddlewareMatchers(file.content),
    scopeRoot: middlewareScopeRoot(file.path) ?? ""
  }));
}

function isMiddlewareFile(file: SourceFile): boolean {
  return middlewareScopeRoot(file.path) !== undefined;
}

function middlewareScopeRoot(filePath: string): string | undefined {
  if (/^(?:src\/)?middleware\.[tj]s$/.test(filePath)) {
    return "";
  }

  return /^((?:apps|packages)\/[^/]+)\/(?:src\/)?middleware\.[tj]s$/.exec(filePath)?.[1];
}

function hasMiddlewareAuthSignal(content: string): boolean {
  const code = extractMiddlewareCode(stripCommentsAndStrings(content));
  const sourceWithoutComments = stripComments(content);
  const hasAuthCall = /\b(?:requireAuth|currentUser|getServerSession|verifyToken|isAdmin|withAuth|clerkMiddleware)\s*\(/i.test(code);
  const hasKnownModuleAuthCall = hasKnownAuthImport(sourceWithoutComments) && /\b(?:auth|clerk|getUser)\s*\(/i.test(code);
  const hasAuthGuard = /\b(?:if|while)\s*\([^)]*\b(?:session|user|account|claims)(?:\.|\?\.)\s*(?:role|permission)\b/i.test(code);

  return hasAuthCall || hasKnownModuleAuthCall || hasAuthGuard || /\b(?:auth|jwt|session|token)\s*\.\s*verify\s*\(/i.test(code);
}

function hasMiddlewareRateLimitSignal(content: string): boolean {
  const code = extractMiddlewareCode(stripCommentsAndStrings(content));
  const sourceWithoutComments = stripComments(content);
  const hasDirectLimiterCall = /\b(?:applyRateLimit|checkRateLimit|enforceRateLimit|rateLimit|rateLimited|slowDown|throttle|withRateLimit)\s*\(/i.test(
    code
  );
  const hasLimiterMethodCall = /\b(?:limiter|rateLimit|rateLimiter|ratelimit|redis|throttle|upstash)\s*\.\s*(?:check|consume|limit|rateLimit)\s*\(/i.test(
    code
  );
  const hasKnownModuleLimiterCall = KNOWN_RATE_LIMIT_MODULE_PATTERN.test(sourceWithoutComments) && /\.\s*limit\s*\(/i.test(code);
  const hasRateLimitResponse =
    /\b(?:new\s+)?(?:Response|NextResponse)\s*(?:\.\s*\w+)?\s*\([\s\S]{0,600}?\bstatus\s*:\s*429\b/i.test(code) ||
    /\b(?:res|response|reply)\s*\.\s*status\s*\(\s*429\s*\)/i.test(code) ||
    /\bstatusCode\s*=\s*429\b/i.test(code);

  return hasDirectLimiterCall || hasLimiterMethodCall || hasKnownModuleLimiterCall || hasRateLimitResponse;
}

function extractMiddlewareMatchers(content: string): string[] {
  const matcherProperty = /matcher\s*:\s*(\[[^\]]+\]|["'`][^"'`]+["'`])/s.exec(stripComments(content));
  if (!matcherProperty) {
    return [];
  }

  const matcherValue = matcherProperty[1] ?? "";
  return [...matcherValue.matchAll(/["'`]([^"'`]+)["'`]/g)].map((match) => match[1] ?? "").filter(Boolean);
}

function stripComments(content: string): string {
  return content.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, (match) => match.replace(/[^\r\n]/g, " "));
}

function stripCommentsAndStrings(content: string): string {
  return content.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g,
    (match) => match.replace(/[^\r\n]/g, " ")
  );
}

function extractMiddlewareCode(code: string): string {
  const functionMatch = /\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+middleware\s*\([^)]*\)\s*\{/i.exec(code);
  if (functionMatch) {
    const openBraceIndex = code.indexOf("{", functionMatch.index);
    return code.slice(functionMatch.index, findMatchingBrace(code, openBraceIndex) + 1);
  }

  const arrowMatch = /\b(?:export\s+)?(?:const|let|var)\s+middleware\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/i.exec(code);
  if (!arrowMatch) {
    return code;
  }

  const bodyStart = arrowMatch.index + arrowMatch[0].length;
  if (code[bodyStart] === "{") {
    return code.slice(arrowMatch.index, findMatchingBrace(code, bodyStart) + 1);
  }

  const statementEnd = code.indexOf(";", bodyStart);
  return code.slice(arrowMatch.index, statementEnd === -1 ? code.length : statementEnd);
}

function findMatchingBrace(code: string, openBraceIndex: number): number {
  if (openBraceIndex < 0) {
    return code.length - 1;
  }

  let depth = 0;
  for (let index = openBraceIndex; index < code.length; index += 1) {
    if (code[index] === "{") {
      depth += 1;
    } else if (code[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }

  return code.length - 1;
}

function hasKnownAuthImport(content: string): boolean {
  const importPattern = /\bimport\s+(?:\{([^}]*)\}|([A-Za-z_$][\w$]*))\s+from\s*["']([^"']+)["']/g;

  for (const match of content.matchAll(importPattern)) {
    const namedBindings = match[1] ?? "";
    const defaultBinding = match[2] ?? "";
    const moduleName = match[3] ?? "";
    const containsAuthBinding =
      hasNamedAuthBinding(namedBindings) || /^(?:auth|clerk|getUser)$/i.test(defaultBinding);

    if (containsAuthBinding && KNOWN_AUTH_MODULE_PATTERN.test(`\"${moduleName}\"`)) {
      return true;
    }
  }

  return false;
}

function hasNamedAuthBinding(namedBindings: string): boolean {
  return namedBindings.split(",").some((binding) => {
    const importedName = binding.trim().split(/\s+as\s+/i)[0]?.trim() ?? "";
    return /^(?:auth|clerk|getUser)$/i.test(importedName);
  });
}
