import type { MiddlewareSignal, Rule } from "@next-secure-check/core";
import {
  findCommandExecutionMatches,
  findDangerouslySetInnerHtmlMatches,
  findPasswordHandlingMatches,
  findRawSqlConcatMatches,
  findRouteHandlerExports,
  findUploadRouteHandlerMatches,
  hasAuthIntentSignal,
  hasValidationIntentSignal
} from "./ast-utils.js";
import { codeFiles, configFiles, createFinding, findMatches, hasDependency } from "./rule-utils.js";

const RATE_LIMIT_SIGNAL_PATTERN =
  /\b(rateLimit|rate-limit|ratelimit|limiter|checkRateLimit|applyRateLimit|upstash|redis|slowDown|throttle)\b|\b429\b|too many requests/i;

export const envFileCommittedRule: Rule = {
  id: "secrets/env-file-committed",
  title: "Environment file committed",
  severity: "HIGH",
  category: "secrets",
  confidence: "HIGH",
  scan(context) {
    return context.files
      .filter((file) => isCommittedEnvFileName(file.path.split("/").at(-1) ?? ""))
      .map((file) =>
        createFinding({
          rule: envFileCommittedRule,
          file,
          description: "Environment files may contain secrets and should not be committed.",
          recommendation: "Remove committed environment files, rotate exposed secrets, and keep only .env.example templates in git.",
          evidence: file.path
        })
      );
  }
};

export const hardcodedSecretRule: Rule = {
  id: "secrets/hardcoded-secret",
  title: "Possible hardcoded secret detected",
  severity: "HIGH",
  category: "secrets",
  confidence: "MEDIUM",
  scan(context) {
    const findings = [];
    const secretAssignmentPattern =
      /\b(api[_-]?key|secret|token|password|private[_-]?key|stripe[_-]?key|github[_-]?token|jwt[_-]?secret)\b\s*[:=]\s*["'`]([^"'`]{8,})["'`]/i;
    const knownSecretPattern = /(sk_live_[A-Za-z0-9_]+|ghp_[A-Za-z0-9_]+|xox[baprs]-[A-Za-z0-9-]+)/i;

    for (const file of codeFiles(context)) {
      for (const match of findMatches(file, secretAssignmentPattern)) {
        knownSecretPattern.lastIndex = 0;
        if (knownSecretPattern.test(match.evidence)) {
          continue;
        }

        const literalValue = extractAssignedStringLiteral(match.evidence);
        if (literalValue && isLowSignalSecretSample(literalValue)) {
          continue;
        }

        findings.push(
          createFinding({
            rule: hardcodedSecretRule,
            file,
            line: match.line,
            column: match.column,
            evidence: match.evidence,
            description: "A secret-like variable appears to contain a literal value.",
            recommendation: "Move secrets to server-side environment variables and rotate any value that may have been exposed."
          })
        );
      }

      for (const match of findMatches(file, knownSecretPattern)) {
        findings.push(
          createFinding({
            rule: hardcodedSecretRule,
            file,
            line: match.line,
            column: match.column,
            evidence: match.evidence,
            description: "A string matches a known live secret token pattern.",
            recommendation: "Remove the token from source control and rotate it immediately.",
            confidence: "HIGH"
          })
        );
      }
    }

    return findings;
  }
};

export const weakJwtSecretRule: Rule = {
  id: "secrets/weak-jwt-secret",
  title: "Weak JWT secret detected",
  severity: "HIGH",
  category: "secrets",
  confidence: "HIGH",
  scan(context) {
    const findings = [];
    const weakValues = new Set(["secret", "changeme", "change-me", "default", "password", "test", "dev", "development"]);
    const pattern = /\bJWT_SECRET\b\s*[:=]\s*["'`]?([^"'`\s,;]{1,64})["'`]?/i;

    for (const file of context.files) {
      for (const match of findMatches(file, pattern)) {
        const value = match.evidence.split(/[:=]/).at(-1)?.replace(/["'`,;]/g, "").trim().toLowerCase() ?? "";
        if (value.length < 32 || weakValues.has(value)) {
          findings.push(
            createFinding({
              rule: weakJwtSecretRule,
              file,
              line: match.line,
              column: match.column,
              evidence: match.evidence,
              description: "JWT secrets should be long, random, and unique per environment.",
              recommendation: "Use a high-entropy secret of at least 32 bytes and rotate weak/default values."
            })
          );
        }
      }
    }

    return findings;
  }
};

export const noEvalRule: Rule = {
  id: "injection/no-eval",
  title: "eval() usage detected",
  severity: "HIGH",
  category: "injection",
  confidence: "HIGH",
  scan(context) {
    return codeFiles(context).flatMap((file) =>
      findMatches(file, /\beval\s*\(/)
        .filter((match) => !isInsideQuotedLiteral(match.evidence, match.column))
        .map((match) =>
          createFinding({
            rule: noEvalRule,
            file,
            line: match.line,
            column: match.column,
            evidence: match.evidence,
            description: "eval() can execute untrusted code and may lead to code injection.",
            recommendation: "Replace eval() with explicit parsing or a safe interpreter for the expected input."
          })
        )
    );
  }
};

export const dangerouslySetInnerHtmlRule: Rule = {
  id: "xss/dangerously-set-inner-html",
  title: "dangerouslySetInnerHTML usage detected",
  severity: "LOW",
  category: "xss",
  confidence: "HIGH",
  scan(context) {
    return codeFiles(context).flatMap((file) =>
      findDangerouslySetInnerHtmlMatches(file).map((match) =>
        createFinding({
          rule: {
            ...dangerouslySetInnerHtmlRule,
            severity: match.severity
          },
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Rendering raw HTML can introduce XSS if the content is user-controlled.",
          recommendation: "Avoid raw HTML rendering or sanitize trusted markup with a proven sanitizer."
        })
      )
    );
  }
};

export const insecureCorsWildcardRule: Rule = {
  id: "config/insecure-cors-wildcard",
  title: "Wildcard CORS origin detected",
  severity: "MEDIUM",
  category: "config",
  confidence: "HIGH",
  scan(context) {
    const pattern = /(Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["'])/i;

    return codeFiles(context).flatMap((file) =>
      findMatches(file, pattern).map((match) =>
        createFinding({
          rule: insecureCorsWildcardRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Wildcard CORS allows any origin to access the endpoint.",
          recommendation: "Restrict CORS origins to trusted domains and avoid credentials with wildcard origins."
        })
      )
    );
  }
};

export const loginWithoutRateLimitRule: Rule = {
  id: "auth/login-without-rate-limit",
  title: "Login endpoint may be missing rate limiting",
  severity: "HIGH",
  category: "auth",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context)
      .filter((file) => /(login|signin|sign-in|auth)/i.test(file.path))
      .filter((file) => !hasRateLimitSignal(file.content))
      .filter((file) => !isRouteProtectedByMiddleware(context.middleware, file.path, "rate-limit"))
      .map((file) =>
        createFinding({
          rule: loginWithoutRateLimitRule,
          file,
          description: "Authentication endpoints are common brute-force targets and should be rate limited.",
          recommendation: "Add per-IP and per-account rate limiting to login/auth endpoints."
        })
      );
  }
};

export const registerWithoutRateLimitRule: Rule = {
  id: "auth/register-without-rate-limit",
  title: "Register endpoint may be missing rate limiting",
  severity: "HIGH",
  category: "auth",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context)
      .filter((file) => /(register|signup|sign-up|create-account)/i.test(file.path))
      .filter((file) => !hasRateLimitSignal(file.content))
      .filter((file) => !isRouteProtectedByMiddleware(context.middleware, file.path, "rate-limit"))
      .map((file) =>
        createFinding({
          rule: registerWithoutRateLimitRule,
          file,
          description:
            "Registration endpoints can be abused for spam accounts, brute force, or resource exhaustion and should be rate limited.",
          recommendation: "Add per-IP and abuse-aware rate limiting to registration/signup endpoints."
        })
      );
  }
};

export const passwordWithoutHashingRule: Rule = {
  id: "auth/password-without-hashing-library",
  title: "Password handling without bcrypt or argon2 detected",
  severity: "MEDIUM",
  category: "auth",
  confidence: "MEDIUM",
  scan(context) {
    if (hasDependency(context, ["bcrypt", "bcryptjs", "argon2"])) {
      return [];
    }

    return codeFiles(context).flatMap((file) =>
      findPasswordHandlingMatches(file).map((match) =>
        createFinding({
          rule: passwordWithoutHashingRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Password-related code exists, but bcrypt/argon2 dependency usage was not detected.",
          recommendation: "Hash passwords with argon2 or bcrypt and avoid storing or comparing plaintext passwords."
        })
      )
    );
  }
};

export const rawSqlConcatRule: Rule = {
  id: "injection/raw-sql-concat",
  title: "Possible raw SQL string interpolation detected",
  severity: "HIGH",
  category: "injection",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context).flatMap((file) =>
      findRawSqlConcatMatches(file).map((match) =>
        createFinding({
          rule: rawSqlConcatRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "SQL built with string interpolation or concatenation can lead to SQL injection.",
          recommendation: "Use parameterized queries, prepared statements, or a safe ORM query builder."
        })
      )
    );
  }
};

export const missingSecurityHeadersRule: Rule = {
  id: "headers/missing-security-headers",
  title: "Security headers were not detected",
  severity: "LOW",
  category: "headers",
  confidence: "LOW",
  scan(context) {
    if (context.project.framework !== "nextjs") {
      return [];
    }

    const configuredHeaders = getConfiguredSecurityHeaders(configFiles(context).map((file) => file.content).join("\n"));
    if (configuredHeaders.missing.length === 0) {
      return [];
    }

    const anchorFile = context.files.find((file) => file.path === "package.json") ?? context.files[0];
    if (!anchorFile) {
      return [];
    }

    return [
      createFinding({
        rule: missingSecurityHeadersRule,
        file: anchorFile,
        description: `Missing common security header configuration: ${configuredHeaders.missing.join(", ")}.`,
        recommendation:
          "Configure Content-Security-Policy, frame protection, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
      })
    ];
  }
};

export const nextPublicSecretRule: Rule = {
  id: "secrets/next-public-secret",
  title: "NEXT_PUBLIC secret-like value requires review",
  severity: "HIGH",
  category: "secrets",
  confidence: "MEDIUM",
  scan(context) {
    const pattern = /NEXT_PUBLIC_(?:[A-Z0-9_]*)(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|JWT|STRIPE_SECRET)(?:[A-Z0-9_]*)\s*[:=]/i;

    return context.files.flatMap((file) =>
      findMatches(file, pattern).map((match) =>
        createFinding({
          rule: nextPublicSecretRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description:
            "NEXT_PUBLIC values are exposed to browser-side code in Next.js. This finding is a review signal based on a secret-like variable name, not proof that the assigned value is a credential.",
          recommendation:
            "Review the assigned value and its intended audience. Keep credentials in server-only environment variables and remove the NEXT_PUBLIC prefix; if the value is intentionally public, use a name that does not imply a secret."
        })
      )
    );
  }
};

export const noNewFunctionRule: Rule = {
  id: "injection/no-new-function",
  title: "new Function() usage detected",
  severity: "HIGH",
  category: "injection",
  confidence: "HIGH",
  scan(context) {
    return codeFiles(context).flatMap((file) =>
      findMatches(file, /\bnew\s+Function\s*\(/)
        .filter((match) => !isInsideQuotedLiteral(match.evidence, match.column))
        .map((match) =>
          createFinding({
            rule: noNewFunctionRule,
            file,
            line: match.line,
            column: match.column,
            evidence: match.evidence,
            description: "new Function() can execute dynamically generated code and may lead to code injection if input is untrusted.",
            recommendation: "Avoid dynamic code execution. Replace new Function() with explicit logic or a safe parser for the expected input."
          })
        )
    );
  }
};

export const commandExecRule: Rule = {
  id: "injection/command-exec",
  title: "Shell command execution detected",
  severity: "HIGH",
  category: "injection",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context).flatMap((file) =>
      findCommandExecutionMatches(file).map((match) =>
        createFinding({
          rule: commandExecRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Shell command execution can lead to command injection if user input reaches the command or arguments.",
          recommendation: "Avoid shell execution for user-controlled input. Use safe APIs, strict allowlists, and argument arrays when command execution is required."
        })
      )
    );
  }
};

export const missingFileTypeValidationRule: Rule = {
  id: "upload/missing-file-type-validation",
  title: "Upload endpoint may be missing file type validation",
  severity: "MEDIUM",
  category: "upload",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context).flatMap((file) => {
      if (hasFileTypeValidationSignal(file.content)) {
        return [];
      }

      return findUploadRouteHandlerMatches(file).map((match) =>
        createFinding({
          rule: missingFileTypeValidationRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Upload endpoints should validate file types before accepting user-controlled files.",
          recommendation:
            "Validate MIME type and file extension with an allowlist before storing or processing uploaded files."
        })
      );
    });
  }
};

export const missingFileSizeLimitRule: Rule = {
  id: "upload/missing-file-size-limit",
  title: "Upload endpoint may be missing file size limit",
  severity: "MEDIUM",
  category: "upload",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context).flatMap((file) => {
      if (hasFileSizeLimitSignal(file.content)) {
        return [];
      }

      return findUploadRouteHandlerMatches(file).map((match) =>
        createFinding({
          rule: missingFileSizeLimitRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Upload endpoints should enforce file size limits to reduce abuse and resource exhaustion risk.",
          recommendation:
            "Add a strict maximum file size and reject files that exceed it before storage or further processing."
        })
      );
    });
  }
};

export const apiRouteWithoutValidationRule: Rule = {
  id: "validation/api-route-without-validation",
  title: "API route may be missing input validation",
  severity: "MEDIUM",
  category: "validation",
  confidence: "MEDIUM",
  scan(context) {
    const pathSignals = /\b(app\/api|pages\/api)\b/i;
    const contentSignals = /(\breq\.body\b|\breq\.query\b|\breq\.json\(|request\.json\(|request\.formData\(|searchParams|nextUrl\.searchParams)/i;

    return codeFiles(context)
      .filter((file) => pathSignals.test(file.path))
      .filter((file) => contentSignals.test(file.content))
      .filter((file) => !hasValidationIntentSignal(file))
      .map((file) =>
        createFinding({
          rule: apiRouteWithoutValidationRule,
          file,
          description: "API routes that consume user input should validate the input before using it.",
          recommendation: "Add input validation with a schema library such as Zod, Yup, Joi, or a clear custom validation layer."
        })
      );
  }
};

export const adminRouteWithoutAuthRule: Rule = {
  id: "auth/admin-route-without-auth",
  title: "Admin route may be missing auth protection",
  severity: "HIGH",
  category: "auth",
  confidence: "MEDIUM",
  scan(context) {
    return codeFiles(context).flatMap((file) => {
      if (!isAdminApiRoutePath(file.path) || hasAuthIntentSignal(file)) {
        return [];
      }

      if (isRouteProtectedByMiddleware(context.middleware, file.path, "auth")) {
        return [];
      }

      const routeHandlers = findRouteHandlerExports(file);
      const [match] = routeHandlers;
      if (!match) {
        return [];
      }

      return [
        createFinding({
          rule: adminRouteWithoutAuthRule,
          file,
          line: match.line,
          column: match.column,
          evidence: match.evidence,
          description: "Admin routes should include authentication and authorization checks.",
          recommendation: "Protect admin routes with authentication and role/permission checks before returning sensitive data."
        })
      ];
    });
  }
};

export const productionBrowserSourceMapsRule: Rule = {
  id: "config/production-browser-source-maps",
  title: "Production browser source maps may be enabled",
  severity: "LOW",
  category: "config",
  confidence: "HIGH",
  scan(context) {
    const nextConfigFiles = configFiles(context).filter((file) => /next\.config\.(js|mjs|cjs|ts)$/.test(file.path));
    const findings = [];

    for (const file of nextConfigFiles) {
      if (/productionBrowserSourceMaps\s*[:=]\s*true/i.test(file.content)) {
        findings.push(
          createFinding({
            rule: productionBrowserSourceMapsRule,
            file,
            description: "Production browser source maps can expose source code structure and make client-side code easier to inspect.",
            recommendation: "Disable productionBrowserSourceMaps unless you intentionally need public production source maps."
          })
        );
      }
    }

    return findings;
  }
};

export const nextPoweredByHeaderRule: Rule = {
  id: "config/next-powered-by-header",
  title: "X-Powered-By header may be enabled",
  severity: "INFO",
  category: "config",
  confidence: "MEDIUM",
  scan(context) {
    if (context.project.framework !== "nextjs") {
      return [];
    }

    const nextConfigFiles = configFiles(context)
      .filter((file) => /next\.config\.(js|mjs|cjs|ts)$/.test(file.path))
      .filter((file) => shouldCheckPoweredByHeaderConfig(file.path, context.files));
    
    if (nextConfigFiles.length === 0) {
      return [];
    }

    const findings = [];
    for (const file of nextConfigFiles) {
      if (!/poweredByHeader\s*:\s*false/i.test(file.content)) {
        findings.push(
          createFinding({
            rule: nextPoweredByHeaderRule,
            file,
            description: "The default X-Powered-By header can reveal framework information. Hiding it is a small hardening step.",
            recommendation: "Set poweredByHeader: false in next.config.js to reduce framework fingerprinting."
          })
        );
      }
    }

    return findings;
  }
};

export const builtInSecurityRules: Rule[] = [
  envFileCommittedRule,
  hardcodedSecretRule,
  weakJwtSecretRule,
  noEvalRule,
  noNewFunctionRule,
  commandExecRule,
  dangerouslySetInnerHtmlRule,
  insecureCorsWildcardRule,
  loginWithoutRateLimitRule,
  passwordWithoutHashingRule,
  rawSqlConcatRule,
  missingSecurityHeadersRule,
  nextPublicSecretRule,
  registerWithoutRateLimitRule,
  missingFileTypeValidationRule,
  missingFileSizeLimitRule,
  apiRouteWithoutValidationRule,
  adminRouteWithoutAuthRule,
  productionBrowserSourceMapsRule,
  nextPoweredByHeaderRule
];

function shouldCheckPoweredByHeaderConfig(configPath: string, files: Array<{ path: string }>): boolean {
  const normalizedPath = normalizeRulePath(configPath);
  if (isLowSignalNextConfigPath(normalizedPath)) {
    return false;
  }

  const configRoot = normalizedPath.replace(/(^|\/)next\.config\.(js|mjs|cjs|ts)$/, "").replace(/\/$/, "");
  if (configRoot === normalizedPath) {
    return false;
  }

  if (configRoot === "") {
    return true;
  }

  return hasNextAppIndicator(configRoot, files);
}

function isLowSignalNextConfigPath(filePath: string): boolean {
  return (
    filePath.startsWith("examples/") ||
    filePath.includes("/examples/") ||
    filePath.startsWith("templates/") ||
    filePath.includes("/templates/") ||
    filePath.startsWith("fixtures/") ||
    filePath.includes("/fixtures/") ||
    filePath.startsWith("docs/") ||
    filePath.includes("/docs/") ||
    filePath.includes("/__tests__/") ||
    filePath.includes("/test/") ||
    filePath.includes("/tests/")
  );
}

function hasNextAppIndicator(configRoot: string, files: Array<{ path: string }>): boolean {
  const appIndicators = ["app/", "src/app/", "pages/", "src/pages/"];
  const normalizedRoot = configRoot === "" ? "" : `${configRoot}/`;

  return files.some((file) => {
    const filePath = normalizeRulePath(file.path);
    if (!filePath.startsWith(normalizedRoot) || filePath === `${normalizedRoot}next.config.js`) {
      return false;
    }

    const relativePath = filePath.slice(normalizedRoot.length);
    return appIndicators.some((indicator) => relativePath.startsWith(indicator));
  });
}

function normalizeRulePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

function isInsideQuotedLiteral(line: string, column: number): boolean {
  const beforeMatch = line.slice(0, Math.max(0, column - 1));
  let quote: "'" | "\"" | "`" | undefined;
  let escaped = false;

  for (const char of beforeMatch) {
    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = undefined;
      }
      continue;
    }

    if (char === "'" || char === "\"" || char === "`") {
      quote = char;
    }
  }

  return quote !== undefined;
}

function isMethodCall(line: string, column: number): boolean {
  const beforeMatch = line.slice(0, Math.max(0, column - 1));
  return /\.\s*$/.test(beforeMatch);
}

function isCommittedEnvFileName(fileName: string): boolean {
  return /^\.env(?:\.(?:local|production|production\.local|development|development\.local|test|test\.local|staging|staging\.local))?$/.test(
    fileName
  );
}

function getConfiguredSecurityHeaders(content: string): { missing: string[] } {
  const requiredHeaders = [
    {
      name: "Content-Security-Policy",
      detected: /Content-Security-Policy/i.test(content)
    },
    {
      name: "frame protection",
      detected: /X-Frame-Options/i.test(content) || /frame-ancestors/i.test(content)
    },
    {
      name: "X-Content-Type-Options",
      detected: /X-Content-Type-Options/i.test(content)
    },
    {
      name: "Referrer-Policy",
      detected: /Referrer-Policy/i.test(content)
    },
    {
      name: "Permissions-Policy",
      detected: /Permissions-Policy/i.test(content)
    }
  ];

  return {
    missing: requiredHeaders.filter((header) => !header.detected).map((header) => header.name)
  };
}

function extractAssignedStringLiteral(line: string): string | undefined {
  const match = /[:=]\s*["'`]([^"'`]*)["'`]/.exec(line);
  return match?.[1];
}

function isLowSignalSecretSample(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  const sampleWords = ["password", "changeme", "change-me", "example", "demo", "dummy", "placeholder", "test"];

  if (sampleWords.includes(normalized)) {
    return true;
  }

  if (/^(?:test|demo|dummy|example|placeholder)[-_]?\d*$/i.test(normalized)) {
    return true;
  }

  if (/^\d+$/.test(normalized)) {
    return true;
  }

  if (normalized.length < 16 && countCharacterClasses(normalized) <= 2) {
    return true;
  }

  return false;
}

function isAdminApiRoutePath(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  return (
    /^app\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/.*)?\/route\.[tj]s$/i.test(normalizedPath) ||
    /^src\/app\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/.*)?\/route\.[tj]s$/i.test(normalizedPath) ||
    /^pages\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/|$).*\.([tj]s)$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/app\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/.*)?\/route\.[tj]s$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/src\/app\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/.*)?\/route\.[tj]s$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/pages\/api\/(?:.*\/)?(?:admin|dashboard|manage)(?:\/|$).*\.([tj]s)$/i.test(normalizedPath)
  );
}

function isRouteProtectedByMiddleware(
  middlewareSignals: MiddlewareSignal[] | undefined,
  filePath: string,
  signalType: "auth" | "rate-limit"
): boolean {
  const routePath = routePathFromFilePath(filePath);
  if (!routePath) {
    return false;
  }

  return (middlewareSignals ?? []).some((signal) => {
    const hasSignal = signalType === "auth" ? signal.hasAuthSignal : signal.hasRateLimitSignal;
    return hasSignal && signal.matchers.some((matcher) => middlewareMatcherCoversRoute(matcher, routePath));
  });
}

function routePathFromFilePath(filePath: string): string | undefined {
  const normalizedPath = filePath.replace(/\\/g, "/");
  const appRouteMatch = /^(?:apps\/[^/]+\/)?(?:src\/)?app\/api\/(.+)\/route\.[tj]s$/i.exec(normalizedPath);
  if (appRouteMatch?.[1]) {
    return `/api/${appRouteMatch[1]}`;
  }

  const pagesRouteMatch = /^(?:apps\/[^/]+\/)?pages\/api\/(.+)\.[tj]s$/i.exec(normalizedPath);
  if (pagesRouteMatch?.[1]) {
    return `/api/${pagesRouteMatch[1]}`;
  }

  return undefined;
}

function middlewareMatcherCoversRoute(matcher: string, routePath: string): boolean {
  const normalizedMatcher = normalizeMiddlewareMatcher(matcher);
  if (!normalizedMatcher.startsWith("/")) {
    return false;
  }

  const prefix = normalizedMatcher.replace(/\/:path\*$/, "");
  return routePath === prefix || routePath.startsWith(`${prefix}/`);
}

function normalizeMiddlewareMatcher(matcher: string): string {
  return matcher.trim().replace(/\/+$/, "") || "/";
}

function hasRateLimitSignal(content: string): boolean {
  return RATE_LIMIT_SIGNAL_PATTERN.test(content);
}

function hasFileTypeValidationSignal(content: string): boolean {
  return /\b(mimetype|mimeType|fileType|allowedTypes|allowedMimeTypes|allowedExtensions|extension|extname|accept)\b|\.type\b|\.mime\b|content-type|includes\(\s*file\.type|startsWith\(["']image\//i.test(
    content
  );
}

function hasFileSizeLimitSignal(content: string): boolean {
  return /\b(maxSize|maxFileSize|sizeLimit|fileSize|MAX_FILE_SIZE)\b|limit\s*[:=]|\.limit\b|\.size\s*[><=]/i.test(content);
}

function countCharacterClasses(value: string): number {
  return [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value)
  ].filter(Boolean).length;
}
