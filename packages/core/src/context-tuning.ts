import type { Confidence, Finding, FindingContext, Severity } from "./types.js";

type TuningAdjustment = {
  severity?: Severity;
  confidence?: Confidence;
  reason: string;
};

export function applyContextTuning(finding: Finding): Finding {
  const adjustment = getContextAdjustment(finding);
  if (!adjustment) {
    return finding;
  }

  const tunedSeverity = adjustment.severity ?? finding.severity;
  const tunedConfidence = adjustment.confidence ?? finding.confidence;
  const severityChanged = tunedSeverity !== finding.severity;
  const confidenceChanged = tunedConfidence !== finding.confidence;

  if (!severityChanged && !confidenceChanged) {
    return finding;
  }

  return {
    ...finding,
    severity: tunedSeverity,
    confidence: tunedConfidence,
    originalSeverity: severityChanged ? finding.severity : finding.originalSeverity,
    originalConfidence: confidenceChanged ? finding.confidence : finding.originalConfidence,
    contextAdjustmentReason: adjustment.reason
  };
}

function getContextAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.ruleId) {
    case "injection/command-exec":
      return commandExecAdjustment(finding.context);
    case "injection/raw-sql-concat":
      return rawSqlAdjustment(finding);
    case "auth/admin-route-without-auth":
      return adminRouteAdjustment(finding);
    case "auth/password-without-hashing-library":
      return passwordAdjustment(finding);
    case "upload/missing-file-type-validation":
    case "upload/missing-file-size-limit":
      return uploadAdjustment(finding);
    case "xss/dangerously-set-inner-html":
      return dangerouslySetHtmlAdjustment(finding);
    case "config/next-powered-by-header":
      return nextPoweredByHeaderAdjustment(finding.context);
    case "validation/api-route-without-validation":
      return validationAdjustment(finding.context);
    case "auth/login-without-rate-limit":
    case "auth/register-without-rate-limit":
      return authRateLimitAdjustment(finding.context);
    default:
      return undefined;
  }
}

function commandExecAdjustment(context: FindingContext | undefined): TuningAdjustment | undefined {
  switch (context) {
    case "release-tooling":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered command execution finding in release/tooling context"
      };
    case "cli-tooling":
      return {
        severity: "MEDIUM",
        confidence: "MEDIUM",
        reason: "lowered command execution finding in CLI tooling context"
      };
    case "example-code":
    case "template-code":
      return {
        severity: "MEDIUM",
        confidence: "LOW",
        reason: "lowered command execution finding in example/template context"
      };
    default:
      return undefined;
  }
}

function rawSqlAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.context) {
    case "app-code":
      if (isUiOrComponentPath(finding.filePath)) {
        return {
          severity: "MEDIUM",
          confidence: "LOW",
          reason: "lowered raw SQL finding in app component/UI context"
        };
      }

      return undefined;
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "MEDIUM",
        confidence: "LOW",
        reason: "lowered raw SQL finding in docs/example/template context"
      };
    default:
      return undefined;
  }
}

function passwordAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.context) {
    case "app-code":
      if (isUiOrComponentPath(finding.filePath)) {
        return {
          severity: "MEDIUM",
          confidence: "LOW",
          reason: "lowered password-handling finding in app component/UI context"
        };
      }

      return undefined;
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered password-handling finding in docs/example/template context"
      };
    default:
      return undefined;
  }
}

function uploadAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.context) {
    case "app-code":
      if (isUiOrComponentPath(finding.filePath)) {
        return {
          severity: "MEDIUM",
          confidence: "LOW",
          reason: "lowered upload validation finding in app component/UI context"
        };
      }

      return undefined;
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered upload validation finding in docs/example/template context"
      };
    default:
      return undefined;
  }
}

function dangerouslySetHtmlAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.context) {
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "MEDIUM",
        confidence: "LOW",
        reason: "lowered dangerouslySetInnerHTML finding in docs/example/template context"
      };
    case "app-code":
      if (isDemoStoryOrFixturePath(finding.filePath)) {
        return {
          confidence: "LOW",
          reason: "lowered dangerouslySetInnerHTML confidence in demo/story/fixture app context"
        };
      }

      if (isUiOrComponentPath(finding.filePath) && !hasExplicitUserControlledHtmlSignal(finding.evidence)) {
        return {
          confidence: "LOW",
          reason: "lowered dangerouslySetInnerHTML confidence in app component/UI context"
        };
      }

      return undefined;
    default:
      return undefined;
  }
}

function nextPoweredByHeaderAdjustment(context: FindingContext | undefined): TuningAdjustment | undefined {
  switch (context) {
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered powered-by header finding in docs/example/template context"
      };
    default:
      return undefined;
  }
}

function adminRouteAdjustment(finding: Finding): TuningAdjustment | undefined {
  switch (finding.context) {
    case "app-code":
      if (isApiRoutePath(finding.filePath)) {
        return undefined;
      }

      return {
        severity: "MEDIUM",
        confidence: "LOW",
        reason: "lowered admin route finding in non-API app component context"
      };
    case "docs-code":
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered admin route finding in docs/example/template context"
      };
    default:
      return undefined;
  }
}

function isApiRoutePath(filePath: string): boolean {
  const normalizedPath = normalizePath(filePath);
  return (
    normalizedPath.startsWith("app/api/") ||
    normalizedPath.startsWith("src/app/api/") ||
    normalizedPath.startsWith("pages/api/") ||
    /^apps\/[^/]+\/app\/api\//.test(normalizedPath) ||
    /^apps\/[^/]+\/src\/app\/api\//.test(normalizedPath) ||
    /^apps\/[^/]+\/pages\/api\//.test(normalizedPath)
  );
}

function isUiOrComponentPath(filePath: string): boolean {
  const normalizedPath = normalizePath(filePath);
  return (
    !isApiRoutePath(normalizedPath) &&
    (normalizedPath.includes("/components/") ||
      normalizedPath.includes("/component/") ||
      normalizedPath.includes("/ui/") ||
      normalizedPath.endsWith(".tsx") ||
      normalizedPath.endsWith(".jsx"))
  );
}

function isDemoStoryOrFixturePath(filePath: string): boolean {
  const normalizedPath = normalizePath(filePath);
  return /(^|\/)(demo|demos|storybook|stories|fixtures|examples)(\/|\.|$)/i.test(normalizedPath) || /\.stories\.(tsx|jsx|ts|js)$/.test(normalizedPath);
}

function hasExplicitUserControlledHtmlSignal(evidence: string | undefined): boolean {
  return /\b(userInput|searchParams|params|body|request|req|query)\b/i.test(evidence ?? "");
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

function validationAdjustment(context: FindingContext | undefined): TuningAdjustment | undefined {
  switch (context) {
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered API validation finding in example/template context"
      };
    default:
      return undefined;
  }
}

function authRateLimitAdjustment(context: FindingContext | undefined): TuningAdjustment | undefined {
  switch (context) {
    case "example-code":
    case "template-code":
      return {
        severity: "LOW",
        confidence: "LOW",
        reason: "lowered auth rate-limit finding in example/template context"
      };
    default:
      return undefined;
  }
}
