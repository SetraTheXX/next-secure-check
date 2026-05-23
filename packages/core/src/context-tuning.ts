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
      return rawSqlAdjustment(finding.context);
    case "auth/admin-route-without-auth":
      return adminRouteAdjustment(finding);
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

function rawSqlAdjustment(context: FindingContext | undefined): TuningAdjustment | undefined {
  switch (context) {
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
  const normalizedPath = filePath.replace(/\\/g, "/").replace(/^\.\//, "");
  return (
    normalizedPath.startsWith("app/api/") ||
    normalizedPath.startsWith("src/app/api/") ||
    normalizedPath.startsWith("pages/api/") ||
    /^apps\/[^/]+\/app\/api\//.test(normalizedPath) ||
    /^apps\/[^/]+\/src\/app\/api\//.test(normalizedPath) ||
    /^apps\/[^/]+\/pages\/api\//.test(normalizedPath)
  );
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
