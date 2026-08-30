import type { Rule } from "@next-secure-check/core";

const HELP_BASE_URL = "https://github.com/SetraTheXX/next-secure-check";

type RuleExplanation = {
  checks: string;
  why: string;
  falsePositiveNote: string;
  falseNegativeNote: string;
};

const RULE_EXPLANATIONS: Record<string, RuleExplanation> = {
  "xss/dangerously-set-inner-html": {
    checks: "Flags dangerouslySetInnerHTML usage when the HTML source is not clearly static or sanitized.",
    why: "Rendering user-controlled HTML can lead to cross-site scripting in Next.js pages and components.",
    falsePositiveNote: "Static HTML strings, sanitizer calls, and component/template contexts may be lower risk.",
    falseNegativeNote: "Cross-file values, dynamic component resolution, and custom sanitizer wrappers are not fully proven; a clean result does not prove every rendered HTML value is safe."
  },
  "auth/admin-route-without-auth": {
    checks: "Looks for admin-like API route handlers without local or middleware auth signals.",
    why: "Admin endpoints usually expose privileged data or actions and should require authentication and authorization.",
    falsePositiveNote: "Middleware, framework conventions, or external gateways can protect a route even when the handler is minimal.",
    falseNegativeNote: "The check does not build a full cross-file middleware or authorization graph; custom wrappers and external gateways may be missed."
  },
  "auth/server-action-without-guards": {
    checks: "Looks for direct Server Actions or Server Functions with a use server directive and action/request input but no visible auth or input-validation intent.",
    why: "Next.js Server Actions are public request boundaries and should re-authorize the caller and validate client-controlled input.",
    falsePositiveNote: "A guard in a shared data-access layer, framework adapter, or unknown local wrapper may be valid but is not proven by this syntax-only check; one recognized guard lowers the finding.",
    falseNegativeNote: "The check does not prove runtime reachability or follow cross-file calls, dynamic exports, or custom wrappers; it only inspects the same function and short local aliases."
  },
  "redirect/unvalidated-target": {
    checks: "Looks for request-derived values reaching imported redirect, permanentRedirect, NextResponse.redirect, or Pages Router getServerSideProps destinations without a recognized path or host guard.",
    why: "An unvalidated redirect destination can send users to an attacker-controlled location or create a phishing/open-redirect path.",
    falsePositiveNote: "Fixed destinations, explicit internal-path checks, host/origin allowlists, and deployment controls can make a flow safe even when the surrounding syntax needs review.",
    falseNegativeNote: "The check is intentionally bounded to recognized same-function sources, sinks, and short aliases; custom wrappers, cross-file/cross-function flow, dynamic properties, and unsupported router/config APIs are not proven."
  },
  "auth/login-without-rate-limit": {
    checks: "Looks for login/auth routes without route-level or matching middleware rate-limit signals.",
    why: "Authentication endpoints are common brute-force and credential-stuffing targets.",
    falsePositiveNote: "Infrastructure-level rate limiting may not be visible to a static source scan.",
    falseNegativeNote: "The check does not build a full cross-file middleware or infrastructure graph; custom rate-limit wrappers and external controls may be missed."
  },
  "auth/register-without-rate-limit": {
    checks: "Looks for register/signup routes without route-level or matching middleware rate-limit signals.",
    why: "Registration endpoints can be abused for spam accounts or resource exhaustion.",
    falsePositiveNote: "Infrastructure-level abuse controls may not be visible to a static source scan.",
    falseNegativeNote: "The check does not build a full cross-file middleware or infrastructure graph; custom abuse-control wrappers and external controls may be missed."
  },
  "injection/command-exec": {
    checks: "Flags child_process imports and calls such as exec, execSync, spawn, and spawnSync.",
    why: "Shell command execution can become command injection when arguments are user-controlled.",
    falsePositiveNote: "CLI/release tooling can legitimately execute commands; presets/context tuning reduce that noise.",
    falseNegativeNote: "Bounded source-to-sink flow is limited to the same function and a small alias chain; cross-file, cross-function, and dynamically resolved execution paths may be missed."
  },
  "injection/raw-sql-concat": {
    checks: "Flags interpolated SQL templates passed to common query sinks.",
    why: "Interpolated SQL can expose applications to SQL injection.",
    falsePositiveNote: "Static or parameterized queries are intentionally ignored.",
    falseNegativeNote: "Bounded source-to-sink flow is limited to the same function and at most two alias hops; cross-file, cross-function, and dynamically constructed query paths may be missed."
  },
  "secrets/hardcoded-secret": {
    checks: "Looks for high-signal hardcoded API keys, tokens, passwords, and provider token patterns.",
    why: "Committed secrets can be copied, leaked, and abused after publication.",
    falsePositiveNote: "Obvious sample values are filtered, but rotate any real token that was committed.",
    falseNegativeNote: "Pattern matching does not cover every dynamically assembled or externally injected credential; a clean result is not a complete secret inventory."
  },
  "secrets/next-public-secret": {
    checks: "Flags NEXT_PUBLIC_ variable names containing secret-like terms; it does not prove that the assigned value is a credential.",
    why: "NEXT_PUBLIC_ values are exposed to browser-side code in Next.js, so credential-like values deserve review before shipping.",
    falsePositiveNote: "Public client identifiers or browser-safe tokens can be intentional. Review the assigned value and audience, and rename the variable when practical.",
    falseNegativeNote: "The rule is name- and context-based; secrets hidden behind computed names or other configuration channels may be missed."
  },
  "headers/missing-security-headers": {
    checks: "Looks for missing common security header configuration in Next.js apps.",
    why: "Security headers help reduce XSS, clickjacking, content sniffing, and referrer leakage risks.",
    falsePositiveNote: "Headers configured outside the app, for example at a reverse proxy, may not be visible.",
    falseNegativeNote: "Headers configured by reverse proxies, hosting, or dynamic runtime code may be missed."
  },
  "upload/missing-file-type-validation": {
    checks: "Looks for upload route handlers without file type validation signals.",
    why: "Uploads without type validation can allow unsafe file handling or unexpected content.",
    falsePositiveNote: "Deep validation in shared helpers may not always be visible.",
    falseNegativeNote: "Validation implemented through shared helpers, middleware, or infrastructure may be missed."
  },
  "upload/missing-file-size-limit": {
    checks: "Looks for upload route handlers without file size limit signals.",
    why: "Uploads without size limits can cause resource exhaustion.",
    falsePositiveNote: "Limits enforced by hosting or middleware may not be visible.",
    falseNegativeNote: "Limits enforced through shared helpers, middleware, hosting, or infrastructure may be missed."
  }
};

export function formatRulesList(rules: Rule[]): string {
  const sortedRules = sortRules(rules);
  const rows = sortedRules.map((rule) => [
    rule.id,
    rule.category,
    rule.severity,
    rule.confidence ?? "MEDIUM",
    rule.title
  ]);
  const widths = columnWidths([["Rule ID", "Category", "Severity", "Confidence", "Title"], ...rows]);
  const lines = [
    "next-secure-check rules",
    "",
    formatRow(["Rule ID", "Category", "Severity", "Confidence", "Title"], widths),
    formatRow(widths.map((width) => "-".repeat(width)), widths),
    ...rows.map((row) => formatRow(row, widths)),
    "",
    `Total rules: ${sortedRules.length}`,
    "Use `next-secure-check explain <rule-id>` for details."
  ];

  return lines.join("\n");
}

export function formatRuleExplanation(rules: Rule[], ruleId: string): string | undefined {
  const rule = rules.find((item) => item.id === ruleId);
  if (!rule) {
    return undefined;
  }

  const explanation = RULE_EXPLANATIONS[rule.id] ?? genericExplanation(rule);
  return [
    `Rule: ${rule.id}`,
    "",
    `Title: ${rule.title}`,
    `Category: ${rule.category}`,
    `Severity: ${rule.severity}`,
    `Confidence: ${rule.confidence ?? "MEDIUM"}`,
    "",
    "Checks:",
    explanation.checks,
    "",
    "Why it matters:",
    explanation.why,
    "",
    "False positive note:",
    explanation.falsePositiveNote,
    "",
    "False negative boundary:",
    explanation.falseNegativeNote,
    "",
    `Help: ${ruleHelpUri(rule.id)}`
  ].join("\n");
}

export function formatUnknownRuleMessage(rules: Rule[], ruleId: string): string {
  const suggestions = suggestRuleIds(rules, ruleId);
  const lines = [`Unknown rule id: ${ruleId}`];

  if (suggestions.length > 0) {
    lines.push("", "Did you mean:", ...suggestions.map((suggestion) => `- ${suggestion}`));
  }

  lines.push("", "Run `next-secure-check rules` to list available rules.");
  return lines.join("\n");
}

export function suggestRuleIds(rules: Rule[], ruleId: string): string[] {
  const queryParts = new Set(ruleId.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  return sortRules(rules)
    .map((rule) => ({
      id: rule.id,
      score: similarityScore(rule.id, queryParts, ruleId)
    }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, 3)
    .map((item) => item.id);
}

function genericExplanation(rule: Rule): RuleExplanation {
  return {
    checks: `Runs the built-in ${rule.category} check named "${rule.title}".`,
    why: "The finding is a deterministic review signal for a security-relevant pattern.",
    falsePositiveNote: "Review context, framework conventions, middleware, and deployment controls before treating it as confirmed risk.",
    falseNegativeNote: "Cross-file data flow, dynamic resolution, and external controls are outside this bounded static check and may be missed."
  };
}

function sortRules(rules: Rule[]): Rule[] {
  return [...rules].sort((left, right) => left.category.localeCompare(right.category) || left.id.localeCompare(right.id));
}

function columnWidths(rows: string[][]): number[] {
  const columnCount = rows[0]?.length ?? 0;
  return Array.from({ length: columnCount }, (_, index) => Math.max(...rows.map((row) => row[index]?.length ?? 0)));
}

function formatRow(row: string[], widths: number[]): string {
  return row.map((cell, index) => cell.padEnd(widths[index] ?? 0)).join("  ");
}

function similarityScore(id: string, queryParts: Set<string>, query: string): number {
  const normalizedId = id.toLowerCase();
  if (normalizedId === query.toLowerCase()) {
    return 100;
  }

  let score = normalizedId.includes(query.toLowerCase()) ? 10 : 0;
  for (const part of queryParts) {
    if (normalizedId.includes(part)) {
      score += 1;
    }
  }

  return score;
}

function ruleHelpUri(ruleId: string): string {
  return `${HELP_BASE_URL}#${ruleId.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase()}`;
}
