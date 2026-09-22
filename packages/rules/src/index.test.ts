import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getBuiltInRules } from "./index.js";

describe("getBuiltInRules", () => {
  it("returns a copy of the built-in rule list", () => {
    const first = getBuiltInRules();
    const second = getBuiltInRules();

    expect(first.length).toBeGreaterThan(0);
    expect(first).not.toBe(second);
  });

  it("includes the phase 1 rules", () => {
    const ruleIds = getBuiltInRules().map((rule) => rule.id);

    expect(ruleIds).toContain("secrets/env-file-committed");
    expect(ruleIds).toContain("secrets/hardcoded-secret");
    expect(ruleIds).toContain("secrets/weak-jwt-secret");
    expect(ruleIds).toContain("injection/no-eval");
    expect(ruleIds).toContain("xss/dangerously-set-inner-html");
    expect(ruleIds).toContain("config/insecure-cors-wildcard");
    expect(ruleIds).toContain("auth/login-without-rate-limit");
    expect(ruleIds).toContain("auth/password-without-hashing-library");
    expect(ruleIds).toContain("injection/raw-sql-concat");
    expect(ruleIds).toContain("headers/missing-security-headers");
    expect(ruleIds).toContain("auth/server-action-without-guards");
    expect(ruleIds).toContain("auth/session-cookie-without-security-flags");
    expect(ruleIds).toContain("redirect/unvalidated-target");
    expect(ruleIds).toContain("ssrf/unvalidated-outbound-url");
    expect(ruleIds).toContain("config/next-image-domains");
    expect(ruleIds).toHaveLength(25);
  });

  it("has unique rule ids", () => {
    const ruleIds = getBuiltInRules().map((rule) => rule.id);

    expect(new Set(ruleIds).size).toBe(ruleIds.length);
  });

  it("has valid rule metadata shape", () => {
    const severities = new Set(["HIGH", "MEDIUM", "LOW", "INFO"]);

    for (const rule of getBuiltInRules()) {
      expect(rule.id).toMatch(/^[a-z-]+\/[a-z-]+$/);
      expect(severities.has(rule.severity)).toBe(true);
      expect(rule.title.trim().length).toBeGreaterThan(0);
      expect(rule.category.trim().length).toBeGreaterThan(0);
    }
  });

  it("documents every rule in docs/rules", () => {
    const rules = getBuiltInRules();
    const docsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "docs", "rules");
    const docFiles = readdirSync(docsDir).filter((name) => name.endsWith(".md") && name !== "README.md");
    const docContents = docFiles.map((name) => readFileSync(join(docsDir, name), "utf8"));

    expect(docFiles.length).toBe(rules.length);

    for (const rule of rules) {
      expect(
        docContents.some((content) => content.includes(rule.id)),
        `missing docs for rule ${rule.id}`,
      ).toBe(true);
    }

    for (const [index, content] of docContents.entries()) {
      expect(
        rules.some((rule) => content.includes(rule.id)),
        `orphan doc without rule id: ${docFiles[index]}`,
      ).toBe(true);
    }
  });
});
