import { describe, expect, it } from "vitest";
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
  });
});
