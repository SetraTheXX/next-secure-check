import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding, RiskLevel, Severity } from "@next-secure-check/core";
import { getBuiltInRules } from "@next-secure-check/rules";
import { CONFIG_FILE_NAME } from "./config.js";
import { shouldFail } from "./fail-on.js";
import { initProject, NEXT_SECURE_CHECK_WORKFLOW_PATH } from "./init.js";
import { formatRuleExplanation, formatRulesList, formatUnknownRuleMessage } from "./rules-info.js";
import { CLI_VERSION } from "./version.js";

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "next-secure-check-cli-"));
  tempDirs.push(tempDir);
  return tempDir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("shouldFail", () => {
  it("fails critical gates based on scan risk level", () => {
    expect(shouldFail(createResult("critical", ["HIGH"]), "critical")).toBe(true);
  });

  it("does not fail critical gates for non-critical risk levels", () => {
    expect(shouldFail(createResult("high", ["HIGH"]), "critical")).toBe(false);
    expect(shouldFail(createResult("excellent", ["LOW"]), "critical")).toBe(false);
  });

  it("keeps severity threshold gates for high, medium, low, and info", () => {
    expect(shouldFail(createResult("excellent", ["HIGH"]), "high")).toBe(true);
    expect(shouldFail(createResult("excellent", ["MEDIUM"]), "high")).toBe(false);
    expect(shouldFail(createResult("excellent", ["MEDIUM"]), "medium")).toBe(true);
    expect(shouldFail(createResult("excellent", ["LOW"]), "medium")).toBe(false);
    expect(shouldFail(createResult("excellent", ["LOW"]), "low")).toBe(true);
    expect(shouldFail(createResult("excellent", ["INFO"]), "low")).toBe(false);
    expect(shouldFail(createResult("excellent", ["INFO"]), "info")).toBe(true);
  });

  it("does not fail when failOn is not configured", () => {
    expect(shouldFail(createResult("critical", ["HIGH"]), undefined)).toBe(false);
  });
});

describe("CLI version", () => {
  it("reads the published version from the package manifest", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8")
    ) as { version: string };

    expect(CLI_VERSION).toBe(manifest.version);
  });
});

describe("rules CLI helpers", () => {
  it("formats the built-in rule list", () => {
    const output = formatRulesList(getBuiltInRules());

    expect(output).toContain("next-secure-check rules");
    expect(output).toContain("Rule ID");
    expect(output).toContain("xss/dangerously-set-inner-html");
    expect(output).toContain("auth/login-without-rate-limit");
    expect(output).toContain("Total rules:");
  });

  it("explains a known rule", () => {
    const output = formatRuleExplanation(getBuiltInRules(), "xss/dangerously-set-inner-html");

    expect(output).toContain("Rule: xss/dangerously-set-inner-html");
    expect(output).toContain("Title: dangerouslySetInnerHTML usage detected");
    expect(output).toContain("Category: xss");
    expect(output).toContain("Severity:");
    expect(output).toContain("Checks:");
    expect(output).toContain("Why it matters:");
    expect(output).toContain("False positive note:");
    expect(output).toContain("Help: https://github.com/SetraTheXX/next-secure-check#xss-dangerously-set-inner-html");
  });

  it("returns undefined and formats a helpful message for unknown rule ids", () => {
    const rules = getBuiltInRules();

    expect(formatRuleExplanation(rules, "xss/not-a-rule")).toBeUndefined();
    expect(formatUnknownRuleMessage(rules, "xss/not-a-rule")).toContain("Unknown rule id: xss/not-a-rule");
    expect(formatUnknownRuleMessage(rules, "xss/not-a-rule")).toContain("next-secure-check rules");
  });
});

describe("initProject", () => {
  it("creates the default config and GitHub Actions workflow", async () => {
    const targetPath = await createTempDir();

    const result = await initProject(targetPath);

    expect(result).toEqual([
      { path: CONFIG_FILE_NAME, status: "created" },
      { path: NEXT_SECURE_CHECK_WORKFLOW_PATH, status: "created" }
    ]);
    await expect(readFile(path.join(targetPath, CONFIG_FILE_NAME), "utf8")).resolves.toBe(
      JSON.stringify({ preset: "app", format: "terminal", failOn: "high" }, null, 2) + "\n"
    );
    await expect(readFile(path.join(targetPath, NEXT_SECURE_CHECK_WORKFLOW_PATH), "utf8")).resolves.toContain(
      "npx --yes next-secure-check@0.3.0 scan . --preset app --format github --fail-on high"
    );
    await expect(readFile(path.join(targetPath, NEXT_SECURE_CHECK_WORKFLOW_PATH), "utf8")).resolves.toContain(
      "actions/checkout@v7"
    );
    await expect(readFile(path.join(targetPath, NEXT_SECURE_CHECK_WORKFLOW_PATH), "utf8")).resolves.toContain(
      "actions/setup-node@v7"
    );
  });

  it("skips existing files by default", async () => {
    const targetPath = await createTempDir();
    const configPath = path.join(targetPath, CONFIG_FILE_NAME);
    await writeFile(configPath, "existing config", "utf8");

    const result = await initProject(targetPath);

    expect(result).toEqual([
      { path: CONFIG_FILE_NAME, status: "skipped" },
      { path: NEXT_SECURE_CHECK_WORKFLOW_PATH, status: "created" }
    ]);
    await expect(readFile(configPath, "utf8")).resolves.toBe("existing config");
  });
});

function createResult(riskLevel: RiskLevel, severities: Severity[]) {
  const findings = severities.map((severity, index) => createFinding(severity, index));
  return {
    findings,
    summary: {
      high: severities.filter((severity) => severity === "HIGH").length,
      info: severities.filter((severity) => severity === "INFO").length,
      low: severities.filter((severity) => severity === "LOW").length,
      medium: severities.filter((severity) => severity === "MEDIUM").length,
      riskLevel,
      score: 100,
      totalFindings: findings.length
    }
  };
}

function createFinding(severity: Severity, index: number): Finding {
  return {
    category: "test",
    confidence: "HIGH",
    description: "description",
    filePath: `file-${index}.ts`,
    id: `finding-${index}`,
    recommendation: "recommendation",
    ruleId: `rule/${index}`,
    severity,
    title: "title"
  };
}
