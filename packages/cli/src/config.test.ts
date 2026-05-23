import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CONFIG_FILE_NAME, MAX_EXCLUDE_PATHS, resolveScanCommandSettings } from "./config.js";

const allowedCategories = new Set(["secrets", "auth", "xss", "headers", "config", "injection", "upload", "validation"]);
const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "next-secure-check-cli-config-"));
  tempDirs.push(tempDir);
  return tempDir;
}

async function writeConfig(dir: string, value: unknown): Promise<string> {
  const configPath = path.join(dir, CONFIG_FILE_NAME);
  await writeFile(configPath, typeof value === "string" ? value : JSON.stringify(value), "utf8");
  return configPath;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("resolveScanCommandSettings", () => {
  it("keeps the default behavior when no config file exists", async () => {
    const targetPath = await createTempDir();

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toEqual({
      categories: undefined,
      contextTuning: "standard",
      excludePaths: undefined,
      failOn: undefined,
      format: "terminal",
      preset: "default",
      warnings: []
    });
  });

  it("applies excludePaths from the target config file", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      excludePaths: ["**/*.test.ts", "examples/**"]
    });

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      excludePaths: ["**/*.test.ts", "examples/**"]
    });
  });

  it("applies preset excludePaths from the target config file", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      preset: "app"
    });

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      preset: "app",
      contextTuning: "standard",
      excludePaths: expect.arrayContaining([
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        ".github/**",
        "examples/**",
        "apps/**/examples/**",
        "docs/**",
        "dist/**",
        ".next/**",
        "generated/**"
      ])
    });
  });

  it("keeps default preset close to v0.1 behavior while using standard tuning", async () => {
    const targetPath = await createTempDir();

    await expect(resolveScanCommandSettings(targetPath, { preset: "default" }, allowedCategories)).resolves.toEqual({
      categories: undefined,
      contextTuning: "standard",
      excludePaths: undefined,
      failOn: undefined,
      format: "terminal",
      preset: "default",
      warnings: []
    });
  });

  it("merges preset excludePaths with config excludePaths", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      preset: "app",
      excludePaths: ["custom/**"]
    });

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      excludePaths: expect.arrayContaining([".github/**", "examples/**", "custom/**"])
    });
  });

  it("applies categories, failOn, and format from the target config file", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      categories: ["secrets", "headers"],
      failOn: "high",
      format: "sarif",
      preset: "ci"
    });

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      categories: ["secrets", "headers"],
      contextTuning: "standard",
      failOn: "high",
      format: "sarif",
      preset: "ci"
    });
  });

  it("lets explicit CLI flags override config values", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      categories: ["headers"],
      excludePaths: ["examples/**"],
      failOn: "high",
      format: "markdown",
      preset: "library"
    });

    await expect(
      resolveScanCommandSettings(
        targetPath,
        {
          category: "secrets,auth",
          exclude: "**/*.test.ts",
          failOn: "low",
          format: "json",
          preset: "app"
        },
        allowedCategories
      )
    ).resolves.toMatchObject({
      categories: ["secrets", "auth"],
      excludePaths: expect.arrayContaining([".github/**", "examples/**", "**/*.test.ts"]),
      failOn: "low",
      format: "json",
      preset: "app",
      contextTuning: "standard"
    });
  });

  it("turns context tuning off for strict and audit presets", async () => {
    const targetPath = await createTempDir();

    await expect(resolveScanCommandSettings(targetPath, { preset: "strict" }, allowedCategories)).resolves.toMatchObject({
      contextTuning: "off",
      excludePaths: undefined,
      preset: "strict"
    });

    await expect(resolveScanCommandSettings(targetPath, { preset: "audit" }, allowedCategories)).resolves.toMatchObject({
      contextTuning: "off",
      excludePaths: undefined,
      preset: "audit"
    });
  });

  it("documents app preset as the app-focused exclude set", async () => {
    const targetPath = await createTempDir();

    await expect(resolveScanCommandSettings(targetPath, { preset: "app" }, allowedCategories)).resolves.toMatchObject({
      contextTuning: "standard",
      excludePaths: expect.arrayContaining([
        "**/*.test.ts",
        "**/*.spec.ts",
        "**/*.test.tsx",
        ".github/**",
        "examples/**",
        "apps/**/examples/**",
        "docs/**",
        "dist/**",
        ".next/**",
        "generated/**"
      ]),
      preset: "app"
    });
  });

  it("merges CLI excludePaths with CLI preset excludePaths", async () => {
    const targetPath = await createTempDir();

    await expect(
      resolveScanCommandSettings(
        targetPath,
        {
          exclude: "custom/**",
          preset: "app"
        },
        allowedCategories
      )
    ).resolves.toMatchObject({
      excludePaths: expect.arrayContaining([".github/**", "examples/**", "custom/**"])
    });
  });

  it("accepts sarif as an explicit CLI format", async () => {
    const targetPath = await createTempDir();

    await expect(resolveScanCommandSettings(targetPath, { format: "sarif" }, allowedCategories)).resolves.toMatchObject({
      format: "sarif"
    });
  });

  it("loads an explicit --config path", async () => {
    const targetPath = await createTempDir();
    const configDir = await createTempDir();
    const configPath = path.join(configDir, "custom-config.json");
    await writeFile(configPath, JSON.stringify({ format: "github", failOn: "critical" }), "utf8");

    await expect(resolveScanCommandSettings(targetPath, { config: configPath }, allowedCategories)).resolves.toMatchObject({
      failOn: "critical",
      format: "github"
    });
  });

  it("accepts UTF-8 BOM encoded JSON config files", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, `\uFEFF${JSON.stringify({ format: "json" })}`);

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      format: "json"
    });
  });

  it("rejects invalid JSON", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, "{not-json");

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).rejects.toThrow("Invalid JSON");
  });

  it("rejects invalid failOn, format, and category values", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, { failOn: "blocker" });
    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).rejects.toThrow("Unsupported fail-on");

    const formatTarget = await createTempDir();
    await writeConfig(formatTarget, { format: "xml" });
    await expect(resolveScanCommandSettings(formatTarget, {}, allowedCategories)).rejects.toThrow("Unsupported output format");

    const categoryTarget = await createTempDir();
    await writeConfig(categoryTarget, { categories: ["unknown"] });
    await expect(resolveScanCommandSettings(categoryTarget, {}, allowedCategories)).rejects.toThrow("Unsupported category");

    const presetTarget = await createTempDir();
    await writeConfig(presetTarget, { preset: "mobile" });
    await expect(resolveScanCommandSettings(presetTarget, {}, allowedCategories)).rejects.toThrow("Unsupported preset");
  });

  it("rejects unsafe excludePaths", async () => {
    const absolutePathTarget = await createTempDir();
    await writeConfig(absolutePathTarget, { excludePaths: ["/tmp/secrets"] });
    await expect(resolveScanCommandSettings(absolutePathTarget, {}, allowedCategories)).rejects.toThrow("relative paths");

    const traversalTarget = await createTempDir();
    await writeConfig(traversalTarget, { excludePaths: ["../outside"] });
    await expect(resolveScanCommandSettings(traversalTarget, {}, allowedCategories)).rejects.toThrow("path traversal");

    const emptyTarget = await createTempDir();
    await writeConfig(emptyTarget, { excludePaths: [""] });
    await expect(resolveScanCommandSettings(emptyTarget, {}, allowedCategories)).rejects.toThrow("empty patterns");

    const tooManyTarget = await createTempDir();
    await writeConfig(tooManyTarget, { excludePaths: Array.from({ length: MAX_EXCLUDE_PATHS + 1 }, (_, index) => `${index}.ts`) });
    await expect(resolveScanCommandSettings(tooManyTarget, {}, allowedCategories)).rejects.toThrow("cannot contain more");
  });

  it("warns about unknown fields without failing", async () => {
    const targetPath = await createTempDir();
    await writeConfig(targetPath, {
      format: "json",
      rules: {
        "secrets/hardcoded-secret": "off"
      }
    });

    await expect(resolveScanCommandSettings(targetPath, {}, allowedCategories)).resolves.toMatchObject({
      format: "json",
      warnings: [expect.stringContaining("Ignoring unsupported config field")]
    });
  });
});
