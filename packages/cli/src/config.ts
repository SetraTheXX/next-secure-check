import { access, readFile } from "node:fs/promises";
import path from "node:path";
import type { ReportFormat } from "@next-secure-check/reporter";

export const CONFIG_FILE_NAME = ".next-secure-check.json";
export const MAX_EXCLUDE_PATHS = 50;
export const MAX_EXCLUDE_PATH_LENGTH = 160;

const SUPPORTED_CONFIG_KEYS = new Set(["excludePaths", "categories", "failOn", "format", "preset"]);
const SUPPORTED_FORMATS = new Set(["terminal", "json", "markdown", "github", "sarif"]);
const SUPPORTED_FAIL_ON_VALUES = new Set(["critical", "high", "medium", "low", "info"]);
const SUPPORTED_PRESETS = new Set(["default", "app", "strict", "ci", "audit", "library", "monorepo"]);

export type ScanPreset = "default" | "app" | "strict" | "ci" | "audit" | "library" | "monorepo";

export type CliConfig = {
  excludePaths?: string[];
  categories?: string[];
  failOn?: string;
  format?: ReportFormat;
  preset?: ScanPreset;
};

export type ScanCommandOptions = {
  format?: string;
  output?: string;
  failOn?: string;
  category?: string;
  exclude?: string;
  config?: string;
  preset?: string;
};

export type ResolvedScanCommandSettings = {
  categories?: string[];
  contextTuning: "standard" | "off";
  excludePaths?: string[];
  failOn?: string;
  format: ReportFormat;
  preset: ScanPreset;
  warnings: string[];
};

type ConfigLoadResult = {
  config: CliConfig;
  warnings: string[];
};

export async function resolveScanCommandSettings(
  targetPath: string,
  options: ScanCommandOptions,
  allowedCategories: Set<string>
): Promise<ResolvedScanCommandSettings> {
  const { config, warnings } = await loadConfig(targetPath, options.config, allowedCategories);
  const preset =
    options.preset !== undefined
      ? parsePreset(options.preset, "CLI --preset")
      : config.preset ?? "default";
  const userExcludePaths =
    options.exclude !== undefined
      ? validateExcludePaths(parseListOption(options.exclude), "CLI --exclude")
      : config.excludePaths;

  return {
    categories:
      options.category !== undefined
        ? parseCategoriesOption(options.category, allowedCategories)
        : config.categories,
    contextTuning: getPresetContextTuning(preset),
    excludePaths: mergePresetExcludePaths(preset, userExcludePaths),
    failOn:
      options.failOn !== undefined
        ? parseFailOn(options.failOn, "CLI --fail-on")
        : config.failOn,
    format:
      options.format !== undefined
        ? parseFormat(options.format, "CLI --format")
        : config.format ?? "terminal",
    preset,
    warnings
  };
}

export async function loadConfig(
  targetPath: string,
  explicitConfigPath: string | undefined,
  allowedCategories: Set<string>
): Promise<ConfigLoadResult> {
  const configPath = await resolveConfigPath(targetPath, explicitConfigPath);
  if (!configPath) {
    return { config: {}, warnings: [] };
  }

  const raw = (await readFile(configPath, "utf8")).replace(/^\uFEFF/, "");
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in config file: ${configPath}`);
  }

  return validateConfig(parsed, configPath, allowedCategories);
}

async function resolveConfigPath(targetPath: string, explicitConfigPath?: string): Promise<string | undefined> {
  if (explicitConfigPath) {
    return path.resolve(explicitConfigPath);
  }

  const defaultConfigPath = path.join(path.resolve(targetPath), CONFIG_FILE_NAME);
  try {
    await access(defaultConfigPath);
    return defaultConfigPath;
  } catch {
    return undefined;
  }
}

function validateConfig(value: unknown, configPath: string, allowedCategories: Set<string>): ConfigLoadResult {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new Error(`Config file must contain a JSON object: ${configPath}`);
  }

  const warnings = Object.keys(value)
    .filter((key) => !SUPPORTED_CONFIG_KEYS.has(key))
    .map((key) => `Ignoring unsupported config field "${key}" in ${configPath}.`);

  return {
    config: {
      excludePaths:
        value.excludePaths === undefined
          ? undefined
          : validateExcludePaths(value.excludePaths, "config excludePaths"),
      categories:
        value.categories === undefined
          ? undefined
          : validateCategories(value.categories, allowedCategories, "config categories"),
      failOn:
        value.failOn === undefined
          ? undefined
          : parseFailOn(value.failOn, "config failOn"),
      format:
        value.format === undefined
          ? undefined
          : parseFormat(value.format, "config format"),
      preset:
        value.preset === undefined
          ? undefined
          : parsePreset(value.preset, "config preset")
    },
    warnings
  };
}

function parseFormat(value: unknown, source: string): ReportFormat {
  if (typeof value !== "string") {
    throw new Error(`${source} must be a string.`);
  }

  const normalized = value.trim().toLowerCase();
  if (SUPPORTED_FORMATS.has(normalized)) {
    return normalized as ReportFormat;
  }

  throw new Error(`Unsupported output format in ${source}: ${value}`);
}

function parseFailOn(value: unknown, source: string): string {
  if (typeof value !== "string") {
    throw new Error(`${source} must be a string.`);
  }

  const normalized = value.trim().toLowerCase();
  if (SUPPORTED_FAIL_ON_VALUES.has(normalized)) {
    return normalized;
  }

  throw new Error(`Unsupported fail-on severity in ${source}: ${value}`);
}

function parsePreset(value: unknown, source: string): ScanPreset {
  if (typeof value !== "string") {
    throw new Error(`${source} must be a string.`);
  }

  const normalized = value.trim().toLowerCase();
  if (SUPPORTED_PRESETS.has(normalized)) {
    return normalized as ScanPreset;
  }

  throw new Error(`Unsupported preset in ${source}: ${value}`);
}

function mergePresetExcludePaths(preset: ScanPreset, excludePaths?: string[]): string[] | undefined {
  const presetExcludePaths = getPresetExcludePaths(preset);
  if (presetExcludePaths.length === 0) {
    return excludePaths;
  }

  return [...new Set([...presetExcludePaths, ...(excludePaths ?? [])])];
}

function getPresetExcludePaths(preset: ScanPreset): string[] {
  switch (preset) {
    case "app":
      return [
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
      ];
    case "ci":
      return [
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "dist/**",
        ".next/**",
        "generated/**"
      ];
    case "library":
      return [
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "docs/**",
        "examples/**",
        "apps/**/examples/**",
        "dist/**",
        ".next/**",
        "generated/**"
      ];
    case "monorepo":
      return [
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "docs/**",
        "examples/**",
        "apps/**/examples/**",
        "dist/**",
        ".next/**",
        "generated/**"
      ];
    case "default":
    case "strict":
    case "audit":
      return [];
  }
}

function getPresetContextTuning(preset: ScanPreset): "standard" | "off" {
  switch (preset) {
    case "strict":
    case "audit":
      return "off";
    case "default":
    case "app":
    case "ci":
    case "library":
    case "monorepo":
      return "standard";
  }
}

function parseCategoriesOption(value: string, allowedCategories: Set<string>): string[] | undefined {
  return validateCategories(parseListOption(value), allowedCategories, "CLI --category");
}

function validateCategories(value: unknown, allowedCategories: Set<string>, source: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${source} must be an array of strings.`);
  }

  return value.map((item) => {
    if (typeof item !== "string") {
      throw new Error(`${source} must only contain strings.`);
    }

    const normalized = item.trim().toLowerCase();
    if (!allowedCategories.has(normalized)) {
      throw new Error(`Unsupported category in ${source}: ${item}`);
    }

    return normalized;
  });
}

function parseListOption(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function validateExcludePaths(value: unknown, source: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${source} must be an array of strings.`);
  }

  if (value.length > MAX_EXCLUDE_PATHS) {
    throw new Error(`${source} cannot contain more than ${MAX_EXCLUDE_PATHS} patterns.`);
  }

  return value.map((item) => validateExcludePath(item, source));
}

function validateExcludePath(value: unknown, source: string): string {
  if (typeof value !== "string") {
    throw new Error(`${source} must only contain strings.`);
  }

  const normalized = value.trim().replace(/\\/g, "/").replace(/^\.\//, "");
  if (normalized.length === 0) {
    throw new Error(`${source} cannot contain empty patterns.`);
  }

  if (normalized.length > MAX_EXCLUDE_PATH_LENGTH) {
    throw new Error(`${source} patterns cannot exceed ${MAX_EXCLUDE_PATH_LENGTH} characters.`);
  }

  if (/[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error(`${source} patterns cannot contain control characters.`);
  }

  if (path.isAbsolute(value) || normalized.startsWith("/") || /^[a-zA-Z]:\//.test(normalized)) {
    throw new Error(`${source} patterns must be relative paths.`);
  }

  if (normalized.split("/").includes("..")) {
    throw new Error(`${source} patterns cannot contain path traversal segments.`);
  }

  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
