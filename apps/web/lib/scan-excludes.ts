export const DEFAULT_WEB_EXCLUDE_PATHS = [
  "**/*.test.ts",
  "**/*.test.tsx",
  "**/*.spec.ts",
  "**/*.spec.tsx",
  "examples/**"
];

export const MAX_EXCLUDE_PATHS = 10;
export const MAX_EXCLUDE_PATH_LENGTH = 120;

export function validateExcludePaths(input: unknown): string[] | null {
  if (input === undefined) {
    return [];
  }

  if (!Array.isArray(input) || input.length > MAX_EXCLUDE_PATHS) {
    return null;
  }

  const values = [];
  for (const item of input) {
    if (typeof item !== "string") {
      return null;
    }

    const value = item.trim();
    if (!isSafeExcludePath(value)) {
      return null;
    }

    values.push(value);
  }

  return values;
}

function isSafeExcludePath(value: string): boolean {
  if (!value || value.length > MAX_EXCLUDE_PATH_LENGTH) {
    return false;
  }

  if (/[\0\r\n]/.test(value)) {
    return false;
  }

  if (value.startsWith("/") || value.startsWith("\\") || /^[A-Za-z]:/.test(value)) {
    return false;
  }

  return !value.split(/[\\/]+/).includes("..");
}
