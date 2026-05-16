const windowsDrivePattern = /^[A-Za-z]:[\\/]/;

export function normalizeArchiveEntryPath(entryPath: string): string | null {
  const trimmed = entryPath.trim();
  if (!trimmed) {
    return null;
  }

  if (trimmed.includes("\0")) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  if (!normalized || normalized === "." || normalized === "/") {
    return null;
  }

  if (normalized.startsWith("/") || windowsDrivePattern.test(normalized)) {
    return null;
  }

  const parts = normalized.split("/");
  const safeParts: string[] = [];

  for (const part of parts) {
    if (!part || part === ".") {
      continue;
    }

    if (part === "..") {
      if (safeParts.length === 0) {
        return null;
      }

      safeParts.pop();
      continue;
    }

    safeParts.push(part);
  }

  if (safeParts.length === 0) {
    return null;
  }

  return safeParts.join("/");
}

export function isSafeArchiveEntryPath(entryPath: string): boolean {
  return normalizeArchiveEntryPath(entryPath) !== null;
}