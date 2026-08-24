export const DEFAULT_GITHUB_TIMEOUT_MS = 12_000;
export const DEFAULT_SCAN_TIMEOUT_MS = 60_000;

type TimeoutEnvironment = Readonly<Record<string, string | undefined>>;

export class OperationTimeoutError extends Error {
  constructor(message = "Operation timed out") {
    super(message);
    this.name = "OperationTimeoutError";
  }
}

export function getGitHubTimeoutMs(env: TimeoutEnvironment = process.env): number {
  return parseTimeoutMs(env.NEXT_SECURE_CHECK_GITHUB_TIMEOUT_MS, DEFAULT_GITHUB_TIMEOUT_MS);
}

export function getScanTimeoutMs(env: TimeoutEnvironment = process.env): number {
  return parseTimeoutMs(env.NEXT_SECURE_CHECK_SCAN_TIMEOUT_MS, DEFAULT_SCAN_TIMEOUT_MS);
}

export async function fetchWithAbortTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new OperationTimeoutError()), timeoutMs);

  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal
    });
  } catch (error) {
    if (isTimeoutAbort(error)) {
      throw new OperationTimeoutError();
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_, reject) => {
        timeout = setTimeout(() => reject(new OperationTimeoutError()), timeoutMs);
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

function parseTimeoutMs(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > 300_000) {
    return fallback;
  }

  return parsed;
}

function isTimeoutAbort(error: unknown): boolean {
  return (
    error instanceof OperationTimeoutError ||
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}
