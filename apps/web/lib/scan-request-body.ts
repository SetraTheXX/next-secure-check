export const MAX_SCAN_REQUEST_BODY_BYTES = 16 * 1024;
export const SCAN_REQUEST_BODY_READ_TIMEOUT_MS = 5_000;

export type ScanRequestJsonResult =
  | {
      ok: true;
      value: unknown;
    }
  | {
      ok: false;
      reason: "aborted" | "invalid" | "timeout" | "too_large";
    };

export function validateScanRequestContentLength(
  value: string | null
): "valid" | "invalid" | "too_large" {
  if (value === null) {
    return "valid";
  }

  const normalized = value.trim();
  if (!/^[0-9]+$/.test(normalized)) {
    return "invalid";
  }

  const withoutLeadingZeros = normalized.replace(/^0+/, "") || "0";
  const maxLength = String(MAX_SCAN_REQUEST_BODY_BYTES);
  if (withoutLeadingZeros.length > maxLength.length) {
    return "too_large";
  }

  return Number(withoutLeadingZeros) > MAX_SCAN_REQUEST_BODY_BYTES ? "too_large" : "valid";
}

export async function readScanRequestJson(request: Request): Promise<ScanRequestJsonResult> {
  if (!request.body) {
    return { ok: false, reason: "invalid" };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  let wasInterrupted = false;
  let removeAbortListener: (() => void) | undefined;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  const interruption = new Promise<"aborted" | "timeout">((resolve) => {
    timeoutHandle = setTimeout(() => resolve("timeout"), SCAN_REQUEST_BODY_READ_TIMEOUT_MS);

    if (request.signal.aborted) {
      resolve("aborted");
      return;
    }

    const abortRequest = () => resolve("aborted");
    request.signal.addEventListener("abort", abortRequest, { once: true });
    removeAbortListener = () => request.signal.removeEventListener("abort", abortRequest);
  });

  try {
    while (true) {
      const currentRead = reader.read();
      const readResult = await Promise.race([
        currentRead.then((read) => ({ kind: "read" as const, read })),
        interruption.then((reason) => ({ kind: "interrupted" as const, reason }))
      ]);

      if (readResult.kind === "interrupted") {
        wasInterrupted = true;
        void reader.cancel().catch(() => undefined);
        void currentRead.then(
          () => releaseReaderLock(reader),
          () => releaseReaderLock(reader)
        );
        return { ok: false, reason: readResult.reason };
      }

      const { done, value } = readResult.read;
      if (done) {
        break;
      }

      byteLength += value.byteLength;
      if (byteLength > MAX_SCAN_REQUEST_BODY_BYTES) {
        void reader.cancel().catch(() => undefined);
        return { ok: false, reason: "too_large" };
      }

      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: "invalid" };
  } finally {
    if (timeoutHandle !== undefined) {
      clearTimeout(timeoutHandle);
    }
    removeAbortListener?.();
    if (!wasInterrupted) {
      releaseReaderLock(reader);
    }
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, reason: "invalid" };
  }
}

function releaseReaderLock(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.releaseLock();
  } catch {
    // A pending read retains the lock until its promise settles.
  }
}
