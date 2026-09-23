export const MAX_SCAN_REQUEST_BODY_BYTES = 16 * 1024;

export type ScanRequestJsonResult =
  | {
      ok: true;
      value: unknown;
    }
  | {
      ok: false;
      reason: "invalid" | "too_large";
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

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      byteLength += value.byteLength;
      if (byteLength > MAX_SCAN_REQUEST_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The oversized request is rejected even if its stream cannot be cancelled.
        }
        return { ok: false, reason: "too_large" };
      }

      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: "invalid" };
  } finally {
    reader.releaseLock();
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
