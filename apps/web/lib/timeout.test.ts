import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_GITHUB_TIMEOUT_MS,
  DEFAULT_SCAN_TIMEOUT_MS,
  getGitHubTimeoutMs,
  getScanTimeoutMs,
  OperationTimeoutError,
  withTimeout
} from "./timeout";

describe("timeout configuration", () => {
  it("uses defaults when timeout env values are missing", () => {
    expect(getGitHubTimeoutMs({})).toBe(DEFAULT_GITHUB_TIMEOUT_MS);
    expect(getScanTimeoutMs({})).toBe(DEFAULT_SCAN_TIMEOUT_MS);
  });

  it("uses valid timeout env values", () => {
    expect(getGitHubTimeoutMs({ NEXT_SECURE_CHECK_GITHUB_TIMEOUT_MS: "15000" })).toBe(15000);
    expect(getScanTimeoutMs({ NEXT_SECURE_CHECK_SCAN_TIMEOUT_MS: "45000" })).toBe(45000);
  });

  it("falls back to defaults for invalid timeout env values", () => {
    expect(getGitHubTimeoutMs({ NEXT_SECURE_CHECK_GITHUB_TIMEOUT_MS: "nope" })).toBe(
      DEFAULT_GITHUB_TIMEOUT_MS
    );
    expect(getScanTimeoutMs({ NEXT_SECURE_CHECK_SCAN_TIMEOUT_MS: "-1" })).toBe(
      DEFAULT_SCAN_TIMEOUT_MS
    );
  });

  it("aborts the active operation when it times out", async () => {
    const abort = vi.fn();
    const operation = vi.fn((signal: AbortSignal) =>
      new Promise<never>((_, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            abort();
            reject(signal.reason);
          },
          { once: true }
        );
      })
    );

    await expect(withTimeout(operation, 1)).rejects.toBeInstanceOf(OperationTimeoutError);

    expect(abort).toHaveBeenCalledOnce();
  });
});
