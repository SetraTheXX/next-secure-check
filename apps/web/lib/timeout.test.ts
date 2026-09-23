import { describe, expect, it } from "vitest";
import {
  DEFAULT_GITHUB_TIMEOUT_MS,
  DEFAULT_SCAN_TIMEOUT_MS,
  getGitHubTimeoutMs,
  getScanTimeoutMs
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
});
