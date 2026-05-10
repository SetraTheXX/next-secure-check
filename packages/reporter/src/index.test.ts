import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatMarkdown, formatReport, formatSummary, formatTerminal } from "./index.js";

describe("formatSummary", () => {
  it("renders the scan score and risk level", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatSummary(result)).toContain("Score: 100/100");
    expect(formatSummary(result)).toContain("Risk Level: excellent");
  });

  it("renders json reports", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(JSON.parse(formatReport(result, "json")).summary.score).toBe(100);
  });

  it("renders markdown reports", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatMarkdown(result)).toContain("# next-secure-check report");
  });

  it("renders terminal reports with no findings", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatTerminal(result)).toContain("No findings detected.");
  });
});
