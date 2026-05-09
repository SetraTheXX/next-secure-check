import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "@next-secure-check/core";
import { formatSummary } from "./index.js";

describe("formatSummary", () => {
  it("renders the scan score and risk level", () => {
    const result = createScanResultSkeleton("demo-app");

    expect(formatSummary(result)).toContain("Score: 100/100");
    expect(formatSummary(result)).toContain("Risk Level: excellent");
  });
});
