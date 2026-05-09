import { describe, expect, it } from "vitest";
import { createScanResultSkeleton } from "./index.js";

describe("createScanResultSkeleton", () => {
  it("returns an empty successful scan result shape", () => {
    const result = createScanResultSkeleton("demo-app", "0.0.0-test");

    expect(result.project.name).toBe("demo-app");
    expect(result.summary.score).toBe(100);
    expect(result.summary.totalFindings).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.metadata.toolVersion).toBe("0.0.0-test");
  });
});
