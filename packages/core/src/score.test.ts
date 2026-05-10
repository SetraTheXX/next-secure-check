import { describe, expect, it } from "vitest";
import { riskLevelForScore, summarizeFindings } from "./score.js";
import type { Finding } from "./types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "id",
    ruleId: "rule",
    title: "Finding",
    severity: "LOW",
    confidence: "HIGH",
    category: "test",
    filePath: "file.ts",
    description: "description",
    recommendation: "recommendation",
    ...overrides
  };
}

describe("summarizeFindings", () => {
  it("counts severities", () => {
    const summary = summarizeFindings([
      finding({ severity: "HIGH" }),
      finding({ severity: "MEDIUM" }),
      finding({ severity: "LOW" }),
      finding({ severity: "INFO" })
    ]);

    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.info).toBe(1);
  });

  it("applies confidence multipliers to score", () => {
    const summary = summarizeFindings([finding({ severity: "HIGH", confidence: "LOW" })]);

    expect(summary.score).toBe(94);
  });

  it("never returns a negative score", () => {
    const summary = summarizeFindings(Array.from({ length: 20 }, () => finding({ severity: "HIGH" })));

    expect(summary.score).toBe(0);
  });
});

describe("riskLevelForScore", () => {
  it("maps excellent scores", () => {
    expect(riskLevelForScore(90)).toBe("excellent");
  });

  it("maps good scores", () => {
    expect(riskLevelForScore(75)).toBe("good");
  });

  it("maps medium scores", () => {
    expect(riskLevelForScore(60)).toBe("medium");
  });

  it("maps high scores", () => {
    expect(riskLevelForScore(40)).toBe("high");
  });

  it("maps critical scores", () => {
    expect(riskLevelForScore(39)).toBe("critical");
  });
});
