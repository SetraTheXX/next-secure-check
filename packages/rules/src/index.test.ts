import { describe, expect, it } from "vitest";
import { getBuiltInRules } from "./index.js";

describe("getBuiltInRules", () => {
  it("returns a copy of the built-in rule list", () => {
    const first = getBuiltInRules();
    const second = getBuiltInRules();

    expect(first).toEqual([]);
    expect(first).not.toBe(second);
  });
});
