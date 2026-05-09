import type { Rule } from "@next-secure-check/core";

export const builtInRules: Rule[] = [];

export function getBuiltInRules(): Rule[] {
  return [...builtInRules];
}
