import type { Rule } from "@next-secure-check/core";
import { builtInSecurityRules } from "./security-rules.js";

export { builtInSecurityRules } from "./security-rules.js";

export const builtInRules: Rule[] = builtInSecurityRules;

export function getBuiltInRules(): Rule[] {
  return [...builtInRules];
}
