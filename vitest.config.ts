import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@next-secure-check/core": "./packages/core/src/index.ts",
      "@next-secure-check/reporter": "./packages/reporter/src/index.ts",
      "@next-secure-check/rules": "./packages/rules/src/index.ts"
    }
  },
  test: {
    include: ["packages/**/*.test.ts"],
    globals: false
  }
});
