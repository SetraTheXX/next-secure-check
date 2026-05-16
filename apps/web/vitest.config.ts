import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@next-secure-check/core": "../../packages/core/src/index.ts",
      "@next-secure-check/rules": "../../packages/rules/src/index.ts"
    }
  },
  test: {
    environment: "node"
  }
});
