import { describe, expect, it } from "vitest";
import { classifyFileContext } from "./context-classifier.js";

describe("classifyFileContext", () => {
  it.each([
    ["app/api/users/route.ts", "api-code"],
    ["src/app/api/users/route.ts", "api-code"],
    ["pages/api/users.ts", "api-code"],
    ["app/page.tsx", "app-code"],
    ["pages/index.tsx", "app-code"],
    ["src/app/dashboard/page.tsx", "app-code"],
    ["src/pages/index.tsx", "app-code"],
    ["index.test.ts", "test-code"],
    ["components/button.spec.tsx", "test-code"],
    ["__tests__/scanner.test.ts", "test-code"],
    ["examples/vulnerable/app/page.tsx", "example-code"],
    ["apps/web/examples/demo.tsx", "example-code"],
    ["docs/rules/command-exec.md", "docs-code"],
    ["README.md", "docs-code"],
    [".github/workflows/security-check.yml", "github-actions"],
    [".github/changeset-version.js", "release-tooling"],
    ["scripts/release/publish.ts", "release-tooling"],
    ["changeset.config.js", "release-tooling"],
    ["cli/src/index.ts", "cli-tooling"],
    ["src/cli/commands.ts", "cli-tooling"],
    ["packages/cli/src/index.ts", "cli-tooling"],
    ["dist/index.js", "generated-code"],
    [".next/server/app/page.js", "generated-code"],
    ["generated/client.ts", "generated-code"],
    ["templates/app/page.tsx", "template-code"],
    ["fixtures/vulnerable/app/page.tsx", "template-code"],
    ["lib/utils.ts", "unknown"]
  ])("classifies %s as %s", (filePath, expectedContext) => {
    expect(classifyFileContext(filePath).context).toBe(expectedContext);
  });

  it("normalizes Windows path separators", () => {
    expect(classifyFileContext("app\\api\\users\\route.ts")).toMatchObject({
      context: "api-code",
      contextReason: "matched Next.js API route path"
    });
  });

  it("returns a reason with every classification", () => {
    expect(classifyFileContext("lib/utils.ts").contextReason).toBe("no known file context pattern matched");
  });
});
