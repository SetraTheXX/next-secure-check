import type { FindingContext } from "./types.js";

export type FileContextClassification = {
  context: FindingContext;
  contextReason: string;
};

export function classifyFileContext(filePath: string): FileContextClassification {
  const normalizedPath = normalizeContextPath(filePath);
  const basename = normalizedPath.split("/").at(-1) ?? normalizedPath;

  if (matchesTestCode(normalizedPath, basename)) {
    return {
      context: "test-code",
      contextReason: "matched test/spec file path"
    };
  }

  if (matchesExampleCode(normalizedPath)) {
    return {
      context: "example-code",
      contextReason: "matched example/demo path"
    };
  }

  if (matchesDocsCode(normalizedPath, basename)) {
    return {
      context: "docs-code",
      contextReason: "matched docs or markdown path"
    };
  }

  if (normalizedPath.startsWith(".github/workflows/")) {
    return {
      context: "github-actions",
      contextReason: "matched GitHub Actions workflow path"
    };
  }

  if (matchesReleaseTooling(normalizedPath, basename)) {
    return {
      context: "release-tooling",
      contextReason: "matched release/tooling path"
    };
  }

  if (matchesCliTooling(normalizedPath)) {
    return {
      context: "cli-tooling",
      contextReason: "matched CLI tooling path"
    };
  }

  if (matchesGeneratedCode(normalizedPath)) {
    return {
      context: "generated-code",
      contextReason: "matched generated/build output path"
    };
  }

  if (matchesTemplateCode(normalizedPath)) {
    return {
      context: "template-code",
      contextReason: "matched template/fixture path"
    };
  }

  if (matchesApiCode(normalizedPath)) {
    return {
      context: "api-code",
      contextReason: "matched Next.js API route path"
    };
  }

  if (matchesAppCode(normalizedPath)) {
    return {
      context: "app-code",
      contextReason: "matched Next.js app/page runtime path"
    };
  }

  return {
    context: "unknown",
    contextReason: "no known file context pattern matched"
  };
}

function normalizeContextPath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

function matchesApiCode(filePath: string): boolean {
  return (
    filePath.startsWith("app/api/") ||
    filePath.startsWith("src/app/api/") ||
    filePath.startsWith("pages/api/") ||
    /^apps\/[^/]+\/app\/api\//.test(filePath) ||
    /^apps\/[^/]+\/src\/app\/api\//.test(filePath) ||
    /^apps\/[^/]+\/pages\/api\//.test(filePath)
  );
}

function matchesAppCode(filePath: string): boolean {
  return (
    filePath.startsWith("app/") ||
    filePath.startsWith("pages/") ||
    filePath.startsWith("src/app/") ||
    filePath.startsWith("src/pages/") ||
    /^apps\/[^/]+\/app\//.test(filePath) ||
    /^apps\/[^/]+\/src\/app\//.test(filePath) ||
    /^apps\/[^/]+\/pages\//.test(filePath) ||
    /^packages\/[^/]+\/app\//.test(filePath) ||
    /^packages\/[^/]+\/src\/app\//.test(filePath)
  );
}

function matchesTestCode(filePath: string, basename: string): boolean {
  return (
    filePath.startsWith("__tests__/") ||
    filePath.includes("/__tests__/") ||
    /\.(test|spec)\.(ts|tsx|js|jsx)$/.test(basename)
  );
}

function matchesExampleCode(filePath: string): boolean {
  return (
    filePath.startsWith("examples/") ||
    /^apps\/[^/]+\/examples\//.test(filePath) ||
    /^apps\/[^/]+\/app\/examples\//.test(filePath)
  );
}

function matchesDocsCode(filePath: string, basename: string): boolean {
  return filePath.startsWith("docs/") || /\.mdx?$/.test(basename);
}

function matchesReleaseTooling(filePath: string, basename: string): boolean {
  return (
    /^\.github\/[^/]+\.(js|ts)$/.test(filePath) ||
    filePath.startsWith("scripts/release/") ||
    /^changeset/i.test(basename)
  );
}

function matchesCliTooling(filePath: string): boolean {
  return (
    filePath.startsWith("cli/") ||
    filePath.startsWith("src/cli/") ||
    filePath.startsWith("packages/cli/")
  );
}

function matchesGeneratedCode(filePath: string): boolean {
  return filePath.startsWith("dist/") || filePath.startsWith(".next/") || filePath.startsWith("generated/");
}

function matchesTemplateCode(filePath: string): boolean {
  return filePath.startsWith("templates/") || filePath.startsWith("fixtures/");
}
