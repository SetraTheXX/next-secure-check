import path from "node:path";
import type { ProjectInfo, ScanContext, SourceFile } from "./types.js";

type PackageJsonShape = {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

type ParsedPackageJson = {
  name?: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

export function detectProject(files: SourceFile[], rootPath: string): Pick<ScanContext, "packageJson" | "project"> {
  const packageJsonFile = files.find((file) => file.path === "package.json");
  const packageJson = parsePackageJson(packageJsonFile?.content);
  const allDependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies
  };

  const hasNextDependency = "next" in allDependencies;
  const hasReactDependency = "react" in allDependencies || files.some((file) => /\.(tsx|jsx)$/.test(file.path));
  const hasNextStructure = files.some((file) => file.path.startsWith("app/") || file.path.startsWith("src/app/"));
  const hasApiRoutes = files.some((file) => file.path.includes("/api/") || file.path.startsWith("pages/api/"));

  const project: ProjectInfo = {
    name: packageJson.name ?? path.basename(rootPath),
    framework: hasNextDependency || hasNextStructure || hasApiRoutes ? "nextjs" : hasReactDependency ? "react" : "node",
    router: detectRouter(files),
    language: detectLanguage(files)
  };

  return {
    packageJson: packageJsonFile
      ? {
          name: packageJson.name,
          dependencies: packageJson.dependencies,
          devDependencies: packageJson.devDependencies
        }
      : undefined,
    project
  };
}

function parsePackageJson(content?: string): ParsedPackageJson {
  if (!content) {
    return { dependencies: {}, devDependencies: {} };
  }

  try {
    const parsed = JSON.parse(content) as PackageJsonShape;
    return {
      name: parsed.name,
      dependencies: parsed.dependencies ?? {},
      devDependencies: parsed.devDependencies ?? {}
    };
  } catch {
    return { dependencies: {}, devDependencies: {} };
  }
}

function detectRouter(files: SourceFile[]): ProjectInfo["router"] {
  const hasApp = files.some((file) => file.path.startsWith("app/") || file.path.startsWith("src/app/"));
  const hasPages = files.some((file) => file.path.startsWith("pages/") || file.path.startsWith("src/pages/"));

  if (hasApp && hasPages) {
    return "mixed";
  }

  if (hasApp) {
    return "app";
  }

  if (hasPages) {
    return "pages";
  }

  return "unknown";
}

function detectLanguage(files: SourceFile[]): ProjectInfo["language"] {
  const hasTypeScript = files.some((file) => /\.(ts|tsx)$/.test(file.path));
  const hasJavaScript = files.some((file) => /\.(js|jsx)$/.test(file.path));

  if (hasTypeScript && hasJavaScript) {
    return "mixed";
  }

  if (hasTypeScript) {
    return "typescript";
  }

  if (hasJavaScript) {
    return "javascript";
  }

  return "unknown";
}
