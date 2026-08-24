import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";
import { SourceAnalysisCache, type AnalysisCacheStats } from "./analysis-cache.js";
import {
  COMMAND_EXECUTION_NAMES,
  bindingElementLocalName,
  bindingElementName,
  isChildProcessSpecifier
} from "./command-ast.js";
import { collectCommandSourcePaths, isAnalyzableCommandExecutionCall } from "./command-flow.js";
import { findPasswordHandlingNodes, hasPasswordHashingCall } from "./password-ast.js";
import { findRawSqlConcatNodes } from "./sql-ast.js";
import {
  ROUTE_HANDLER_NAMES,
  exportedRouteHandlerName,
  hasAuthIntentInSource,
  hasValidationIntentInSource,
  isApiRouteFilePath,
  isUploadHandlingNode
} from "./route-ast.js";
import { createXssAnalysisFacts, findDangerouslySetInnerHtmlNodes } from "./xss-ast.js";

export type AstMatch = {
  line: number;
  column: number;
  evidence: string;
  sourceLine: string;
  evidencePath?: string;
};

export type DangerouslySetInnerHtmlMatch = AstMatch & {
  severity: Extract<Severity, "LOW" | "MEDIUM">;
};

export type AnalysisFacts = {
  sourceFile: ts.SourceFile;
  commandIdentifiers: ReadonlySet<string>;
  childProcessNamespaces: ReadonlySet<string>;
  commandDeclarationNodes: readonly ts.Node[];
  commandSourcePaths: ReadonlyMap<ts.CallExpression, string>;
  routeHandlerNodes: readonly ts.Node[];
  sanitizerIdentifiers: ReadonlySet<string>;
  safeHtmlIdentifiers: ReadonlySet<string>;
  hasPasswordHashing: boolean;
  hasAuthIntent: boolean;
  hasValidationIntent: boolean;
  hasUploadHandling: boolean;
};

export type AnalysisFactsCacheStats = AnalysisCacheStats;

const analysisFactsCache = new SourceAnalysisCache<AnalysisFacts>();

export function getAnalysisFacts(file: SourceFile): AnalysisFacts {
  return analysisFactsCache.get(file, () => {
    const sourceFile = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKindForPath(file.path)
    );
    return createAnalysisFacts(sourceFile);
  });
}

export function getAnalysisFactsCacheStats(): AnalysisFactsCacheStats {
  return analysisFactsCache.stats();
}

export function resetAnalysisFactsCacheForTests(): void {
  analysisFactsCache.clear();
}

export function findCommandExecutionMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes, commandSourcePaths } = getAnalysisFacts(file);
  const matches = commandDeclarationNodes.map((node) => matchFromNode(file, sourceFile, node));

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node) || !isAnalyzableCommandExecutionCall(node, commandIdentifiers, childProcessNamespaces)) {
      return;
    }

    const match = matchFromNode(file, sourceFile, node);
    const evidencePath = commandSourcePaths.get(node);
    matches.push(evidencePath ? { ...match, evidencePath } : match);
  });

  return dedupeMatches(matches);
}

export function findRawSqlConcatMatches(file: SourceFile): AstMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  return dedupeMatches(findRawSqlConcatNodes(sourceFile).map((node) => matchFromNode(file, sourceFile, node)));
}

export function findDangerouslySetInnerHtmlMatches(file: SourceFile): DangerouslySetInnerHtmlMatch[] {
  const { sourceFile, sanitizerIdentifiers, safeHtmlIdentifiers } = getAnalysisFacts(file);
  return dedupeMatches(
    findDangerouslySetInnerHtmlNodes(sourceFile, sanitizerIdentifiers, safeHtmlIdentifiers).map(({ node, severity }) => ({
      ...matchFromNode(file, sourceFile, node),
      severity
    }))
  );
}

export function findPasswordHandlingMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, hasPasswordHashing } = getAnalysisFacts(file);
  if (hasPasswordHashing) {
    return [];
  }

  return dedupeMatches(findPasswordHandlingNodes(sourceFile).map((node) => matchFromNode(file, sourceFile, node)));
}

export function findRouteHandlerExports(file: SourceFile): AstMatch[] {
  const { sourceFile, routeHandlerNodes } = getAnalysisFacts(file);
  return dedupeMatches(routeHandlerNodes.map((node) => matchFromNode(file, sourceFile, node)));
}

export function hasAuthIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasAuthIntent;
}

export function hasValidationIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasValidationIntent;
}

export function findUploadRouteHandlerMatches(file: SourceFile): AstMatch[] {
  if (!isApiRouteFilePath(file.path)) {
    return [];
  }

  const { sourceFile, routeHandlerNodes, hasUploadHandling } = getAnalysisFacts(file);
  const routeHandlerMatches = routeHandlerNodes
    .filter((node) => {
      const name = exportedRouteHandlerName(node);
      return name === "DEFAULT" || name === "POST" || name === "PUT" || name === "PATCH";
    })
    .map((node) => matchFromNode(file, sourceFile, node));

  return hasUploadHandling ? dedupeMatches(routeHandlerMatches) : [];
}

function createAnalysisFacts(sourceFile: ts.SourceFile): AnalysisFacts {
  const commandIdentifiers = new Set<string>();
  const childProcessNamespaces = new Set<string>();
  const commandDeclarationNodes: ts.Node[] = [];
  const routeHandlerNodes: ts.Node[] = [];
  let hasUploadHandling = false;

  visit(sourceFile, (node) => {
    collectChildProcessImports(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);
    collectChildProcessRequires(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);

    const routeName = exportedRouteHandlerName(node);
    if (routeName && (routeName === "DEFAULT" || ROUTE_HANDLER_NAMES.has(routeName))) {
      routeHandlerNodes.push(node);
    }

    if (!hasUploadHandling && isUploadHandlingNode(node)) {
      hasUploadHandling = true;
    }
  });

  const xssFacts = createXssAnalysisFacts(sourceFile);

  return {
    sourceFile,
    commandIdentifiers,
    childProcessNamespaces,
    commandDeclarationNodes,
    commandSourcePaths: collectCommandSourcePaths(sourceFile, commandIdentifiers, childProcessNamespaces),
    routeHandlerNodes,
    sanitizerIdentifiers: xssFacts.sanitizerIdentifiers,
    safeHtmlIdentifiers: xssFacts.safeHtmlIdentifiers,
    hasPasswordHashing: hasPasswordHashingCall(sourceFile),
    hasAuthIntent: hasAuthIntentInSource(sourceFile),
    hasValidationIntent: hasValidationIntentInSource(sourceFile),
    hasUploadHandling
  };
}

function collectChildProcessImports(
  node: ts.Node,
  commandIdentifiers: Set<string>,
  childProcessNamespaces: Set<string>,
  declarationNodes: ts.Node[]
): void {
  if (!ts.isImportDeclaration(node) || !isChildProcessSpecifier(node.moduleSpecifier)) {
    return;
  }

  const importClause = node.importClause;
  if (!importClause) {
    return;
  }

  if (importClause.name) {
    childProcessNamespaces.add(importClause.name.text);
  }

  const namedBindings = importClause.namedBindings;
  if (namedBindings && ts.isNamespaceImport(namedBindings)) {
    childProcessNamespaces.add(namedBindings.name.text);
    return;
  }

  if (!namedBindings || !ts.isNamedImports(namedBindings)) {
    return;
  }

  for (const importSpecifier of namedBindings.elements) {
    const importedName = importSpecifier.propertyName?.text ?? importSpecifier.name.text;
    if (!COMMAND_EXECUTION_NAMES.has(importedName)) {
      continue;
    }

    commandIdentifiers.add(importSpecifier.name.text);
    if (importedName === "exec" || importedName === "execSync") {
      declarationNodes.push(importSpecifier);
    }
  }
}

function collectChildProcessRequires(
  node: ts.Node,
  commandIdentifiers: Set<string>,
  childProcessNamespaces: Set<string>,
  declarationNodes: ts.Node[]
): void {
  if (!ts.isVariableDeclaration(node) || !node.initializer) {
    return;
  }

  if (isRequireChildProcessCall(node.initializer)) {
    if (ts.isIdentifier(node.name)) {
      childProcessNamespaces.add(node.name.text);
      return;
    }

    if (ts.isObjectBindingPattern(node.name)) {
      for (const element of node.name.elements) {
        const importedName = bindingElementName(element);
        const localName = bindingElementLocalName(element);
        if (!importedName || !localName || !COMMAND_EXECUTION_NAMES.has(importedName)) {
          continue;
        }

        commandIdentifiers.add(localName);
        if (importedName === "exec" || importedName === "execSync") {
          declarationNodes.push(element);
        }
      }
    }

    return;
  }

  if (ts.isPropertyAccessExpression(node.initializer) && isRequireChildProcessCall(node.initializer.expression)) {
    const importedName = node.initializer.name.text;
    if (ts.isIdentifier(node.name) && COMMAND_EXECUTION_NAMES.has(importedName)) {
      commandIdentifiers.add(node.name.text);
      if (importedName === "exec" || importedName === "execSync") {
        declarationNodes.push(node);
      }
    }
  }
}

function isRequireChildProcessCall(node: ts.Node): boolean {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "require") {
    return false;
  }

  const [specifier] = node.arguments;
  return isChildProcessSpecifier(specifier);
}

function matchFromNode(file: SourceFile, sourceFile: ts.SourceFile, node: ts.Node): AstMatch {
  const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const sourceLine = file.lines[position.line] ?? "";

  return {
    line: position.line + 1,
    column: position.character + 1,
    evidence: sourceLine.trim(),
    sourceLine
  };
}

function dedupeMatches<TMatch extends AstMatch>(matches: TMatch[]): TMatch[] {
  const seen = new Set<string>();
  const uniqueMatches: TMatch[] = [];

  for (const match of matches) {
    const key = `${match.line}:${match.column}:${match.evidence}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    uniqueMatches.push(match);
  }

  return uniqueMatches.sort((left, right) => left.line - right.line || left.column - right.column);
}

function scriptKindForPath(filePath: string): ts.ScriptKind {
  if (/\.tsx$/i.test(filePath)) {
    return ts.ScriptKind.TSX;
  }

  if (/\.jsx$/i.test(filePath)) {
    return ts.ScriptKind.JSX;
  }

  if (/\.ts$/i.test(filePath)) {
    return ts.ScriptKind.TS;
  }

  return ts.ScriptKind.JS;
}

function visit(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visit(child, callback));
}
