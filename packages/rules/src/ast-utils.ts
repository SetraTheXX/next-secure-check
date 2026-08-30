import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";
import { SourceAnalysisCache, type AnalysisCacheStats } from "./analysis-cache.js";
import type { BoundedFlowFacts } from "./analysis-facts.js";
import { collectCommandDiscovery } from "./command-discovery.js";
import { collectCommandFlowFacts, isAnalyzableCommandExecutionCall } from "./command-flow.js";
import { findPasswordHandlingNodes, hasPasswordHashingCall } from "./password-ast.js";
import { createRawSqlFlowCallbacks, findRawSqlConcatNodes } from "./sql-ast.js";
import {
  ROUTE_HANDLER_NAMES,
  exportedRouteHandlerName,
  findRequestBoundarySources,
  hasRequestBoundaryGuardInSource,
  hasAuthIntentInSource,
  hasRateLimitIntentInSource,
  hasValidationIntentInSource,
  isApiRouteFilePath,
  isUploadHandlingNode
} from "./route-ast.js";
import { findServerActionBoundaries } from "./server-action-ast.js";
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

export type ServerActionMatch = AstMatch & {
  boundaryName: string;
  hasAuthIntent: boolean;
  hasValidationIntent: boolean;
};

export type AnalysisFacts = {
  sourceFile: ts.SourceFile;
  boundedFlow: BoundedFlowFacts;
  commandIdentifiers: ReadonlySet<string>;
  childProcessNamespaces: ReadonlySet<string>;
  commandDeclarationNodes: readonly ts.Node[];
  commandSourcePaths: ReadonlyMap<ts.CallExpression, string>;
  safeCommandCalls: ReadonlySet<ts.CallExpression>;
  routeHandlerNodes: readonly ts.Node[];
  sanitizerIdentifiers: ReadonlySet<string>;
  untrustedSanitizerIdentifiers: ReadonlySet<string>;
  safeHtmlIdentifiers: ReadonlySet<string>;
  hasPasswordHashing: boolean;
  hasAuthIntent: boolean;
  hasRateLimitIntent: boolean;
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
  const { sourceFile, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes, commandSourcePaths, safeCommandCalls } = getAnalysisFacts(file);
  const matches = commandDeclarationNodes.map((node) => matchFromNode(file, sourceFile, node));

  visit(sourceFile, (node) => {
    if (
      !ts.isCallExpression(node) ||
      safeCommandCalls.has(node) ||
      !isAnalyzableCommandExecutionCall(node, commandIdentifiers, childProcessNamespaces)
    ) {
      return;
    }

    const match = matchFromNode(file, sourceFile, node);
    const evidencePath = commandSourcePaths.get(node);
    matches.push(evidencePath ? { ...match, evidencePath } : match);
  });

  return dedupeMatches(matches);
}

export function findRawSqlConcatMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, boundedFlow } = getAnalysisFacts(file);
  const directMatches = findRawSqlConcatNodes(sourceFile);
  const boundedMatches = boundedFlow.sinks
    .filter((sink) => sink.kind === "raw-sql")
    .map((sink) => sink.node);
  const nodes = [...directMatches, ...boundedMatches];

  return dedupeMatches(
    nodes.map((node) => {
      const match = matchFromNode(file, sourceFile, node);
      const evidencePath = boundedFlow.evidencePaths.get(node);
      return evidencePath ? { ...match, evidencePath } : match;
    })
  );
}

export function findDangerouslySetInnerHtmlMatches(file: SourceFile): DangerouslySetInnerHtmlMatch[] {
  const { sourceFile, boundedFlow, sanitizerIdentifiers, untrustedSanitizerIdentifiers, safeHtmlIdentifiers } = getAnalysisFacts(file);
  return dedupeMatches(
    findDangerouslySetInnerHtmlNodes(
      sourceFile,
      sanitizerIdentifiers,
      safeHtmlIdentifiers,
      boundedFlow,
      untrustedSanitizerIdentifiers
    ).map(({ node, severity, evidencePath }) => ({
      ...matchFromNode(file, sourceFile, node),
      severity,
      ...(evidencePath ? { evidencePath } : {})
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

export function hasRateLimitIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasRateLimitIntent;
}

export function hasValidationIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasValidationIntent;
}

export function findRequestBoundaryInputMatches(file: SourceFile): AstMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  return dedupeMatches(
    findRequestBoundarySources(sourceFile).map(({ node, path }) => ({
      ...matchFromNode(file, sourceFile, node),
      evidencePath: path
    }))
  );
}

export function hasRequestBoundaryGuardSignal(file: SourceFile): boolean {
  return hasRequestBoundaryGuardInSource(getAnalysisFacts(file).sourceFile);
}

export function findServerActionMatches(file: SourceFile): ServerActionMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  return dedupeMatches(
    findServerActionBoundaries(sourceFile).map((boundary) => ({
      ...matchFromNode(file, sourceFile, boundary.node),
      boundaryName: boundary.name,
      evidencePath: boundary.inputPath,
      hasAuthIntent: boundary.hasAuthIntent,
      hasValidationIntent: boundary.hasValidationIntent
    }))
  );
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
  const commandDiscovery = collectCommandDiscovery(sourceFile);
  const commandFlow = collectCommandFlowFacts(
    sourceFile,
    commandDiscovery.commandIdentifiers,
    commandDiscovery.childProcessNamespaces,
    createRawSqlFlowCallbacks()
  );
  const routeHandlerNodes: ts.Node[] = [];
  let hasUploadHandling = false;

  visit(sourceFile, (node) => {
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
    boundedFlow: commandFlow.boundedFlow,
    commandIdentifiers: commandDiscovery.commandIdentifiers,
    childProcessNamespaces: commandDiscovery.childProcessNamespaces,
    commandDeclarationNodes: commandDiscovery.commandDeclarationNodes,
    commandSourcePaths: commandFlow.sourcePaths,
    safeCommandCalls: commandFlow.safeCommandCalls,
    routeHandlerNodes,
    sanitizerIdentifiers: xssFacts.sanitizerIdentifiers,
    untrustedSanitizerIdentifiers: xssFacts.untrustedSanitizerIdentifiers,
    safeHtmlIdentifiers: xssFacts.safeHtmlIdentifiers,
    hasPasswordHashing: hasPasswordHashingCall(sourceFile),
    hasAuthIntent: hasAuthIntentInSource(sourceFile),
    hasRateLimitIntent: hasRateLimitIntentInSource(sourceFile),
    hasValidationIntent: hasValidationIntentInSource(sourceFile),
    hasUploadHandling
  };
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
