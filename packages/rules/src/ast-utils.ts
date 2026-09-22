import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";
import { SourceAnalysisCache, type AnalysisCacheStats } from "./analysis-cache.js";
import type { BoundedFlowFacts } from "./analysis-facts.js";
import { collectCommandDiscovery } from "./command-discovery.js";
import { collectCommandFlowFacts, isAnalyzableCommandExecutionCall, type BoundedFlowCallbacks } from "./command-flow.js";
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
import { findUnvalidatedRedirectTargets, type RedirectDestinationKind } from "./redirect-flow.js";
import { createSsrfFlowAnalysis, type SsrfFlowMatch } from "./ssrf-flow.js";
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

export type RedirectMatch = AstMatch & {
  destinationKind: RedirectDestinationKind;
  sinkName: string;
};

export type OutboundRequestMatch = AstMatch & {
  evidencePath: string;
  sinkName: string;
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
  ssrfMatches: readonly SsrfFlowMatch[];
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

export function findUnvalidatedRedirectMatches(file: SourceFile): RedirectMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  return dedupeMatches(
    findUnvalidatedRedirectTargets(sourceFile).map((match) => ({
      ...matchFromNode(file, sourceFile, match.node),
      evidencePath: match.evidencePath,
      destinationKind: match.destinationKind,
      sinkName: match.sinkName
    }))
  );
}

export function findUnvalidatedOutboundRequestMatches(file: SourceFile): OutboundRequestMatch[] {
  const { sourceFile, ssrfMatches } = getAnalysisFacts(file);
  return dedupeMatches(
    ssrfMatches.map((match) => ({
      ...matchFromNode(file, sourceFile, match.node),
      evidencePath: match.evidencePath,
      sinkName: match.sinkName
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

export function findDynamicFunctionMatches(file: SourceFile): AstMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  const matches: AstMatch[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node) && !ts.isNewExpression(node)) {
      return;
    }

    if (referencesGlobalFunction(node.expression)) {
      matches.push(matchFromNode(file, sourceFile, node));
    }
  });

  return dedupeMatches(matches);
}

function createAnalysisFacts(sourceFile: ts.SourceFile): AnalysisFacts {
  const rawSqlCallbacks = createRawSqlFlowCallbacks();
  const ssrfAnalysis = createSsrfFlowAnalysis(sourceFile);
  const commandDiscovery = collectCommandDiscovery(sourceFile);
  const commandFlow = collectCommandFlowFacts(
    sourceFile,
    commandDiscovery.commandIdentifiers,
    commandDiscovery.childProcessNamespaces,
    mergeBoundedFlowCallbacks(rawSqlCallbacks, ssrfAnalysis.callbacks)
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
    hasUploadHandling,
    ssrfMatches: ssrfAnalysis.getMatches()
  };
}

function mergeBoundedFlowCallbacks(...callbackSets: BoundedFlowCallbacks[]): BoundedFlowCallbacks {
  return {
    onVariableDeclaration: (node, context) => callbackSets.forEach((callbacks) => callbacks.onVariableDeclaration?.(node, context)),
    onAssignment: (node, context) => callbackSets.forEach((callbacks) => callbacks.onAssignment?.(node, context)),
    onCall: (node, context) => callbackSets.forEach((callbacks) => callbacks.onCall?.(node, context)),
    shouldSkipCallInvalidation: (node, context) => callbackSets.some((callbacks) => callbacks.shouldSkipCallInvalidation?.(node, context) ?? false),
    onTaggedTemplate: (node, context) => callbackSets.forEach((callbacks) => callbacks.onTaggedTemplate?.(node, context)),
    onInvalidation: (identifier, reason, context) => callbackSets.forEach((callbacks) => callbacks.onInvalidation?.(identifier, reason, context))
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

const GLOBAL_OBJECT_NAMES = new Set(["window", "globalThis", "global", "self"]);

function referencesGlobalFunction(expression: ts.Expression): boolean {
  if (ts.isIdentifier(expression)) {
    return expression.text === "Function" && !isNameShadowedAt(expression, expression.text);
  }

  if (ts.isPropertyAccessExpression(expression)) {
    return expression.name.text === "Function" && isGlobalObjectReference(expression.expression);
  }

  if (ts.isElementAccessExpression(expression)) {
    return isFunctionNameLiteral(expression.argumentExpression) && isGlobalObjectReference(expression.expression);
  }

  return false;
}

function isGlobalObjectReference(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && GLOBAL_OBJECT_NAMES.has(expression.text) && !isNameShadowedAt(expression, expression.text);
}

function isFunctionNameLiteral(node: ts.Expression | undefined): boolean {
  return node !== undefined && ts.isStringLiteralLike(node) && node.text === "Function";
}

type FunctionScopeNode =
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration
  | ts.ConstructorDeclaration
  | ts.GetAccessorDeclaration
  | ts.SetAccessorDeclaration;

function isFunctionScope(node: ts.Node): node is FunctionScopeNode {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function isNameShadowedAt(node: ts.Node, name: string): boolean {
  for (let current: ts.Node | undefined = node; current !== undefined; current = current.parent) {
    if (scopeDeclaresName(current, name)) {
      return true;
    }
  }

  return false;
}

function scopeDeclaresName(scope: ts.Node, name: string): boolean {
  if (ts.isSourceFile(scope) || ts.isBlock(scope) || ts.isModuleBlock(scope)) {
    return (
      scope.statements.some((statement) => statementDeclaresName(statement, name)) ||
      nodeDeclaresVarName(scope, name)
    );
  }

  if (ts.isCaseBlock(scope)) {
    return (
      scope.clauses.some((clause) => clause.statements.some((statement) => statementDeclaresName(statement, name))) ||
      nodeDeclaresVarName(scope, name)
    );
  }

  if (isFunctionScope(scope)) {
    return functionScopeDeclaresName(scope, name);
  }

  if (ts.isCatchClause(scope)) {
    return scope.variableDeclaration !== undefined && bindingDeclaresName(scope.variableDeclaration.name, name);
  }

  if (ts.isForStatement(scope) || ts.isForInStatement(scope) || ts.isForOfStatement(scope)) {
    return scope.initializer !== undefined && ts.isVariableDeclarationList(scope.initializer) && variableDeclarationListDeclaresName(scope.initializer, name);
  }

  return false;
}

function functionScopeDeclaresName(node: FunctionScopeNode, name: string): boolean {
  const declarationName = functionScopeDeclarationName(node);
  if (declarationName === name) {
    return true;
  }

  if (node.parameters.some((parameter) => bindingDeclaresName(parameter.name, name))) {
    return true;
  }

  return nodeDeclaresVarName(node.body, name);
}

function functionScopeDeclarationName(node: FunctionScopeNode): string | undefined {
  if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) {
    return node.name?.text;
  }

  return undefined;
}

function nodeDeclaresVarName(node: ts.Node | undefined, name: string): boolean {
  if (node === undefined || isFunctionScope(node)) {
    return false;
  }

  if (ts.isVariableDeclarationList(node) && (node.flags & ts.NodeFlags.BlockScoped) === 0) {
    return variableDeclarationListDeclaresName(node, name);
  }

  return ts.forEachChild(node, (child) => nodeDeclaresVarName(child, name)) ?? false;
}

function statementDeclaresName(statement: ts.Statement, name: string): boolean {
  if (ts.isImportDeclaration(statement)) {
    return importDeclarationDeclaresName(statement, name);
  }

  if (ts.isVariableStatement(statement)) {
    return variableDeclarationListDeclaresName(statement.declarationList, name);
  }

  if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) || ts.isEnumDeclaration(statement) || ts.isModuleDeclaration(statement)) {
    return statement.name?.text === name;
  }

  return false;
}

function importDeclarationDeclaresName(statement: ts.ImportDeclaration, name: string): boolean {
  const clause = statement.importClause;
  if (clause === undefined) {
    return false;
  }

  if (clause.name?.text === name) {
    return true;
  }

  const bindings = clause.namedBindings;
  if (bindings === undefined) {
    return false;
  }

  return ts.isNamespaceImport(bindings) ? bindings.name.text === name : bindings.elements.some((element) => element.name.text === name);
}

function variableDeclarationListDeclaresName(list: ts.VariableDeclarationList, name: string): boolean {
  return list.declarations.some((declaration) => bindingDeclaresName(declaration.name, name));
}

function bindingDeclaresName(binding: ts.BindingName, name: string): boolean {
  return bindingIdentifiers(binding).some((identifier) => identifier.text === name);
}

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) {
    return [name];
  }

  return name.elements.flatMap((element) => (ts.isBindingElement(element) ? bindingIdentifiers(element.name) : []));
}

function visit(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visit(child, callback));
}
