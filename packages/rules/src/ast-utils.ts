import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";
import { SourceAnalysisCache, type AnalysisCacheStats } from "./analysis-cache.js";
import {
  COMMAND_ALIAS_LIMIT,
  COMMAND_EXECUTION_NAMES,
  REQUEST_SOURCE_NAMES,
  ROUTE_PARAMS_NAMES,
  SEARCH_PARAMS_NAME,
  commandExecutionName,
  isCommandAssignmentOperator,
  isCommandExecutionCall,
  isCommandMutationOperator
} from "./command-ast.js";

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

const ROUTE_HANDLER_NAMES = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);
const SQL_QUERY_METHOD_NAMES = new Set(["query", "execute"]);
const SQL_RAW_TAG_NAMES = new Set(["$queryRaw", "$executeRaw"]);
const SQL_KEYWORD_PATTERN = /\b(SELECT|INSERT|UPDATE|DELETE)\b/i;
const SANITIZER_MODULE_PATTERN = /^(?:dompurify|sanitize-html)$/i;
const AUTH_CALL_NAMES = new Set([
  "auth",
  "clerk",
  "currentUser",
  "getServerSession",
  "getUser",
  "isAdmin",
  "middleware",
  "requireAuth",
  "verifyToken",
  "withAuth"
]);
const AUTH_GUARD_PROPERTY_NAMES = new Set(["permission", "role"]);
const AUTH_GUARD_TARGET_NAMES = new Set(["account", "claims", "session", "user"]);
const VALIDATION_CALL_NAMES = new Set(["isValid", "parse", "safeParse", "validate", "validateSync"]);
const VALIDATION_MODULE_PATTERN = /^(?:arktype|joi|superstruct|valibot|yup|zod)(?:\/|$)/i;
const VALIDATION_TYPE_NAMES = new Set(["boolean", "function", "number", "object", "string"]);
const TYPEOF_COMPARISON_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken
]);

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
  const matches: AstMatch[] = [];

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node) && isSqlQuerySinkCall(node)) {
      const [firstArgument] = node.arguments;
      if (isInterpolatedSqlTemplate(firstArgument)) {
        matches.push(matchFromNode(file, sourceFile, node));
      }
      return;
    }

    if (ts.isTaggedTemplateExpression(node) && isRawSqlTaggedTemplate(node) && isInterpolatedSqlTemplate(node.template)) {
      matches.push(matchFromNode(file, sourceFile, node));
    }
  });

  return dedupeMatches(matches);
}

export function findDangerouslySetInnerHtmlMatches(file: SourceFile): DangerouslySetInnerHtmlMatch[] {
  const { sourceFile, sanitizerIdentifiers, safeHtmlIdentifiers } = getAnalysisFacts(file);
  const matches: DangerouslySetInnerHtmlMatch[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isJsxAttribute(node) || !ts.isIdentifier(node.name) || node.name.text !== "dangerouslySetInnerHTML") {
      return;
    }

    const severity = dangerouslySetInnerHtmlSeverity(node.initializer, sanitizerIdentifiers, safeHtmlIdentifiers);
    if (!severity) {
      return;
    }

    matches.push({
      ...matchFromNode(file, sourceFile, node),
      severity
    });
  });

  return dedupeMatches(matches);
}

export function findPasswordHandlingMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, hasPasswordHashing } = getAnalysisFacts(file);
  const matches: AstMatch[] = [];

  if (hasPasswordHashing) {
    return matches;
  }

  visit(sourceFile, (node) => {
    if (isPasswordHandlingNode(node)) {
      matches.push(matchFromNode(file, sourceFile, node));
    }
  });

  return dedupeMatches(matches);
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

  const sanitizerIdentifiers = collectSanitizerIdentifiers(sourceFile);

  return {
    sourceFile,
    commandIdentifiers,
    childProcessNamespaces,
    commandDeclarationNodes,
    commandSourcePaths: collectCommandSourcePaths(sourceFile, commandIdentifiers, childProcessNamespaces),
    routeHandlerNodes,
    sanitizerIdentifiers,
    safeHtmlIdentifiers: collectSafeHtmlIdentifiers(sourceFile, sanitizerIdentifiers),
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

function isAnalyzableCommandExecutionCall(
  node: ts.CallExpression,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>
): boolean {
  return isCommandExecutionCall(node.expression, commandIdentifiers, childProcessNamespaces) && !isSafeStaticSpawnCall(node);
}

function isSafeStaticSpawnCall(node: ts.CallExpression): boolean {
  const methodName = commandExecutionName(node.expression);
  if (methodName !== "spawn" && methodName !== "spawnSync") {
    return false;
  }

  const command = node.arguments[0] ? unwrapCommandExpression(node.arguments[0]) : undefined;
  const argumentsArray = node.arguments[1] ? unwrapCommandExpression(node.arguments[1]) : undefined;
  if (!command || literalText(command) === undefined || !argumentsArray || !ts.isArrayLiteralExpression(argumentsArray)) {
    return false;
  }

  if (!argumentsArray.elements.every((element) => !ts.isSpreadElement(element) && literalText(element) !== undefined)) {
    return false;
  }

  const options = node.arguments[2] ? unwrapCommandExpression(node.arguments[2]) : undefined;
  if (!options) {
    return true;
  }

  if (!ts.isObjectLiteralExpression(options)) {
    return false;
  }

  return options.properties.every((property) => {
    if (ts.isSpreadAssignment(property)) {
      return false;
    }

    if (!ts.isPropertyAssignment(property)) {
      return true;
    }

    const propertyName = ts.isIdentifier(property.name) || ts.isStringLiteral(property.name) ? property.name.text : undefined;
    if (!propertyName) {
      return false;
    }

    if (propertyName !== "shell") {
      return true;
    }

    return property.initializer.kind === ts.SyntaxKind.FalseKeyword;
  });
}

type CommandFlowValue = {
  path: string;
  aliasDepth: number;
};

type CommandFlowState = {
  declared: Set<string>;
  initialized: Set<string>;
  invalidated: Set<string>;
  tracked: Map<string, CommandFlowValue>;
};

type CommandFunctionLike =
  | ts.ArrowFunction
  | ts.ConstructorDeclaration
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.GetAccessorDeclaration
  | ts.MethodDeclaration
  | ts.SetAccessorDeclaration;

function collectCommandSourcePaths(
  sourceFile: ts.SourceFile,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>
): ReadonlyMap<ts.CallExpression, string> {
  const sourcePaths = new Map<ts.CallExpression, string>();
  analyzeCommandScope(sourceFile, sourceFile, commandIdentifiers, childProcessNamespaces, sourcePaths);

  visit(sourceFile, (node) => {
    if (!isCommandFunctionLike(node)) {
      return;
    }

    const body = commandFunctionBody(node);
    if (body) {
      analyzeCommandScope(body, body, commandIdentifiers, childProcessNamespaces, sourcePaths);
    }
  });

  return sourcePaths;
}

function analyzeCommandScope(
  scopeRoot: ts.Node,
  node: ts.Node,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>,
  sourcePaths: Map<ts.CallExpression, string>,
  state: CommandFlowState = createCommandFlowState()
): void {
  if (node !== scopeRoot && isCommandFunctionLike(node)) {
    return;
  }

  if (ts.isVariableDeclaration(node)) {
    recordCommandDeclaration(node, state);
  }

  if (ts.isBinaryExpression(node) && isCommandAssignmentOperator(node.operatorToken.kind)) {
    recordCommandAssignment(node, state);
  }

  if (ts.isPrefixUnaryExpression(node) && isCommandMutationOperator(node.operator)) {
    invalidateCommandTarget(node.operand, state);
  }

  if (ts.isPostfixUnaryExpression(node) && isCommandMutationOperator(node.operator)) {
    invalidateCommandTarget(node.operand, state);
  }

  if (ts.isCallExpression(node)) {
    if (isAnalyzableCommandExecutionCall(node, commandIdentifiers, childProcessNamespaces)) {
      const sourcePath = findCommandSourcePathInArguments(node, state);
      if (sourcePath) {
        sourcePaths.set(node, sourcePath);
      } else {
        invalidateTaintedReferences(node, state);
      }
    } else if (!sourcePathForExpression(node, state)) {
      invalidateTaintedReferences(node, state);
    }
  }

  ts.forEachChild(node, (child) =>
    analyzeCommandScope(scopeRoot, child, commandIdentifiers, childProcessNamespaces, sourcePaths, state)
  );
}

function createCommandFlowState(): CommandFlowState {
  return {
    declared: new Set<string>(),
    initialized: new Set<string>(),
    invalidated: new Set<string>(),
    tracked: new Map<string, CommandFlowValue>()
  };
}

function recordCommandDeclaration(node: ts.VariableDeclaration, state: CommandFlowState): void {
  if (ts.isIdentifier(node.name)) {
    state.declared.add(node.name.text);
    if (!node.initializer) {
      return;
    }

    state.initialized.add(node.name.text);
    trackCommandValue(node.name.text, sourcePathForAssignment(node.initializer, state, node.name.text), state);
    return;
  }

  if (!ts.isObjectBindingPattern(node.name) || !node.initializer) {
    return;
  }

  const base = sourcePathForReference(node.initializer, state);
  for (const element of node.name.elements) {
    const localName = bindingElementLocalName(element);
    const propertyName = bindingElementName(element);
    if (!localName) {
      continue;
    }

    state.declared.add(localName);
    state.initialized.add(localName);
    trackCommandValue(
      localName,
      base && propertyName ? commandProperty(base, propertyName) : undefined,
      state
    );
  }
}

function recordCommandAssignment(node: ts.BinaryExpression, state: CommandFlowState): void {
  const target = commandTargetIdentifier(node.left);
  if (!target) {
    invalidateTaintedReferences(node.left, state);
    return;
  }

  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) {
    invalidateCommandTarget(node.left, state);
    return;
  }

  if (state.invalidated.has(target) || state.initialized.has(target)) {
    invalidateCommandTarget(node.left, state);
    return;
  }

  state.declared.add(target);
  state.initialized.add(target);
  trackCommandValue(target, sourcePathForAssignment(node.right, state, target), state);
}

function trackCommandValue(name: string, value: CommandFlowValue | undefined, state: CommandFlowState): void {
  if (!value || value.aliasDepth > COMMAND_ALIAS_LIMIT || state.invalidated.has(name)) {
    state.tracked.delete(name);
    return;
  }

  state.tracked.set(name, value);
}

function findCommandSourcePathInArguments(node: ts.CallExpression, state: CommandFlowState): string | undefined {
  for (const argument of node.arguments) {
    const sourcePath = findCommandSourcePathInExpression(argument, state);
    if (sourcePath) {
      return sourcePath;
    }
  }

  return undefined;
}

function findCommandSourcePathInExpression(node: ts.Node, state: CommandFlowState): string | undefined {
  const directSource = sourcePathForExpression(node as ts.Expression, state);
  if (directSource) {
    return directSource.path;
  }

  let sourcePath: string | undefined;
  ts.forEachChild(node, (child) => {
    if (sourcePath || isCommandFunctionLike(child)) {
      return;
    }

    sourcePath = findCommandSourcePathInExpression(child, state);
  });

  return sourcePath;
}

function sourcePathForExpression(expression: ts.Expression, state: CommandFlowState): CommandFlowValue | undefined {
  const normalized = unwrapCommandExpression(expression);

  if (ts.isBinaryExpression(normalized)) {
    return sourcePathForExpression(normalized.left, state) ?? sourcePathForExpression(normalized.right, state);
  }

  if (ts.isConditionalExpression(normalized)) {
    return sourcePathForExpression(normalized.whenTrue, state) ?? sourcePathForExpression(normalized.whenFalse, state);
  }

  if (ts.isIdentifier(normalized)) {
    const tracked = state.tracked.get(normalized.text);
    if (tracked && !state.invalidated.has(normalized.text)) {
      return tracked;
    }

    if (ROUTE_PARAMS_NAMES.test(normalized.text)) {
      return { path: normalized.text, aliasDepth: 0 };
    }

    return undefined;
  }

  return sourcePathForReference(normalized, state);
}

function sourcePathForAssignment(
  expression: ts.Expression,
  state: CommandFlowState,
  targetName?: string
): CommandFlowValue | undefined {
  const normalized = unwrapCommandExpression(expression);
  if (ts.isIdentifier(normalized)) {
    const tracked = state.tracked.get(normalized.text);
    if (tracked && !state.invalidated.has(normalized.text)) {
      return commandAlias(tracked, targetName ?? normalized.text);
    }
  }

  return sourcePathForExpression(normalized, state);
}

function sourcePathForReference(expression: ts.Expression, state: CommandFlowState): CommandFlowValue | undefined {
  const normalized = unwrapCommandExpression(expression);

  if (ts.isIdentifier(normalized)) {
    if (state.invalidated.has(normalized.text)) {
      return undefined;
    }

    return state.tracked.get(normalized.text) ?? (ROUTE_PARAMS_NAMES.test(normalized.text) ? { path: normalized.text, aliasDepth: 0 } : undefined);
  }

  if (ts.isPropertyAccessExpression(normalized)) {
    const directSource = directCommandPropertySource(normalized);
    if (directSource) {
      return directSource;
    }

    const base = sourcePathForReference(normalized.expression, state);
    return base ? commandProperty(base, normalized.name.text) : undefined;
  }

  if (ts.isElementAccessExpression(normalized)) {
    const propertyName = normalized.argumentExpression && literalText(normalized.argumentExpression);
    if (!propertyName) {
      return undefined;
    }

    const directSource = directCommandElementSource(normalized, propertyName);
    if (directSource) {
      return directSource;
    }

    const base = sourcePathForReference(normalized.expression, state);
    return base ? commandProperty(base, propertyName) : undefined;
  }

  if (ts.isCallExpression(normalized) && ts.isPropertyAccessExpression(normalized.expression)) {
    const methodName = normalized.expression.name.text;
    const receiver = normalized.expression.expression;
    if ((methodName === "json" || methodName === "formData") && isRequestSourceReceiver(receiver)) {
      return { path: `${commandExpressionLabel(receiver)}.${methodName}()`, aliasDepth: 0 };
    }

    if (methodName === "get") {
      if (isSearchParamsReceiver(receiver)) {
        return { path: `${commandExpressionLabel(receiver)}.get()`, aliasDepth: 0 };
      }

      const base = sourcePathForReference(receiver, state);
      return base ? commandProperty(base, "get()") : undefined;
    }
  }

  return undefined;
}

function directCommandPropertySource(node: ts.PropertyAccessExpression): CommandFlowValue | undefined {
  if (!isRequestSourceReceiver(node.expression) || (node.name.text !== "body" && node.name.text !== "query")) {
    return undefined;
  }

  return { path: `${commandExpressionLabel(node.expression)}.${node.name.text}`, aliasDepth: 0 };
}

function directCommandElementSource(node: ts.ElementAccessExpression, propertyName: string): CommandFlowValue | undefined {
  if (!isRequestSourceReceiver(node.expression) || (propertyName !== "body" && propertyName !== "query")) {
    return undefined;
  }

  return { path: `${commandExpressionLabel(node.expression)}.${propertyName}`, aliasDepth: 0 };
}

function commandProperty(value: CommandFlowValue, propertyName: string): CommandFlowValue {
  return {
    path: `${value.path} -> ${propertyName}`,
    aliasDepth: value.aliasDepth
  };
}

function commandAlias(value: CommandFlowValue, aliasName: string): CommandFlowValue {
  return {
    path: `${value.path} -> ${aliasName}`,
    aliasDepth: value.aliasDepth + 1
  };
}

function invalidateCommandTarget(node: ts.Node, state: CommandFlowState): void {
  const target = commandTargetIdentifier(node);
  if (target) {
    state.tracked.delete(target);
    state.invalidated.add(target);
  }

  invalidateTaintedReferences(node, state);
}

function invalidateTaintedReferences(node: ts.Node, state: CommandFlowState): void {
  const identifiers = new Set<string>();
  visit(node, (child) => {
    if (!ts.isIdentifier(child) || !state.tracked.has(child.text)) {
      return;
    }

    if (ts.isPropertyAccessExpression(child.parent) && child.parent.name === child) {
      return;
    }

    identifiers.add(child.text);
  });

  for (const identifier of identifiers) {
    state.tracked.delete(identifier);
    state.invalidated.add(identifier);
  }
}

function commandTargetIdentifier(node: ts.Node): string | undefined {
  if (ts.isIdentifier(node)) {
    return node.text;
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return commandTargetIdentifier(node.expression);
  }

  return undefined;
}

function unwrapCommandExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAwaitExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression;
  }

  return current;
}

function isRequestSourceReceiver(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && REQUEST_SOURCE_NAMES.test(expression.text);
}

function isSearchParamsReceiver(expression: ts.Expression): boolean {
  if (ts.isIdentifier(expression)) {
    return SEARCH_PARAMS_NAME.test(expression.text);
  }

  return ts.isPropertyAccessExpression(expression) && SEARCH_PARAMS_NAME.test(expression.name.text);
}

function commandExpressionLabel(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }

  if (ts.isPropertyAccessExpression(expression)) {
    return `${commandExpressionLabel(expression.expression)}.${expression.name.text}`;
  }

  return "source";
}

function literalText(node: ts.Expression): string | undefined {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ? node.text : undefined;
}

function isCommandFunctionLike(node: ts.Node): node is CommandFunctionLike {
  return (
    ts.isArrowFunction(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function commandFunctionBody(node: CommandFunctionLike): ts.Node | undefined {
  return node.body;
}

function isSqlQuerySinkCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  return ts.isPropertyAccessExpression(expression) && SQL_QUERY_METHOD_NAMES.has(expression.name.text);
}

function isRawSqlTaggedTemplate(node: ts.TaggedTemplateExpression): boolean {
  const tag = node.tag;
  return ts.isPropertyAccessExpression(tag) && SQL_RAW_TAG_NAMES.has(tag.name.text);
}

function isAuthIntentCall(expression: ts.Expression): boolean {
  if (ts.isIdentifier(expression)) {
    return AUTH_CALL_NAMES.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression)) {
    return false;
  }

  if (AUTH_CALL_NAMES.has(expression.name.text)) {
    return true;
  }

  return (
    expression.name.text === "verify" &&
    ts.isIdentifier(expression.expression) &&
    /^(auth|jwt|session|token)$/i.test(expression.expression.text)
  );
}

function isAuthGuardProperty(node: ts.PropertyAccessExpression): boolean {
  return (
    AUTH_GUARD_PROPERTY_NAMES.has(node.name.text) &&
    ts.isIdentifier(node.expression) &&
    AUTH_GUARD_TARGET_NAMES.has(node.expression.text)
  );
}

function hasAuthIntentInSource(sourceFile: ts.SourceFile): boolean {
  let found = false;

  visit(sourceFile, (node) => {
    if (found) {
      return;
    }

    if (ts.isCallExpression(node) && isAuthIntentCall(node.expression)) {
      found = true;
      return;
    }

    if (ts.isPropertyAccessExpression(node) && isAuthGuardProperty(node)) {
      found = true;
    }
  });

  return found;
}

function isValidationLibraryImport(node: ts.ImportDeclaration): boolean {
  return ts.isStringLiteralLike(node.moduleSpecifier) && VALIDATION_MODULE_PATTERN.test(node.moduleSpecifier.text);
}

function isValidationCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  if (ts.isIdentifier(expression)) {
    return VALIDATION_CALL_NAMES.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression)) {
    return false;
  }

  if (expression.name.text === "isArray" && isArrayTarget(expression.expression)) {
    return true;
  }

  if (!VALIDATION_CALL_NAMES.has(expression.name.text)) {
    return false;
  }

  return expression.name.text !== "parse" || !isBuiltInParserTarget(expression.expression);
}

function hasValidationIntentInSource(sourceFile: ts.SourceFile): boolean {
  let found = false;

  visit(sourceFile, (node) => {
    if (found) {
      return;
    }

    if (ts.isImportDeclaration(node) && isValidationLibraryImport(node)) {
      found = true;
      return;
    }

    if (ts.isCallExpression(node) && isValidationCall(node)) {
      found = true;
      return;
    }

    if (ts.isBinaryExpression(node) && isTypeofValidationCheck(node)) {
      found = true;
    }
  });

  return found;
}

function isArrayTarget(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && expression.text === "Array";
}

function isBuiltInParserTarget(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && /^(?:Date|JSON|Number|URL)$/i.test(expression.text);
}

function isTypeofValidationCheck(node: ts.BinaryExpression): boolean {
  if (!TYPEOF_COMPARISON_OPERATORS.has(node.operatorToken.kind) || !ts.isTypeOfExpression(node.left)) {
    return false;
  }

  return ts.isStringLiteralLike(node.right) && VALIDATION_TYPE_NAMES.has(node.right.text);
}

function isInterpolatedSqlTemplate(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isTemplateExpression(node) && SQL_KEYWORD_PATTERN.test(node.getText());
}

function dangerouslySetInnerHtmlSeverity(
  initializer: ts.JsxAttribute["initializer"],
  sanitizerIdentifiers: ReadonlySet<string>,
  safeHtmlIdentifiers: ReadonlySet<string>
): "LOW" | "MEDIUM" | undefined {
  if (!initializer || ts.isStringLiteral(initializer)) {
    return undefined;
  }

  if (!ts.isJsxExpression(initializer) || !initializer.expression) {
    return undefined;
  }

  const expression = initializer.expression;
  if (!ts.isObjectLiteralExpression(expression)) {
    return "LOW";
  }

  const htmlExpression = expression.properties
    .filter(ts.isPropertyAssignment)
    .find((property) => propertyNameText(property.name) === "__html")?.initializer;

  if (!htmlExpression || isStaticHtmlExpression(htmlExpression, safeHtmlIdentifiers) || isSanitizedHtmlExpression(htmlExpression, sanitizerIdentifiers)) {
    return undefined;
  }

  return "MEDIUM";
}

function collectSanitizerIdentifiers(sourceFile: ts.SourceFile): Set<string> {
  const sanitizerIdentifiers = new Set<string>();

  visit(sourceFile, (node) => {
    if (!ts.isImportDeclaration(node) || !ts.isStringLiteralLike(node.moduleSpecifier)) {
      return;
    }

    const moduleName = node.moduleSpecifier.text;
    const importClause = node.importClause;
    if (!importClause) {
      return;
    }

    if (importClause.name && SANITIZER_MODULE_PATTERN.test(moduleName)) {
      sanitizerIdentifiers.add(importClause.name.text);
    }

    const namedBindings = importClause.namedBindings;
    if (!namedBindings || !ts.isNamedImports(namedBindings)) {
      return;
    }

    for (const importSpecifier of namedBindings.elements) {
      const importedName = importSpecifier.propertyName?.text ?? importSpecifier.name.text;
      if (isSanitizerFunctionName(importedName)) {
        sanitizerIdentifiers.add(importSpecifier.name.text);
      }
    }
  });

  return sanitizerIdentifiers;
}

function collectSafeHtmlIdentifiers(sourceFile: ts.SourceFile, sanitizerIdentifiers: Set<string>): Set<string> {
  const safeHtmlIdentifiers = new Set<string>();

  visit(sourceFile, (node) => {
    if (!ts.isVariableStatement(node) || (node.declarationList.flags & ts.NodeFlags.Const) === 0) {
      return;
    }

    for (const declaration of node.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) {
        continue;
      }

      if (isStaticHtmlExpression(declaration.initializer, safeHtmlIdentifiers) || isSanitizedHtmlExpression(declaration.initializer, sanitizerIdentifiers)) {
        safeHtmlIdentifiers.add(declaration.name.text);
      }
    }
  });

  return safeHtmlIdentifiers;
}

function propertyNameText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }

  return undefined;
}

function isStaticHtmlExpression(expression: ts.Expression, safeHtmlIdentifiers: ReadonlySet<string>): boolean {
  return ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression) || (ts.isIdentifier(expression) && safeHtmlIdentifiers.has(expression.text));
}

function isSanitizedHtmlExpression(expression: ts.Expression, sanitizerIdentifiers: ReadonlySet<string>): boolean {
  if (!ts.isCallExpression(expression)) {
    return false;
  }

  if (ts.isIdentifier(expression.expression)) {
    return sanitizerIdentifiers.has(expression.expression.text) || isSanitizerFunctionName(expression.expression.text);
  }

  if (ts.isPropertyAccessExpression(expression.expression)) {
    return isSanitizerFunctionName(expression.expression.name.text);
  }

  return false;
}

function isSanitizerFunctionName(name: string): boolean {
  return /^(?:sanitize|sanitizeHtml|sanitizeMarkdown|sanitizeContent|toSafeHtml)$/i.test(name);
}

function hasPasswordHashingCall(sourceFile: ts.SourceFile): boolean {
  let hasHashingCall = false;

  visit(sourceFile, (node) => {
    if (hasHashingCall || !ts.isCallExpression(node)) {
      return;
    }

    hasHashingCall = isPasswordHashingCall(node);
  });

  return hasHashingCall;
}

function isPasswordHashingCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  if (ts.isIdentifier(expression)) {
    return /^scrypt(?:Sync)?$/i.test(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression)) {
    return false;
  }

  const methodName = expression.name.text;
  const targetName = expressionNameText(expression.expression);
  if (/^scrypt(?:Sync)?$/i.test(methodName) && targetName === "crypto") {
    return true;
  }

  return methodName === "hash" && (targetName === "bcrypt" || targetName === "argon2");
}

function isPasswordHandlingNode(node: ts.Node): boolean {
  if (ts.isVariableDeclaration(node)) {
    return isPasswordVariableDeclaration(node);
  }

  return (
    ts.isPropertyAccessExpression(node) &&
    node.name.text === "password" &&
    isRequestBodyExpression(node.expression) &&
    !isVariableDeclarationInitializer(node)
  );
}

function isPasswordVariableDeclaration(node: ts.VariableDeclaration): boolean {
  if (!node.initializer) {
    return false;
  }

  if (ts.isIdentifier(node.name) && node.name.text === "password") {
    return isPasswordSourceExpression(node.initializer);
  }

  if (!ts.isObjectBindingPattern(node.name)) {
    return false;
  }

  return node.name.elements.some((element) => bindingElementName(element) === "password") && isCredentialJsonExpression(node.initializer);
}

function isPasswordSourceExpression(expression: ts.Expression): boolean {
  return isPasswordPropertyAccess(expression) || isPasswordFormDataGetCall(expression);
}

function isPasswordPropertyAccess(expression: ts.Expression): boolean {
  return ts.isPropertyAccessExpression(expression) && expression.name.text === "password" && isCredentialContainerExpression(expression.expression);
}

function isPasswordFormDataGetCall(expression: ts.Expression): boolean {
  if (!ts.isCallExpression(expression) || !ts.isPropertyAccessExpression(expression.expression) || expression.expression.name.text !== "get") {
    return false;
  }

  const [fieldName] = expression.arguments;
  return fieldName !== undefined && ts.isStringLiteralLike(fieldName) && fieldName.text === "password";
}

function isVariableDeclarationInitializer(expression: ts.Expression): boolean {
  return ts.isVariableDeclaration(expression.parent) && expression.parent.initializer === expression;
}

function isCredentialContainerExpression(expression: ts.Expression): boolean {
  return isRequestBodyExpression(expression) || isCredentialLikeIdentifier(expression);
}

function isRequestBodyExpression(expression: ts.Expression): boolean {
  return (
    (ts.isIdentifier(expression) && /^(body|credentials|credential|data|payload|formData)$/i.test(expression.text)) ||
    (ts.isPropertyAccessExpression(expression) &&
      expression.name.text === "body" &&
      ts.isIdentifier(expression.expression) &&
      /^(req|request)$/i.test(expression.expression.text))
  );
}

function isCredentialJsonExpression(expression: ts.Expression): boolean {
  const unwrappedExpression = ts.isAwaitExpression(expression) ? expression.expression : expression;
  return (
    ts.isCallExpression(unwrappedExpression) &&
    ts.isPropertyAccessExpression(unwrappedExpression.expression) &&
    unwrappedExpression.expression.name.text === "json" &&
    ts.isIdentifier(unwrappedExpression.expression.expression) &&
    /^(request|req)$/i.test(unwrappedExpression.expression.expression.text)
  );
}

function isCredentialLikeIdentifier(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && /^(credentials?|user|account)$/i.test(expression.text);
}

function expressionNameText(expression: ts.Expression): string | undefined {
  return ts.isIdentifier(expression) ? expression.text : undefined;
}

function exportedRouteHandlerName(node: ts.Node): string | undefined {
  if (ts.isFunctionDeclaration(node) && hasDefaultExportModifier(node)) {
    return "DEFAULT";
  }

  if (ts.isFunctionDeclaration(node) && hasExportModifier(node) && node.name) {
    return node.name.text;
  }

  if (!ts.isVariableStatement(node) || !hasExportModifier(node)) {
    return undefined;
  }

  const [declaration] = node.declarationList.declarations;
  return declaration && ts.isIdentifier(declaration.name) ? declaration.name.text : undefined;
}

function hasExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
}

function hasDefaultExportModifier(node: ts.Node): boolean {
  const modifiers = ts.canHaveModifiers(node) ? (ts.getModifiers(node) ?? []) : [];
  return (
    modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) &&
    modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword)
  );
}

function isApiRouteFilePath(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  return (
    /^app\/api\/.*\/route\.[tj]s$/i.test(normalizedPath) ||
    /^src\/app\/api\/.*\/route\.[tj]s$/i.test(normalizedPath) ||
    /^pages\/api\/.*\.([tj]s)$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/app\/api\/.*\/route\.[tj]s$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/src\/app\/api\/.*\/route\.[tj]s$/i.test(normalizedPath) ||
    /^apps\/[^/]+\/pages\/api\/.*\.([tj]s)$/i.test(normalizedPath)
  );
}

function isUploadHandlingNode(node: ts.Node): boolean {
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const methodName = node.expression.name.text;
    if (methodName === "formData") {
      return true;
    }

    if (methodName === "get") {
      const [fieldName] = node.arguments;
      return fieldName !== undefined && ts.isStringLiteralLike(fieldName) && /^(file|files|blob|image|avatar|media)$/i.test(fieldName.text);
    }
  }

  if (ts.isIdentifier(node)) {
    return /^(file|files|blob|formData)$/i.test(node.text);
  }

  if (ts.isTypeReferenceNode(node) && ts.isIdentifier(node.typeName)) {
    return /^(File|Blob|FormData)$/i.test(node.typeName.text);
  }

  return false;
}

function isRequireChildProcessCall(node: ts.Node): boolean {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "require") {
    return false;
  }

  const [specifier] = node.arguments;
  return isChildProcessSpecifier(specifier);
}

function isChildProcessSpecifier(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isStringLiteralLike(node) && /^(?:node:)?child_process$/.test(node.text);
}

function bindingElementName(element: ts.BindingElement): string | undefined {
  if (element.propertyName) {
    return ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName) ? element.propertyName.text : undefined;
  }

  return ts.isIdentifier(element.name) ? element.name.text : undefined;
}

function bindingElementLocalName(element: ts.BindingElement): string | undefined {
  return ts.isIdentifier(element.name) ? element.name.text : undefined;
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
