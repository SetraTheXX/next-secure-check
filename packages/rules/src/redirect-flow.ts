import ts from "typescript";
import { COMMAND_ALIAS_LIMIT } from "./command-ast.js";

const REQUEST_ROOT_NAMES = new Set([
  "body",
  "cookies",
  "context",
  "ctx",
  "formData",
  "headers",
  "params",
  "query",
  "req",
  "request",
  "routeParams",
  "searchParams"
]);
const REQUEST_MEMBER_NAMES = new Set(["body", "cookies", "formData", "headers", "nextUrl", "params", "query", "url"]);
const DIRECT_INPUT_NAME_PATTERN = /^(?:callbackUrl|continue|continueUrl|destination|href|next|path|redirect|redirectUrl|returnPath|returnTo|returnUrl|target|uri|url)$/i;
const SAFE_REDIRECT_STRING_METHODS = new Set(["startsWith", "endsWith", "includes"]);
const EQUALITY_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken
]);

type RedirectFunctionLike =
  | ts.ArrowFunction
  | ts.ConstructorDeclaration
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.GetAccessorDeclaration
  | ts.MethodDeclaration
  | ts.SetAccessorDeclaration;

export type RedirectDestinationKind = "internal-relative" | "external-absolute" | "dynamic";

type RedirectFlowValue = {
  path: string;
  key: string;
  aliasDepth: number;
  destinationKind: RedirectDestinationKind;
};

type RedirectBindings = {
  redirectNames: ReadonlySet<string>;
  permanentRedirectNames: ReadonlySet<string>;
  nextResponseNames: ReadonlySet<string>;
  safeRedirectHelpers: ReadonlyMap<string, string>;
  staticAllowlistNames: ReadonlySet<string>;
};

type RedirectFlowState = {
  scopeRoot: ts.Node;
  parameterNames: ReadonlySet<string>;
  functionName?: string;
  bindings: RedirectBindings;
  declared: Set<string>;
  initialized: Set<string>;
  invalidated: Set<string>;
  tracked: Map<string, RedirectFlowValue>;
  guardedKeys: Set<string>;
  staticAllowlistNames: Set<string>;
};

type RedirectSink = {
  node: ts.Node;
  destination: ts.Expression;
  name: string;
};

export type RedirectFlowMatch = {
  node: ts.Node;
  evidencePath: string;
  destinationKind: RedirectDestinationKind;
  sinkName: string;
};

export function findUnvalidatedRedirectTargets(sourceFile: ts.SourceFile): RedirectFlowMatch[] {
  if (hasDirective(sourceFile.statements, "use client")) {
    return [];
  }

  const bindings = collectRedirectBindings(sourceFile);
  const matches: RedirectFlowMatch[] = [];

  for (const scope of collectRedirectScopes(sourceFile)) {
    const state = createRedirectFlowState(scope, bindings);
    const body = ts.isSourceFile(scope) ? scope : scope.body;
    if (!body) {
      continue;
    }

    analyzeRedirectScope(body, state, matches);
  }

  return dedupeRedirectMatches(matches);
}

function collectRedirectScopes(sourceFile: ts.SourceFile): Array<ts.SourceFile | RedirectFunctionLike> {
  const scopes: Array<ts.SourceFile | RedirectFunctionLike> = [sourceFile];
  visitAllRedirectNodes(sourceFile, (node) => {
    if (isRedirectFunctionLike(node)) {
      scopes.push(node);
    }
  });
  return scopes;
}

function collectRedirectScopeDeclarations(node: ts.Node, declared: Set<string>): void {
  ts.forEachChild(node, (child) => {
    if (isRedirectFunctionLike(child)) {
      if (ts.isFunctionDeclaration(child) && child.name) {
        declared.add(child.name.text);
      }
      return;
    }

    if (ts.isClassDeclaration(child) && child.name) {
      declared.add(child.name.text);
      return;
    }

    collectRedirectScopeDeclarations(child, declared);
  });
}

function createRedirectFlowState(
  scope: ts.SourceFile | RedirectFunctionLike,
  bindings: RedirectBindings
): RedirectFlowState {
  const parameterNames = ts.isSourceFile(scope)
    ? new Set<string>()
    : new Set(bindingIdentifiers(scope.parameters).map((identifier) => identifier.text));
  const declared = new Set(parameterNames);
  if (!ts.isSourceFile(scope) && scope.body) {
    collectRedirectScopeDeclarations(scope.body, declared);
  }
  return {
    scopeRoot: scope,
    parameterNames,
    functionName: ts.isSourceFile(scope) ? undefined : functionName(scope),
    bindings,
    declared,
    initialized: new Set(parameterNames),
    invalidated: new Set(),
    tracked: new Map(),
    guardedKeys: new Set(),
    staticAllowlistNames: new Set(bindings.staticAllowlistNames)
  };
}

function analyzeRedirectScope(node: ts.Node, state: RedirectFlowState, matches: RedirectFlowMatch[]): void {
  visitRedirectNodes(node, (child) => {
    if (ts.isVariableDeclaration(child)) {
      recordRedirectDeclaration(child, state);
    }

    if (ts.isBinaryExpression(child) && isAssignmentOperator(child.operatorToken.kind)) {
      recordRedirectAssignment(child, state);
    }

    if (
      (ts.isPrefixUnaryExpression(child) || ts.isPostfixUnaryExpression(child)) &&
      isRedirectMutationOperator(child.operator)
    ) {
      invalidateRedirectTarget(child.operand, state);
    }

    const guardCondition = guardConditionExpression(child);
    if (guardCondition) {
      collectRedirectGuards(guardCondition, state);
    }

    const sink = redirectSinkForNode(child, state);
    if (sink) {
      const value = sourceValueForExpression(sink.destination, state);
      if (value && !state.guardedKeys.has(value.key)) {
        matches.push({
          node: sink.node,
          evidencePath: value.path,
          destinationKind: value.destinationKind,
          sinkName: sink.name
        });
      }
    }

    if (ts.isCallExpression(child) && !sink && !isNonEscapingRedirectCall(child, state)) {
      invalidateRedirectReferences(child, state);
    }
  });
}

function redirectSinkForNode(node: ts.Node, state: RedirectFlowState): RedirectSink | undefined {
  if (ts.isCallExpression(node)) {
    if (ts.isIdentifier(node.expression)) {
      if (state.bindings.redirectNames.has(node.expression.text) && !state.declared.has(node.expression.text)) {
        return firstRedirectArgument(node, "redirect");
      }

      if (state.bindings.permanentRedirectNames.has(node.expression.text) && !state.declared.has(node.expression.text)) {
        return firstRedirectArgument(node, "permanentRedirect");
      }
    }

    if (ts.isPropertyAccessExpression(node.expression)) {
      const path = staticMemberPath(node.expression);
      const root = path?.[0];
      if (path?.at(-1) === "redirect" && root && state.bindings.nextResponseNames.has(root) && !state.declared.has(root)) {
        return firstRedirectArgument(node, "NextResponse.redirect");
      }
    }
  }

  if (
    ts.isPropertyAssignment(node) &&
    state.functionName === "getServerSideProps" &&
    propertyName(node.name) === "redirect" &&
    ts.isObjectLiteralExpression(node.initializer)
  ) {
    const destinationProperty = node.initializer.properties.find((property) =>
      (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) &&
      propertyName(property.name) === "destination"
    );
    const destination = destinationProperty && ts.isPropertyAssignment(destinationProperty)
      ? destinationProperty.initializer
      : destinationProperty && ts.isShorthandPropertyAssignment(destinationProperty)
        ? destinationProperty.name
        : undefined;

    if (destination) {
      return { node, destination, name: "getServerSideProps.redirect.destination" };
    }
  }

  return undefined;
}

function firstRedirectArgument(node: ts.CallExpression, name: string): RedirectSink | undefined {
  const destination = node.arguments[0];
  return destination ? { node, destination, name } : undefined;
}

function recordRedirectDeclaration(node: ts.VariableDeclaration, state: RedirectFlowState): void {
  if (!ts.isIdentifier(node.name)) {
    return;
  }

  const name = node.name.text;
  state.declared.add(name);
  if (!node.initializer) {
    state.tracked.delete(name);
    state.initialized.delete(name);
    state.staticAllowlistNames.delete(name);
    return;
  }

  state.initialized.add(name);
  if (isStaticRedirectContainer(node.initializer)) {
    state.staticAllowlistNames.add(name);
  } else {
    state.staticAllowlistNames.delete(name);
  }
  const value = redirectValueForAssignment(node.initializer, name, state);
  if (value && value.aliasDepth <= COMMAND_ALIAS_LIMIT) {
    state.tracked.set(name, value);
  } else {
    state.tracked.delete(name);
  }
}

function recordRedirectAssignment(node: ts.BinaryExpression, state: RedirectFlowState): void {
  const target = rootIdentifier(node.left);
  if (!target) {
    invalidateRedirectReferences(node.left, state);
    return;
  }

  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken || state.initialized.has(target.text)) {
    invalidateRedirectTarget(target, state);
    state.staticAllowlistNames.delete(target.text);
    return;
  }

  state.declared.add(target.text);
  state.initialized.add(target.text);
  if (isStaticRedirectContainer(node.right)) {
    state.staticAllowlistNames.add(target.text);
  } else {
    state.staticAllowlistNames.delete(target.text);
  }
  const value = redirectValueForAssignment(node.right, target.text, state);
  if (value && value.aliasDepth <= COMMAND_ALIAS_LIMIT) {
    state.tracked.set(target.text, value);
  } else {
    state.tracked.delete(target.text);
  }
}

function redirectValueForAssignment(
  expression: ts.Expression,
  targetName: string,
  state: RedirectFlowState
): RedirectFlowValue | undefined {
  const normalized = unwrapRedirectExpression(expression);
  if (ts.isIdentifier(normalized)) {
    const existing = sourceValueForExpression(normalized, state);
    return existing ? withAlias(existing, targetName) : undefined;
  }

  return sourceValueForExpression(normalized, state);
}

function sourceValueForExpression(expression: ts.Expression, state: RedirectFlowState): RedirectFlowValue | undefined {
  const normalized = unwrapRedirectExpression(expression);

  if (ts.isBinaryExpression(normalized)) {
    const value = sourceValueForExpression(normalized.left, state) ?? sourceValueForExpression(normalized.right, state);
    return value ? withDestinationKind(value, normalized) : undefined;
  }

  if (ts.isConditionalExpression(normalized)) {
    const value = sourceValueForExpression(normalized.whenTrue, state) ?? sourceValueForExpression(normalized.whenFalse, state);
    return value ? withDestinationKind(value, normalized) : undefined;
  }

  if (ts.isIdentifier(normalized)) {
    if (isDeclarationName(normalized) || isPropertyName(normalized) || state.invalidated.has(normalized.text)) {
      return undefined;
    }

    const tracked = state.tracked.get(normalized.text);
    if (tracked) {
      return tracked;
    }

    if (isKnownSourceRoot(normalized.text, state) || isDirectInputParameter(normalized.text, state)) {
      return directRedirectSource(normalized.text);
    }

    return undefined;
  }

  if (ts.isPropertyAccessExpression(normalized)) {
    const direct = directRedirectPropertySource(normalized, state);
    if (direct) {
      return direct;
    }

    const base = sourceValueForExpression(normalized.expression, state);
    return base ? withMember(base, normalized.name.text) : undefined;
  }

  if (ts.isElementAccessExpression(normalized)) {
    const member = normalized.argumentExpression && literalText(normalized.argumentExpression);
    if (!member) {
      return undefined;
    }

    const direct = directRedirectElementSource(normalized, member, state);
    if (direct) {
      return direct;
    }

    const base = sourceValueForExpression(normalized.expression, state);
    return base ? withMember(base, member) : undefined;
  }

  if (ts.isCallExpression(normalized)) {
    const direct = directRedirectCallSource(normalized, state);
    if (direct) {
      return direct;
    }
    return undefined;
  }

  if (ts.isNewExpression(normalized)) {
    const [destination] = normalized.arguments ?? [];
    if (!destination) {
      return undefined;
    }

    const value = sourceValueForExpression(destination, state);
    return value ? withDestinationKind(value, normalized) : undefined;
  }

  if (ts.isTemplateExpression(normalized)) {
    const value = normalized.templateSpans
      .map((span) => sourceValueForExpression(span.expression, state))
      .find((candidate): candidate is RedirectFlowValue => candidate !== undefined);
    return value ? withDestinationKind(value, normalized) : undefined;
  }

  return undefined;
}

function directRedirectSource(name: string): RedirectFlowValue {
  return {
    path: name,
    key: name,
    aliasDepth: 0,
    destinationKind: "dynamic"
  };
}

function directRedirectPropertySource(node: ts.PropertyAccessExpression, state: RedirectFlowState): RedirectFlowValue | undefined {
  const path = staticMemberPath(node);
  return path && isRecognizedSourcePath(path, state) ? directRedirectPathSource(path) : undefined;
}

function directRedirectElementSource(
  node: ts.ElementAccessExpression,
  member: string,
  state: RedirectFlowState
): RedirectFlowValue | undefined {
  const path = staticMemberPath(node);
  return path && isRecognizedSourcePath([...path.slice(0, -1), member], state) ? directRedirectPathSource(path) : undefined;
}

function directRedirectCallSource(node: ts.CallExpression, state: RedirectFlowState): RedirectFlowValue | undefined {
  if (!ts.isPropertyAccessExpression(node.expression)) {
    if (ts.isIdentifier(node.expression) && /^(?:cookies|headers)$/i.test(node.expression.text)) {
      return directRedirectSource(`${node.expression.text}()`);
    }
    return undefined;
  }

  const path = staticMemberPath(node.expression);
  if (path && isRecognizedRequestSourceCall(path, state)) {
    return directRedirectPathSource(path, true);
  }

  const receiver = node.expression.expression;
  if (ts.isCallExpression(receiver)) {
    const base = directRedirectCallSource(receiver, state);
    if (base && node.expression.name.text === "get") {
      return withMember(base, "get()", true);
    }
  }

  if (node.expression.name.text === "get") {
    const base = sourceValueForExpression(receiver, state);
    if (base && isRedirectGetSource(base)) {
      return withMember(base, "get()", true);
    }
  }

  return undefined;
}

function directRedirectPathSource(path: string[], call = false): RedirectFlowValue {
  const formatted = formatRedirectPath(path);
  const displayPath = call ? `${formatted}()` : formatted;
  return {
    path: displayPath,
    key: displayPath,
    aliasDepth: 0,
    destinationKind: "dynamic"
  };
}

function withAlias(value: RedirectFlowValue, aliasName: string): RedirectFlowValue {
  return {
    ...value,
    path: `${value.path} -> ${aliasName}`,
    aliasDepth: value.aliasDepth + 1
  };
}

function withMember(value: RedirectFlowValue, member: string, call = false): RedirectFlowValue {
  const suffix = call ? member : member;
  return {
    ...value,
    path: `${value.path} -> ${suffix}`,
    key: `${value.key} -> ${suffix}`
  };
}

function withDestinationKind(value: RedirectFlowValue, expression: ts.Expression): RedirectFlowValue {
  return { ...value, destinationKind: destinationKindForExpression(expression) };
}

function collectRedirectGuards(condition: ts.Expression, state: RedirectFlowState): void {
  const guardKeys = new Set<string>();

  visitRedirectNodes(condition, (node) => {
    if (ts.isBinaryExpression(node) && EQUALITY_OPERATORS.has(node.operatorToken.kind)) {
      const leftKeys = sourceKeysForExpression(node.left, state);
      const rightKeys = sourceKeysForExpression(node.right, state);
      if (leftKeys.size > 0 && isStaticRedirectValue(node.right)) {
        leftKeys.forEach((key) => guardKeys.add(key));
      }
      if (rightKeys.size > 0 && isStaticRedirectValue(node.left)) {
        rightKeys.forEach((key) => guardKeys.add(key));
      }

      if (isSameOriginComparison(node, state)) {
        sourceKeysForExpression(node.left, state).forEach((key) => guardKeys.add(key));
      }
    }

    if (ts.isCallExpression(node) && isAllowlistGuardCall(node, state)) {
      for (const argument of node.arguments) {
        sourceKeysForExpression(argument, state).forEach((key) => guardKeys.add(key));
      }
    }

    if (ts.isCallExpression(node) && isRecognizedSafeRedirectHelperCall(node, state)) {
      for (const argument of node.arguments) {
        sourceKeysForExpression(argument, state).forEach((key) => guardKeys.add(key));
      }
    }
  });

  const startsWithKeys = new Set<string>();
  const doubleSlashKeys = new Set<string>();
  visitRedirectNodes(condition, (node) => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) {
      return;
    }

    const method = node.expression.name.text;
    if (method !== "startsWith") {
      return;
    }

    const [argument] = node.arguments;
    if (!argument || !ts.isStringLiteralLike(argument)) {
      return;
    }

    const keys = sourceKeysForExpression(node.expression.expression, state);
    const target = argument.text === "/" ? startsWithKeys : argument.text === "//" ? doubleSlashKeys : undefined;
    keys.forEach((key) => target?.add(key));
  });

  startsWithKeys.forEach((key) => {
    if (doubleSlashKeys.has(key)) {
      guardKeys.add(key);
    }
  });

  guardKeys.forEach((key) => state.guardedKeys.add(key));
}

function isAllowlistGuardCall(node: ts.CallExpression, state: RedirectFlowState): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || !["has", "includes"].includes(node.expression.name.text)) {
    return false;
  }

  if (!node.arguments.some((argument) => sourceKeysForExpression(argument, state).size > 0)) {
    return false;
  }

  const receiver = node.expression.expression;
  if (ts.isArrayLiteralExpression(receiver)) {
    return receiver.elements.every((element) => !ts.isSpreadElement(element) && isStaticRedirectValue(element));
  }

  if (ts.isNewExpression(receiver) && ts.isIdentifier(receiver.expression) && receiver.expression.text === "Set") {
    return (receiver.arguments ?? []).every((argument) => isStaticRedirectCollection(argument));
  }

  const root = rootIdentifier(receiver);
  return root !== undefined && state.staticAllowlistNames.has(root.text);
}

function isNonEscapingRedirectCall(node: ts.CallExpression, state: RedirectFlowState): boolean {
  if (!ts.isPropertyAccessExpression(node.expression)) {
    return isRedirectSinkCall(node, state);
  }

  if (SAFE_REDIRECT_STRING_METHODS.has(node.expression.name.text)) {
    return true;
  }

  if (node.expression.name.text === "get") {
    const directSource = directRedirectCallSource(node, state);
    const base = sourceValueForExpression(node.expression.expression, state);
    return directSource !== undefined || (base !== undefined && isRedirectGetSource(base));
  }

  return isAllowlistGuardCall(node, state) ||
    isRecognizedSafeRedirectHelperCall(node, state) ||
    isRedirectSinkCall(node, state);
}

function isRecognizedSafeRedirectHelperCall(node: ts.CallExpression, state: RedirectFlowState): boolean {
  if (!ts.isIdentifier(node.expression) || node.arguments.length !== 1) {
    return false;
  }

  return state.bindings.safeRedirectHelpers.has(node.expression.text) && !state.declared.has(node.expression.text);
}

function isRedirectSinkCall(node: ts.CallExpression, state: RedirectFlowState): boolean {
  return redirectSinkForNode(node, state) !== undefined;
}

function invalidateRedirectTarget(node: ts.Node, state: RedirectFlowState): void {
  const target = rootIdentifier(node);
  if (target) {
    state.tracked.delete(target.text);
    state.invalidated.add(target.text);
  }
  invalidateRedirectReferences(node, state);
}

function invalidateRedirectReferences(node: ts.Node, state: RedirectFlowState): void {
  const names = new Set<string>();
  visitRedirectNodes(node, (child) => {
    if (!ts.isIdentifier(child) || !state.tracked.has(child.text) || isPropertyName(child)) {
      return;
    }
    names.add(child.text);
  });

  names.forEach((name) => {
    state.tracked.delete(name);
    state.invalidated.add(name);
  });
}

function sourceKeysForExpression(node: ts.Node, state: RedirectFlowState): Set<string> {
  const keys = new Set<string>();
  visitRedirectNodes(node, (child) => {
    const value = sourceValueForExpression(child as ts.Expression, state);
    if (value) {
      keys.add(value.key);
    }
  });
  return keys;
}

function isSameOriginComparison(node: ts.BinaryExpression, state: RedirectFlowState): boolean {
  const sides = [node.left, node.right];
  return sides.some((side, index) => {
    if (!isNewUrlOriginExpression(side)) {
      return false;
    }

    const other = sides[index === 0 ? 1 : 0];
    const path = staticMemberPath(other);
    return path?.at(-1) === "origin" && isKnownSourceRoot(path[0] ?? "", state);
  });
}

function isNewUrlOriginExpression(node: ts.Node): boolean {
  return ts.isPropertyAccessExpression(node) &&
    node.name.text === "origin" &&
    ts.isNewExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "URL";
}

function isRecognizedSourcePath(path: string[], state: RedirectFlowState): boolean {
  const root = path[0];
  if (!root || !isKnownSourceRoot(root, state) || path.length < 2) {
    return false;
  }

  if (/^(?:body|cookies|formData|headers|params|query|routeParams|searchParams)$/i.test(root)) {
    return true;
  }

  return REQUEST_MEMBER_NAMES.has(path[1] ?? "");
}

function isRecognizedRequestSourceCall(path: string[], state: RedirectFlowState): boolean {
  const root = path[0];
  const method = path.at(-1);
  if (!root || !method || !isKnownSourceRoot(root, state)) {
    return false;
  }

  if (method === "get") {
    return root === "formData" || root === "headers" || root === "cookies" || root === "searchParams" ||
      path.includes("formData") || path.includes("headers") || path.includes("cookies") || path.includes("searchParams");
  }

  return method === "json" || method === "formData";
}

function isRedirectGetSource(value: RedirectFlowValue): boolean {
  return /(?:\.formData\(\)|\.headers|\.cookies|searchParams)$/.test(value.path);
}

function isKnownSourceRoot(name: string, state: RedirectFlowState): boolean {
  return REQUEST_ROOT_NAMES.has(name) && (state.parameterNames.has(name) || !state.declared.has(name));
}

function isDirectInputParameter(name: string, state: RedirectFlowState): boolean {
  return state.parameterNames.has(name) && DIRECT_INPUT_NAME_PATTERN.test(name);
}

function destinationKindForExpression(expression: ts.Expression): RedirectDestinationKind {
  const normalized = unwrapRedirectExpression(expression);
  if (ts.isNewExpression(normalized) && ts.isIdentifier(normalized.expression) && normalized.expression.text === "URL") {
    const [destination] = normalized.arguments ?? [];
    return destination ? destinationKindForExpression(destination) : "dynamic";
  }

  const prefix = staticStringPrefix(normalized);
  if (prefix?.startsWith("/") && !prefix.startsWith("//")) {
    return "internal-relative";
  }

  if (prefix && /^https?:\/\//i.test(prefix)) {
    return "external-absolute";
  }

  return "dynamic";
}

function staticStringPrefix(expression: ts.Expression): string | undefined {
  const normalized = unwrapRedirectExpression(expression);
  if (ts.isStringLiteralLike(normalized)) {
    return normalized.text;
  }

  if (ts.isTemplateExpression(normalized)) {
    return normalized.head.text;
  }

  if (ts.isBinaryExpression(normalized) && normalized.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return staticStringPrefix(normalized.left);
  }

  return undefined;
}

function isStaticRedirectValue(node: ts.Node): boolean {
  return ts.isStringLiteralLike(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword;
}

function isStaticRedirectCollection(node: ts.Node): boolean {
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.every((element) => !ts.isSpreadElement(element) && isStaticRedirectValue(element));
  }

  return isStaticRedirectValue(node);
}

function guardConditionExpression(node: ts.Node): ts.Expression | undefined {
  if (ts.isIfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
    return node.expression;
  }
  if (ts.isForStatement(node)) {
    return node.condition ?? undefined;
  }
  return ts.isConditionalExpression(node) ? node.condition : undefined;
}

function hasDirective(statements: readonly ts.Statement[], directive: string): boolean {
  for (const statement of statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteralLike(statement.expression)) {
      return false;
    }
    if (statement.expression.text === directive) {
      return true;
    }
  }
  return false;
}

function collectRedirectBindings(sourceFile: ts.SourceFile): RedirectBindings {
  const redirectNames = new Set<string>();
  const permanentRedirectNames = new Set<string>();
  const nextResponseNames = new Set<string>();
  const staticAllowlistNames = collectStaticRedirectAllowlistNames(sourceFile);

  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause || !ts.isStringLiteralLike(statement.moduleSpecifier)) {
      continue;
    }

    const moduleName = statement.moduleSpecifier.text;
    const namedBindings = statement.importClause.namedBindings;
    if (!namedBindings || ts.isNamespaceImport(namedBindings)) {
      continue;
    }

    for (const element of namedBindings.elements) {
      const importedName = element.propertyName?.text ?? element.name.text;
      if (moduleName === "next/navigation" && importedName === "redirect") {
        redirectNames.add(element.name.text);
      }
      if (moduleName === "next/navigation" && importedName === "permanentRedirect") {
        permanentRedirectNames.add(element.name.text);
      }
      if (moduleName === "next/server" && importedName === "NextResponse") {
        nextResponseNames.add(element.name.text);
      }
    }
  }

  return {
    redirectNames,
    permanentRedirectNames,
    nextResponseNames,
    safeRedirectHelpers: collectSafeRedirectHelpers(sourceFile, staticAllowlistNames),
    staticAllowlistNames
  };
}

function collectStaticRedirectAllowlistNames(sourceFile: ts.SourceFile): ReadonlySet<string> {
  const names = new Set<string>();
  visitAllRedirectNodes(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) {
      return;
    }

    if (isStaticRedirectContainer(node.initializer)) {
      names.add(node.name.text);
    }
  });
  return names;
}

function isStaticRedirectContainer(node: ts.Expression): boolean {
  const normalized = unwrapRedirectExpression(node);
  if (ts.isArrayLiteralExpression(normalized)) {
    return normalized.elements.every((element) => !ts.isSpreadElement(element) && isStaticRedirectValue(element));
  }

  return ts.isNewExpression(normalized) &&
    ts.isIdentifier(normalized.expression) &&
    normalized.expression.text === "Set" &&
    (normalized.arguments ?? []).every((argument) => isStaticRedirectCollection(argument));
}

function collectSafeRedirectHelpers(sourceFile: ts.SourceFile, staticAllowlistNames: ReadonlySet<string>): ReadonlyMap<string, string> {
  const helpers = new Map<string, string>();

  for (const statement of sourceFile.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name) {
      const parameterName = safeRedirectHelperParameter(statement, staticAllowlistNames);
      if (parameterName) {
        helpers.set(statement.name.text, parameterName);
      }
      continue;
    }

    if (!ts.isVariableStatement(statement)) {
      continue;
    }

    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer || !isSafeRedirectFunction(declaration.initializer)) {
        continue;
      }

      const parameterName = safeRedirectHelperParameter(declaration.initializer, staticAllowlistNames);
      if (parameterName) {
        helpers.set(declaration.name.text, parameterName);
      }
    }
  }

  return helpers;
}

function safeRedirectHelperParameter(
  node: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression,
  staticAllowlistNames: ReadonlySet<string>
): string | undefined {
  if (node.parameters.length !== 1 || !ts.isIdentifier(node.parameters[0]?.name) || !isSafeRedirectFunction(node)) {
    return undefined;
  }

  const parameterName = node.parameters[0].name.text;
  const body = node.body;
  if (!body) {
    return undefined;
  }

  if (!ts.isBlock(body)) {
    return isRecognizedSafeRedirectHelperExpression(body, parameterName, staticAllowlistNames)
      ? parameterName
      : undefined;
  }

  if (body.statements.length !== 1) {
    return undefined;
  }

  const [statement] = body.statements;
  return ts.isReturnStatement(statement) && statement.expression &&
    isRecognizedSafeRedirectHelperExpression(statement.expression, parameterName, staticAllowlistNames)
    ? parameterName
    : undefined;
}

function isSafeRedirectFunction(node: ts.Node): node is ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression {
  return ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node);
}

function isRecognizedSafeRedirectHelperExpression(
  expression: ts.Expression,
  parameterName: string,
  staticAllowlistNames: ReadonlySet<string>
): boolean {
  const normalized = unwrapRedirectExpression(expression);
  if (ts.isBinaryExpression(normalized) && normalized.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
    return (isStartsWithCheck(normalized.left, parameterName, "/") &&
      isNegatedStartsWithCheck(normalized.right, parameterName, "//")) ||
      (isNegatedStartsWithCheck(normalized.left, parameterName, "//") &&
        isStartsWithCheck(normalized.right, parameterName, "/"));
  }

  if (!ts.isCallExpression(normalized) || !ts.isPropertyAccessExpression(normalized.expression)) {
    return false;
  }

  const method = normalized.expression.name.text;
  const [argument] = normalized.arguments;
  if (method !== "has" && method !== "includes") {
    return false;
  }

  if (!argument || !ts.isIdentifier(argument) || argument.text !== parameterName) {
    return false;
  }

  const receiver = normalized.expression.expression;
  if (ts.isArrayLiteralExpression(receiver)) {
    return receiver.elements.every((element) => !ts.isSpreadElement(element) && isStaticRedirectValue(element));
  }

  if (ts.isNewExpression(receiver) && ts.isIdentifier(receiver.expression) && receiver.expression.text === "Set") {
    return (receiver.arguments ?? []).every((element) => isStaticRedirectCollection(element));
  }

  return ts.isIdentifier(receiver) && staticAllowlistNames.has(receiver.text);
}

function isStartsWithCheck(expression: ts.Expression, parameterName: string, prefix: string): boolean {
  const normalized = unwrapRedirectExpression(expression);
  if (!ts.isCallExpression(normalized) || !ts.isPropertyAccessExpression(normalized.expression)) {
    return false;
  }

  const [argument] = normalized.arguments;
  return normalized.expression.name.text === "startsWith" &&
    ts.isIdentifier(normalized.expression.expression) &&
    normalized.expression.expression.text === parameterName &&
    !!argument && ts.isStringLiteralLike(argument) && argument.text === prefix;
}

function isNegatedStartsWithCheck(expression: ts.Expression, parameterName: string, prefix: string): boolean {
  const normalized = unwrapRedirectExpression(expression);
  return ts.isPrefixUnaryExpression(normalized) &&
    normalized.operator === ts.SyntaxKind.ExclamationToken &&
    isStartsWithCheck(normalized.operand, parameterName, prefix);
}

function bindingIdentifiers(parameters: readonly ts.ParameterDeclaration[]): ts.Identifier[] {
  return parameters.flatMap((parameter) => bindingIdentifiersFromName(parameter.name));
}

function bindingIdentifiersFromName(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) {
    return [name];
  }

  return name.elements.flatMap((element) => {
    if (ts.isBindingElement(element)) {
      return bindingIdentifiersFromName(element.name);
    }
    return ts.isIdentifier(element) ? [element] : [];
  });
}

function functionName(node: RedirectFunctionLike): string | undefined {
  if (ts.isFunctionDeclaration(node) && node.name) {
    return node.name.text;
  }

  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return undefined;
}

function rootIdentifier(expression: ts.Node): ts.Identifier | undefined {
  if (ts.isIdentifier(expression)) {
    return expression;
  }
  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    return rootIdentifier(expression.expression);
  }
  return undefined;
}

function propertyName(node: ts.PropertyName): string | undefined {
  return ts.isIdentifier(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ? node.text : undefined;
}

function staticMemberPath(expression: ts.Expression): string[] | undefined {
  if (ts.isIdentifier(expression)) {
    return [expression.text];
  }
  if (ts.isPropertyAccessExpression(expression)) {
    const parentPath = staticMemberPath(expression.expression);
    return parentPath ? [...parentPath, expression.name.text] : undefined;
  }
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression && ts.isStringLiteralLike(expression.argumentExpression)) {
    const parentPath = staticMemberPath(expression.expression);
    return parentPath ? [...parentPath, expression.argumentExpression.text] : undefined;
  }
  return undefined;
}

function formatRedirectPath(path: string[]): string {
  return /^(?:params|routeParams)$/i.test(path[0] ?? "") ? path.join(" -> ") : path.join(".");
}

function literalText(node: ts.Expression): string | undefined {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ? node.text : undefined;
}

function unwrapRedirectExpression(expression: ts.Expression): ts.Expression {
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

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function isRedirectMutationOperator(operator: ts.PrefixUnaryOperator | ts.PostfixUnaryOperator): boolean {
  return operator === ts.SyntaxKind.PlusPlusToken || operator === ts.SyntaxKind.MinusMinusToken;
}

function isDeclarationName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isParameter(parent) && parent.name === node) ||
    (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isBindingElement(parent) && parent.name === node) ||
    (ts.isFunctionDeclaration(parent) && parent.name === node)
  );
}

function isPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    (ts.isMethodDeclaration(parent) && parent.name === node) ||
    (ts.isPropertyDeclaration(parent) && parent.name === node)
  );
}

function isRedirectFunctionLike(node: ts.Node): node is RedirectFunctionLike {
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

function visitRedirectNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => {
    if (isRedirectFunctionLike(child)) {
      return;
    }
    visitRedirectNodes(child, callback);
  });
}

function visitAllRedirectNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitAllRedirectNodes(child, callback));
}

function dedupeRedirectMatches(matches: RedirectFlowMatch[]): RedirectFlowMatch[] {
  const seen = new Set<string>();
  return matches
    .filter((match) => {
      const key = `${match.node.pos}:${match.node.end}:${match.evidencePath}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .sort((left, right) => left.node.getStart() - right.node.getStart());
}
