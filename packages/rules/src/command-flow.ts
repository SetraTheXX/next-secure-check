import ts from "typescript";
import {
  COMMAND_ALIAS_LIMIT,
  COMMAND_EXECUTION_NAMES,
  REQUEST_SOURCE_NAMES,
  ROUTE_PARAMS_NAMES,
  SEARCH_PARAMS_NAME,
  bindingElementLocalName,
  bindingElementName,
  commandExecutionName,
  isCommandAssignmentOperator,
  isCommandExecutionCall,
  isCommandMutationOperator
} from "./command-ast.js";
import {
  createBoundedFlowFactsBuilder,
  finalizeBoundedFlowFacts,
  type BoundedFlowFacts,
  type BoundedFlowFactsBuilder,
  type BoundedFlowInvalidationReason
} from "./analysis-facts.js";
import { hasCommandAllowlistGuard, isCommandAllowlistMembershipCall } from "./command-guards.js";

export type CommandFlowFacts = {
  sourcePaths: ReadonlyMap<ts.CallExpression, string>;
  safeCommandCalls: ReadonlySet<ts.CallExpression>;
  boundedFlow: BoundedFlowFacts;
};

export type BoundedFlowContext = {
  readonly scopeRoot: ts.Node;
  readonly findSourcePathInExpression: (node: ts.Node) => string | undefined;
  readonly findSourcePathInArguments: (node: ts.CallExpression) => string | undefined;
  readonly recordSink: (node: ts.CallExpression, kind?: string) => void;
  readonly recordEvidencePath: (node: ts.Node, path: string) => void;
};

export type BoundedFlowCallbacks = {
  readonly onVariableDeclaration?: (node: ts.VariableDeclaration, context: BoundedFlowContext) => void;
  readonly onAssignment?: (node: ts.BinaryExpression, context: BoundedFlowContext) => void;
  readonly onCall?: (node: ts.CallExpression, context: BoundedFlowContext) => void;
  readonly shouldSkipCallInvalidation?: (node: ts.CallExpression, context: BoundedFlowContext) => boolean;
  readonly onTaggedTemplate?: (node: ts.TaggedTemplateExpression, context: BoundedFlowContext) => void;
  readonly onInvalidation?: (
    identifier: string,
    reason: BoundedFlowInvalidationReason,
    context: BoundedFlowContext
  ) => void;
};

export function isAnalyzableCommandExecutionCall(
  node: ts.CallExpression,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>
): boolean {
  return isCommandExecutionCall(node.expression, commandIdentifiers, childProcessNamespaces) && !isSafeStaticSpawnCall(node);
}

export function collectCommandSourcePaths(
  sourceFile: ts.SourceFile,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>
): ReadonlyMap<ts.CallExpression, string> {
  return collectCommandFlowFacts(sourceFile, commandIdentifiers, childProcessNamespaces).sourcePaths;
}

export function collectCommandFlowFacts(
  sourceFile: ts.SourceFile,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>,
  callbacks: BoundedFlowCallbacks = {}
): CommandFlowFacts {
  const factsBuilder = createBoundedFlowFactsBuilder();
  collectFunctionBoundaryFacts(sourceFile, factsBuilder);
  analyzeCommandScope(sourceFile, sourceFile, commandIdentifiers, childProcessNamespaces, factsBuilder, callbacks);

  visitCommandNodes(sourceFile, (node) => {
    if (!isCommandFunctionLike(node)) {
      return;
    }

    const body = commandFunctionBody(node);
    if (body) {
      analyzeCommandScope(body, body, commandIdentifiers, childProcessNamespaces, factsBuilder, callbacks);
    }
  });

  const boundedFlow = finalizeBoundedFlowFacts(factsBuilder);
  const sourcePaths = new Map<ts.CallExpression, string>();
  for (const [node, path] of boundedFlow.evidencePaths) {
    if (ts.isCallExpression(node)) {
      sourcePaths.set(node, path);
    }
  }

  return {
    sourcePaths,
    safeCommandCalls: boundedFlow.guardedSinks,
    boundedFlow
  };
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
  factsBuilder: BoundedFlowFactsBuilder;
  scopeRoot: ts.Node;
  callbacks: BoundedFlowCallbacks;
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

function analyzeCommandScope(
  scopeRoot: ts.Node,
  node: ts.Node,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>,
  factsBuilder: BoundedFlowFactsBuilder,
  callbacks: BoundedFlowCallbacks,
  state: CommandFlowState = createCommandFlowState(factsBuilder, scopeRoot, callbacks)
): void {
  if (node !== scopeRoot && isCommandFunctionLike(node)) {
    return;
  }

  if (ts.isVariableDeclaration(node)) {
    recordCommandDeclaration(node, state);
    state.callbacks.onVariableDeclaration?.(node, createBoundedFlowContext(state));
  }

  if (ts.isBinaryExpression(node) && isCommandAssignmentOperator(node.operatorToken.kind)) {
    recordCommandAssignment(node, state);
    state.callbacks.onAssignment?.(node, createBoundedFlowContext(state));
  }

  if (ts.isPrefixUnaryExpression(node) && isCommandMutationOperator(node.operator)) {
    invalidateCommandTarget(node.operand, state, "mutation");
  }

  if (ts.isPostfixUnaryExpression(node) && isCommandMutationOperator(node.operator)) {
    invalidateCommandTarget(node.operand, state, "mutation");
  }

  if (ts.isTaggedTemplateExpression(node)) {
    state.callbacks.onTaggedTemplate?.(node, createBoundedFlowContext(state));
  }

  if (ts.isCallExpression(node)) {
    const context = createBoundedFlowContext(state);
    state.callbacks.onCall?.(node, context);
    const skipCallInvalidation = state.callbacks.shouldSkipCallInvalidation?.(node, context) ?? false;

    if (isAnalyzableCommandExecutionCall(node, commandIdentifiers, childProcessNamespaces)) {
      state.factsBuilder.sinkFacts.set(node, { node, scope: scopeRoot, kind: commandExecutionName(node.expression) });
      const sourcePath = findCommandSourcePathInArguments(node, state);
      if (sourcePath) {
        const guardIdentifier = guardedCommandIdentifier(node, state);
        if (guardIdentifier) {
          state.factsBuilder.guardedSinks.add(node);
          state.factsBuilder.guardFacts.set(node, {
            node,
            scope: scopeRoot,
            kind: "command-allowlist",
            identifier: guardIdentifier
          });
        } else {
          state.factsBuilder.evidencePaths.set(node, sourcePath);
        }
      } else {
        invalidateTaintedReferences(node, state, "call-escape");
      }
    } else {
      const sourcePath = sourcePathForExpression(node, state);
      if (!skipCallInvalidation && !isCommandAllowlistMembershipCall(node) && !sourcePath) {
        invalidateTaintedReferences(node, state, "call-escape");
      }
    }
  }

  ts.forEachChild(node, (child) =>
    analyzeCommandScope(scopeRoot, child, commandIdentifiers, childProcessNamespaces, factsBuilder, callbacks, state)
  );
}

function guardedCommandIdentifier(node: ts.CallExpression, state: CommandFlowState): string | undefined {
  const [commandArgument] = node.arguments;
  if (!commandArgument) {
    return undefined;
  }

  const normalized = unwrapCommandExpression(commandArgument);
  if (!ts.isIdentifier(normalized) || !sourcePathForExpression(normalized, state)) {
    return undefined;
  }

  return hasCommandAllowlistGuard(node, normalized.text) && !hasUntrustedSpawnArguments(node, state)
    ? normalized.text
    : undefined;
}

function hasUntrustedSpawnArguments(node: ts.CallExpression, state: CommandFlowState): boolean {
  const methodName = commandExecutionName(node.expression);
  if (methodName !== "spawn" && methodName !== "spawnSync") {
    return false;
  }

  return node.arguments.slice(1).some((argument) => Boolean(findCommandSourcePathInExpression(argument, state)));
}

function createCommandFlowState(
  factsBuilder: BoundedFlowFactsBuilder,
  scopeRoot: ts.Node,
  callbacks: BoundedFlowCallbacks
): CommandFlowState {
  return {
    factsBuilder,
    scopeRoot,
    callbacks,
    declared: new Set<string>(),
    initialized: new Set<string>(),
    invalidated: new Set<string>(),
    tracked: new Map<string, CommandFlowValue>()
  };
}

function createBoundedFlowContext(state: CommandFlowState): BoundedFlowContext {
  return {
    scopeRoot: state.scopeRoot,
    findSourcePathInExpression: (node) => findCommandSourcePathInExpression(node, state),
    findSourcePathInArguments: (node) => findCommandSourcePathInArguments(node, state),
    recordSink: (node, kind) => {
      state.factsBuilder.sinkFacts.set(node, { node, scope: state.scopeRoot, kind });
    },
    recordEvidencePath: (node, path) => {
      state.factsBuilder.evidencePaths.set(node, path);
    }
  };
}

function recordCommandDeclaration(node: ts.VariableDeclaration, state: CommandFlowState): void {
  if (ts.isIdentifier(node.name)) {
    state.declared.add(node.name.text);
    if (!node.initializer) {
      return;
    }

    state.initialized.add(node.name.text);
    const value = sourcePathForAssignment(node.initializer, state, node.name.text);
    recordIdentifierAlias(node, node.name.text, node.initializer, value, state);
    trackCommandValue(node.name.text, value, state);
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
    invalidateTaintedReferences(node.left, state, "reassignment");
    return;
  }

  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) {
    invalidateCommandTarget(node.left, state, "mutation");
    return;
  }

  if (state.invalidated.has(target) || state.initialized.has(target)) {
    invalidateCommandTarget(node.left, state, "reassignment");
    return;
  }

  state.declared.add(target);
  state.initialized.add(target);
  const value = sourcePathForAssignment(node.right, state, target);
  recordIdentifierAlias(node, target, node.right, value, state);
  trackCommandValue(target, value, state);
}

function recordIdentifierAlias(
  node: ts.VariableDeclaration | ts.BinaryExpression,
  target: string,
  expression: ts.Expression,
  value: CommandFlowValue | undefined,
  state: CommandFlowState
): void {
  const normalized = unwrapCommandExpression(expression);
  if (!value || value.aliasDepth > COMMAND_ALIAS_LIMIT || !ts.isIdentifier(normalized) || normalized.text === target) {
    return;
  }

  state.factsBuilder.aliasFacts.push({
    node,
    scope: state.scopeRoot,
    from: normalized.text,
    to: target,
    depth: value.aliasDepth,
    path: value.path
  });
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
      return recordDirectSource(normalized, { path: normalized.text, aliasDepth: 0 }, state);
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

    const tracked = state.tracked.get(normalized.text);
    if (tracked) {
      return tracked;
    }

    if (ROUTE_PARAMS_NAMES.test(normalized.text)) {
      return recordDirectSource(normalized, { path: normalized.text, aliasDepth: 0 }, state);
    }

    return undefined;
  }

  if (ts.isPropertyAccessExpression(normalized)) {
    const directSource = directCommandPropertySource(normalized);
    if (directSource) {
      return recordDirectSource(normalized, directSource, state);
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
      return recordDirectSource(normalized, directSource, state);
    }

    const base = sourcePathForReference(normalized.expression, state);
    return base ? commandProperty(base, propertyName) : undefined;
  }

  if (ts.isCallExpression(normalized) && ts.isPropertyAccessExpression(normalized.expression)) {
    const methodName = normalized.expression.name.text;
    const receiver = normalized.expression.expression;
    if ((methodName === "json" || methodName === "formData") && isRequestSourceReceiver(receiver)) {
      return recordDirectSource(
        normalized,
        { path: `${commandExpressionLabel(receiver)}.${methodName}()`, aliasDepth: 0 },
        state
      );
    }

    if (methodName === "get") {
      if (isSearchParamsReceiver(receiver)) {
        return recordDirectSource(
          normalized,
          { path: `${commandExpressionLabel(receiver)}.get()`, aliasDepth: 0 },
          state
        );
      }

      const base = sourcePathForReference(receiver, state);
      return base ? commandProperty(base, "get()") : undefined;
    }
  }

  return undefined;
}

function recordDirectSource(node: ts.Node, value: CommandFlowValue, state: CommandFlowState): CommandFlowValue {
  state.factsBuilder.sourceFacts.set(node, {
    node,
    path: value.path,
    scope: state.scopeRoot
  });
  return value;
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

function invalidateCommandTarget(
  node: ts.Node,
  state: CommandFlowState,
  reason: BoundedFlowInvalidationReason
): void {
  const target = commandTargetIdentifier(node);
  if (target) {
    recordInvalidation(node, target, reason, state);
    state.tracked.delete(target);
    state.invalidated.add(target);
  }

  invalidateTaintedReferences(node, state, reason);
}

function invalidateTaintedReferences(node: ts.Node, state: CommandFlowState, reason: BoundedFlowInvalidationReason): void {
  const identifiers = new Set<string>();
  visitCommandNodes(node, (child) => {
    if (!ts.isIdentifier(child) || !state.tracked.has(child.text)) {
      return;
    }

    if (ts.isPropertyAccessExpression(child.parent) && child.parent.name === child) {
      return;
    }

    identifiers.add(child.text);
  });

  for (const identifier of identifiers) {
    recordInvalidation(node, identifier, reason, state);
    state.tracked.delete(identifier);
    state.invalidated.add(identifier);
  }
}

function recordInvalidation(
  node: ts.Node,
  identifier: string,
  reason: BoundedFlowInvalidationReason,
  state: CommandFlowState
): void {
  state.factsBuilder.invalidationFacts.push({ node, scope: state.scopeRoot, identifier, reason });
  state.callbacks.onInvalidation?.(identifier, reason, createBoundedFlowContext(state));
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

function collectFunctionBoundaryFacts(sourceFile: ts.SourceFile, factsBuilder: BoundedFlowFactsBuilder): void {
  visitCommandNodes(sourceFile, (node) => {
    if (isCommandFunctionLike(node)) {
      factsBuilder.functionBoundaryFacts.push({ node });
    }
  });
}

function commandFunctionBody(node: CommandFunctionLike): ts.Node | undefined {
  return node.body;
}

function visitCommandNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitCommandNodes(child, callback));
}
