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
  const sourcePaths = new Map<ts.CallExpression, string>();
  analyzeCommandScope(sourceFile, sourceFile, commandIdentifiers, childProcessNamespaces, sourcePaths);

  visitCommandNodes(sourceFile, (node) => {
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

function visitCommandNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitCommandNodes(child, callback));
}
