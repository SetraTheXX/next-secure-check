import ts from "typescript";
import { hasAuthIntentInFunction, hasValidationIntentInFunction } from "./route-ast.js";

const REQUEST_LIKE_NAME_PATTERN = /^(?:body|cookies|formData|headers|params|query|req|request|routeParams|searchParams)$/i;
const NORMALIZER_NAMES = new Set(["normalize", "normalizeInput", "normalizePath", "sanitize", "sanitizeInput"]);
const ALLOWLIST_NAME_PATTERN = /^(?:accept|allowed?|allowlist|permitted|supported|trusted|valid|whitelist)/i;
const EQUALITY_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken
]);

type SupportedFunction = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;

export type ServerActionBoundary = {
  node: SupportedFunction;
  name: string;
  inputPath: string;
  hasAuthIntent: boolean;
  hasValidationIntent: boolean;
};

type InputReference = {
  node: ts.Node;
  path: string;
};

export function findServerActionBoundaries(sourceFile: ts.SourceFile): ServerActionBoundary[] {
  const fileLevelServerAction = hasUseServerDirective(sourceFile.statements);
  const boundaries: ServerActionBoundary[] = [];
  const seenFunctions = new Set<SupportedFunction>();
  const candidates: Array<{ node: SupportedFunction; name: string }> = [];

  for (const statement of sourceFile.statements) {
    for (const candidate of exportedFunctions(statement)) {
      if (fileLevelServerAction || hasInlineUseServerDirective(candidate.node)) {
        candidates.push(candidate);
        seenFunctions.add(candidate.node);
      }
    }
  }

  visitAllNodes(sourceFile, (node) => {
    if (!isSupportedFunction(node) || !hasInlineUseServerDirective(node) || seenFunctions.has(node)) {
      return;
    }

    candidates.push({ node, name: functionName(node) });
    seenFunctions.add(node);
  });

  for (const candidate of candidates) {
    const input = findActionInput(candidate.node);
    if (!input) {
      continue;
    }

      const trackedInputNames = collectTrackedInputNames(
        candidate.node,
        new Set([...input.parameterNames, inputRootFromPath(input.reference.path)])
      );
    boundaries.push({
      node: candidate.node,
      name: candidate.name,
      inputPath: input.reference.path,
      hasAuthIntent: hasAuthIntentInFunction(sourceFile, candidate.node),
      hasValidationIntent:
        hasValidationIntentInFunction(candidate.node) || hasActionInputGuard(candidate.node, trackedInputNames)
    });
  }

  return boundaries;
}

function exportedFunctions(statement: ts.Statement): Array<{ node: SupportedFunction; name: string }> {
  if (ts.isFunctionDeclaration(statement) && hasExportModifier(statement) && statement.body) {
    return [{ node: statement, name: statement.name?.text ?? "default" }];
  }

  if (!ts.isVariableStatement(statement) || !hasExportModifier(statement)) {
    return [];
  }

  return statement.declarationList.declarations.flatMap((declaration) => {
    if (!declaration.initializer || !isSupportedFunction(declaration.initializer)) {
      return [];
    }

    return [{
      node: declaration.initializer,
      name: ts.isIdentifier(declaration.name) ? declaration.name.text : "default"
    }];
  });
}

function isSupportedFunction(node: ts.Node): node is SupportedFunction {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node);
}

function hasUseServerDirective(statements: readonly ts.Statement[] | undefined): boolean {
  if (!statements) {
    return false;
  }

  for (const statement of statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteralLike(statement.expression)) {
      return false;
    }

    if (statement.expression.text === "use server") {
      return true;
    }
  }

  return false;
}

function hasInlineUseServerDirective(node: SupportedFunction): boolean {
  return node.body !== undefined && ts.isBlock(node.body) && hasUseServerDirective(node.body.statements);
}

function functionName(node: SupportedFunction): string {
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

  return "inline";
}

function findActionInput(node: SupportedFunction): { reference: InputReference; parameterNames: Set<string> } | undefined {
  const parameterReferences = node.parameters.flatMap((parameter) => bindingIdentifiers(parameter.name));
  const parameterNames = new Set(parameterReferences.map((reference) => reference.text));
  const references: InputReference[] = [];

  if (node.body) {
    visitActionNodes(node.body, (child) => {
      const path = actionInputPath(child, parameterNames);
      if (path) {
        references.push({ node: child, path });
      }
    });
  }

  if (references.length > 0) {
    return { reference: references[0] as InputReference, parameterNames };
  }

  const [parameter] = parameterReferences;
  if (parameter) {
    return {
      reference: { node: parameter, path: parameter.text },
      parameterNames
    };
  }

  return undefined;
}

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) {
    return [name];
  }

  const identifiers: ts.Identifier[] = [];
  if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    for (const element of name.elements) {
      if (ts.isBindingElement(element)) {
        identifiers.push(...bindingIdentifiers(element.name));
      } else if (ts.isIdentifier(element)) {
        identifiers.push(element);
      }
    }
  }
  return identifiers;
}

function actionInputPath(node: ts.Node, parameterNames: Set<string>): string | undefined {
  if (ts.isCallExpression(node)) {
    const propertyPath = callPropertyPath(node, parameterNames);
    if (propertyPath) {
      return propertyPath;
    }

    if (ts.isIdentifier(node.expression) && /^(?:cookies|headers)$/i.test(node.expression.text)) {
      return `${node.expression.text}()`;
    }
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const memberPath = staticMemberPath(node);
    if (memberPath && isInputRoot(memberPath[0], parameterNames)) {
      return formatInputPath(memberPath);
    }

    if (ts.isPropertyAccessExpression(node) && ts.isCallExpression(node.expression)) {
      const factory = node.expression.expression;
      if (ts.isIdentifier(factory) && /^(?:cookies|headers)$/i.test(factory.text)) {
        return `${factory.text}().${node.name.text}`;
      }
    }
  }

  if (ts.isIdentifier(node) && isInputRoot(node.text, parameterNames) && !isDeclarationName(node) && !isPropertyName(node)) {
    return node.text;
  }

  return undefined;
}

function callPropertyPath(node: ts.CallExpression, parameterNames: Set<string>): string | undefined {
  if (!ts.isPropertyAccessExpression(node.expression)) {
    return undefined;
  }

  const memberPath = staticMemberPath(node.expression);
  if (memberPath && isInputRoot(memberPath[0], parameterNames)) {
    return `${formatInputPath(memberPath)}()`;
  }

  const receiver = node.expression.expression;
  if (ts.isCallExpression(receiver) && ts.isIdentifier(receiver.expression) && /^(?:cookies|headers)$/i.test(receiver.expression.text)) {
    return `${receiver.expression.text}().${node.expression.name.text}()`;
  }

  return undefined;
}

function isInputRoot(root: string | undefined, parameterNames: Set<string>): boolean {
  return root !== undefined && (parameterNames.has(root) || REQUEST_LIKE_NAME_PATTERN.test(root));
}

function inputRootFromPath(path: string): string {
  return /^[A-Za-z_$][\w$]*/.exec(path)?.[0] ?? "";
}

function formatInputPath(memberPath: string[]): string {
  if (/^(?:params|routeParams)$/i.test(memberPath[0] ?? "")) {
    return memberPath.join(" -> ");
  }

  return memberPath.join(".");
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

function collectTrackedInputNames(node: SupportedFunction, parameterNames: Set<string>): Set<string> {
  const mutatedNames = collectMutatedNames(node);
  const trackedNames = new Set([...parameterNames].filter((name) => !mutatedNames.has(name)));
  let availableNames = new Set(trackedNames);

  for (let depth = 1; depth <= 2; depth += 1) {
    const additions = new Set<string>();
    if (!node.body) {
      break;
    }

    visitActionNodes(node.body, (child) => {
      if (!ts.isVariableDeclaration(child) || !ts.isIdentifier(child.name) || !child.initializer || mutatedNames.has(child.name.text)) {
        return;
      }

      if (containsTrackedInput(child.initializer, availableNames)) {
        additions.add(child.name.text);
      }
    });

    for (const name of additions) {
      trackedNames.add(name);
    }
    availableNames = new Set(trackedNames);
  }

  return trackedNames;
}

function collectMutatedNames(node: SupportedFunction): Set<string> {
  const mutatedNames = new Set<string>();
  if (!node.body) {
    return mutatedNames;
  }

  visitActionNodes(node.body, (child) => {
    if (ts.isBinaryExpression(child) && isAssignmentOperator(child.operatorToken.kind)) {
      const root = rootIdentifier(child.left);
      if (root) {
        mutatedNames.add(root.text);
      }
      return;
    }

    if (ts.isPrefixUnaryExpression(child) || ts.isPostfixUnaryExpression(child)) {
      const operand = child.operand;
      if (ts.isIdentifier(operand)) {
        mutatedNames.add(operand.text);
      }
    }
  });
  return mutatedNames;
}

function hasActionInputGuard(node: SupportedFunction, trackedInputNames: Set<string>): boolean {
  let found = false;
  if (!node.body) {
    return false;
  }

  visitActionNodes(node.body, (child) => {
    if (found) {
      return;
    }

    if (ts.isBinaryExpression(child) && isEqualityGuard(child, trackedInputNames)) {
      found = true;
      return;
    }

    if (ts.isCallExpression(child)) {
      if (isAllowlistGuard(child, trackedInputNames) || isNormalizerGuard(child, trackedInputNames)) {
        found = true;
      }
    }
  });

  return found;
}

function isEqualityGuard(node: ts.BinaryExpression, trackedInputNames: Set<string>): boolean {
  if (!EQUALITY_OPERATORS.has(node.operatorToken.kind) || !isWithinGuardCondition(node)) {
    return false;
  }

  return (
    (containsTrackedInput(node.left, trackedInputNames) && isStaticValue(node.right)) ||
    (containsTrackedInput(node.right, trackedInputNames) && isStaticValue(node.left))
  );
}

function isAllowlistGuard(node: ts.CallExpression, trackedInputNames: Set<string>): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || !["has", "includes"].includes(node.expression.name.text)) {
    return false;
  }

  if (!node.arguments.some((argument) => containsTrackedInput(argument, trackedInputNames))) {
    return false;
  }

  const receiver = node.expression.expression;
  if (ts.isArrayLiteralExpression(receiver)) {
    return true;
  }

  if (ts.isNewExpression(receiver) && ts.isIdentifier(receiver.expression) && receiver.expression.text === "Set") {
    return true;
  }

  const root = rootIdentifier(receiver);
  return root !== undefined && ALLOWLIST_NAME_PATTERN.test(root.text);
}

function isNormalizerGuard(node: ts.CallExpression, trackedInputNames: Set<string>): boolean {
  return (
    ts.isIdentifier(node.expression) &&
    NORMALIZER_NAMES.has(node.expression.text) &&
    node.arguments.some((argument) => containsTrackedInput(argument, trackedInputNames)) &&
    isWithinGuardCondition(node)
  );
}

function containsTrackedInput(node: ts.Node, trackedInputNames: Set<string>): boolean {
  let found = false;
  visitActionNodes(node, (child) => {
    if (found || !ts.isIdentifier(child) || !trackedInputNames.has(child.text) || isDeclarationName(child) || isPropertyName(child)) {
      return;
    }
    found = true;
  });
  return found;
}

function isWithinGuardCondition(node: ts.Node): boolean {
  let current = node;
  while (current.parent) {
    const parent = current.parent;
    if (
      (ts.isIfStatement(parent) && parent.expression === current) ||
      (ts.isWhileStatement(parent) && parent.expression === current) ||
      (ts.isDoStatement(parent) && parent.expression === current) ||
      (ts.isForStatement(parent) && parent.condition === current) ||
      (ts.isConditionalExpression(parent) && parent.condition === current)
    ) {
      return true;
    }
    current = parent;
  }
  return false;
}

function isStaticValue(node: ts.Node): boolean {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword;
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function rootIdentifier(expression: ts.Expression): ts.Identifier | undefined {
  if (ts.isIdentifier(expression)) {
    return expression;
  }

  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    return rootIdentifier(expression.expression);
  }

  return undefined;
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

function visitActionNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => {
    if (isNestedFunction(child)) {
      return;
    }
    visitActionNodes(child, callback);
  });
}

function visitAllNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitAllNodes(child, callback));
}

function isNestedFunction(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function hasExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
}
