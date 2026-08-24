import ts from "typescript";

const ALLOWLIST_METHODS = new Set(["includes", "has"]);

export function isCommandAllowlistMembershipCall(node: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || !ALLOWLIST_METHODS.has(node.expression.name.text)) {
    return false;
  }

  return node.arguments.length === 1 && ts.isIdentifier(node.arguments[0]);
}

export function hasCommandAllowlistGuard(node: ts.CallExpression, commandName: string): boolean {
  return hasSiblingEarlyExitGuard(node, commandName) || hasPositiveAllowlistBranch(node, commandName);
}

function hasSiblingEarlyExitGuard(node: ts.CallExpression, commandName: string): boolean {
  const statement = containingStatement(node);
  if (!statement || !ts.isBlock(statement.parent)) {
    return false;
  }

  const statementIndex = statement.parent.statements.indexOf(statement);
  if (statementIndex <= 0) {
    return false;
  }

  const previousStatement = statement.parent.statements[statementIndex - 1];
  return isRejectingAllowlistGuard(previousStatement, commandName);
}

function isRejectingAllowlistGuard(node: ts.Statement, commandName: string): boolean {
  if (!ts.isIfStatement(node) || node.elseStatement || !isNegatedAllowlistCheck(node.expression, commandName)) {
    return false;
  }

  return isExitStatement(node.thenStatement);
}

function hasPositiveAllowlistBranch(node: ts.CallExpression, commandName: string): boolean {
  let current: ts.Node = node;

  while (current.parent) {
    const parent = current.parent;
    if (ts.isIfStatement(parent) && parent.thenStatement === current && isAllowlistCheck(parent.expression, commandName)) {
      return true;
    }

    if (isFunctionBoundary(parent)) {
      return false;
    }

    current = parent;
  }

  return false;
}

function isNegatedAllowlistCheck(expression: ts.Expression, commandName: string): boolean {
  const normalized = unwrapParenthesized(expression);
  return ts.isPrefixUnaryExpression(normalized) && normalized.operator === ts.SyntaxKind.ExclamationToken && isAllowlistCheck(normalized.operand, commandName);
}

function isAllowlistCheck(expression: ts.Expression, commandName: string): boolean {
  const normalized = unwrapParenthesized(expression);
  if (!ts.isCallExpression(normalized) || !isCommandAllowlistMembershipCall(normalized)) {
    return false;
  }

  const [argument] = normalized.arguments;
  return ts.isIdentifier(argument) && argument.text === commandName;
}

function isExitStatement(node: ts.Statement): boolean {
  if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) {
    return true;
  }

  if (!ts.isBlock(node) || node.statements.length === 0) {
    return false;
  }

  const lastStatement = node.statements[node.statements.length - 1];
  return ts.isReturnStatement(lastStatement) || ts.isThrowStatement(lastStatement);
}

function containingStatement(node: ts.Node): ts.Statement | undefined {
  let current: ts.Node | undefined = node;
  while (current) {
    if (ts.isStatement(current)) {
      return current;
    }

    current = current.parent;
  }

  return undefined;
}

function unwrapParenthesized(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current)) {
    current = current.expression;
  }

  return current;
}

function isFunctionBoundary(node: ts.Node): boolean {
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
