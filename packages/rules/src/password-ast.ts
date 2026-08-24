import ts from "typescript";
import { bindingElementName } from "./command-ast.js";

export function hasPasswordHashingCall(sourceFile: ts.SourceFile): boolean {
  let hasHashingCall = false;

  visitPasswordNodes(sourceFile, (node) => {
    if (hasHashingCall || !ts.isCallExpression(node)) {
      return;
    }

    hasHashingCall = isPasswordHashingCall(node);
  });

  return hasHashingCall;
}

export function findPasswordHandlingNodes(sourceFile: ts.SourceFile): ts.Node[] {
  const matches: ts.Node[] = [];

  visitPasswordNodes(sourceFile, (node) => {
    if (isPasswordHandlingNode(node)) {
      matches.push(node);
    }
  });

  return matches;
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

function visitPasswordNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitPasswordNodes(child, callback));
}
