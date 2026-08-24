import ts from "typescript";

export const ROUTE_HANDLER_NAMES = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);

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

export function hasAuthIntentInSource(sourceFile: ts.SourceFile): boolean {
  let found = false;

  visitRouteNodes(sourceFile, (node) => {
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

export function hasValidationIntentInSource(sourceFile: ts.SourceFile): boolean {
  let found = false;

  visitRouteNodes(sourceFile, (node) => {
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

export function exportedRouteHandlerName(node: ts.Node): string | undefined {
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

export function isApiRouteFilePath(filePath: string): boolean {
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

export function isUploadHandlingNode(node: ts.Node): boolean {
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

function visitRouteNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitRouteNodes(child, callback));
}
