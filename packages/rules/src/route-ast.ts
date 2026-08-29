import ts from "typescript";

export const ROUTE_HANDLER_NAMES = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);

const ALWAYS_RECOGNIZED_AUTH_CALL_NAMES = new Set([
  "currentUser",
  "getServerSession",
  "isAdmin",
  "requireAuth",
  "verifyToken",
  "withAuth",
  "clerkMiddleware"
]);
const CONDITIONAL_AUTH_CALL_NAMES = new Set(["auth", "clerk", "getUser"]);
const KNOWN_AUTH_MODULE_PATTERN = /^(?:next-auth(?:\/|$)|@auth(?:\/|$)|@clerk\/nextjs(?:\/|$)|@supabase\/(?:ssr|auth-helpers-nextjs)(?:\/|$)|better-auth(?:\/|$))/i;
const AUTH_GUARD_PROPERTY_NAMES = new Set(["permission", "role"]);
const AUTH_GUARD_TARGET_NAMES = new Set(["account", "claims", "session", "user"]);
const VALIDATION_CALL_NAMES = new Set(["isValid", "parse", "safeParse", "validate", "validateSync"]);
const VALIDATION_MODULE_PATTERN = /^(?:arktype|joi|superstruct|valibot|yup|zod)(?:\/|$)/i;
const RATE_LIMIT_CALL_NAMES = new Set([
  "applyRateLimit",
  "checkRateLimit",
  "enforceRateLimit",
  "rateLimit",
  "rateLimited",
  "slowDown",
  "throttle",
  "withRateLimit"
]);
const RATE_LIMIT_METHOD_NAMES = new Set(["check", "consume", "limit", "rateLimit"]);
const RATE_LIMIT_RECEIVER_PATTERN = /^(?:limiter|rateLimit|rateLimiter|ratelimit|redis|throttle|upstash)$/i;
const RESPONSE_FACTORY_NAMES = new Set(["json", "redirect", "rewrite"]);
const RESPONSE_NAMES = new Set(["NextResponse", "Response"]);
const RESPONSE_OBJECT_NAMES = new Set(["reply", "res", "response"]);
const VALIDATION_TYPE_NAMES = new Set(["boolean", "function", "number", "object", "string"]);
const TYPEOF_COMPARISON_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken
]);

export function hasAuthIntentInSource(sourceFile: ts.SourceFile): boolean {
  const bindings = collectAuthIntentBindings(sourceFile);

  for (const root of routeHandlerRoots(sourceFile)) {
    let found = false;
    visitRouteNodes(root, (node) => {
      if (found) {
        return;
      }

      if (ts.isCallExpression(node) && isAuthIntentCall(node.expression, bindings)) {
        found = true;
        return;
      }

      if (ts.isPropertyAccessExpression(node) && isAuthGuardProperty(node)) {
        found = true;
      }
    });

    if (!found) {
      return false;
    }
  }

  return true;
}

export function hasValidationIntentInSource(sourceFile: ts.SourceFile): boolean {
  let found = false;

  if (sourceFile.statements.some((node) => ts.isImportDeclaration(node) && isValidationLibraryImport(node))) {
    return true;
  }

  for (const root of routeHandlerRoots(sourceFile)) {
    visitRouteNodes(root, (node) => {
      if (found) {
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

    if (found) {
      break;
    }
  }

  return found;
}

export function hasRateLimitIntentInSource(sourceFile: ts.SourceFile): boolean {
  for (const root of routeHandlerRoots(sourceFile)) {
    let found = false;
    visitRouteNodes(root, (node) => {
      if (found) {
        return;
      }

      if (ts.isCallExpression(node) && (isRateLimitCall(node.expression) || isRateLimitResponseCall(node))) {
        found = true;
        return;
      }

      if (ts.isNewExpression(node) && isRateLimitResponseConstructor(node)) {
        found = true;
        return;
      }

      if (ts.isBinaryExpression(node) && isRateLimitStatusAssignment(node)) {
        found = true;
      }
    });

    if (!found) {
      return false;
    }
  }

  return true;
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
    /^(?:(?:apps|packages)\/[^/]+\/)?(?:src\/)?app\/api(?:\/[^/]+)*\/route\.[tj]s$/i.test(normalizedPath) ||
    /^pages\/api\/.*\.([tj]s)$/i.test(normalizedPath) ||
    /^src\/pages\/api\/.*\.([tj]s)$/i.test(normalizedPath) ||
    /^(?:apps|packages)\/[^/]+\/pages\/api\/.*\.([tj]s)$/i.test(normalizedPath) ||
    /^(?:apps|packages)\/[^/]+\/src\/pages\/api\/.*\.([tj]s)$/i.test(normalizedPath)
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

function isAuthIntentCall(expression: ts.Expression, bindings: AuthIntentBindings): boolean {
  if (ts.isIdentifier(expression)) {
    return ALWAYS_RECOGNIZED_AUTH_CALL_NAMES.has(expression.text) || bindings.trusted.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression)) {
    return false;
  }

  if (ALWAYS_RECOGNIZED_AUTH_CALL_NAMES.has(expression.name.text) || bindings.trusted.has(expression.name.text)) {
    return true;
  }

  if (expression.name.text === "protect") {
    const receiver = rootIdentifier(expression.expression);
    if (receiver && bindings.trusted.has(receiver.text)) {
      return true;
    }
  }

  return (
    expression.name.text === "verify" &&
    ts.isIdentifier(expression.expression) &&
    /^(auth|jwt|session|token)$/i.test(expression.expression.text)
  );
}

function isAuthGuardProperty(node: ts.PropertyAccessExpression): boolean {
  const target = rootIdentifier(node.expression);
  return (
    AUTH_GUARD_PROPERTY_NAMES.has(node.name.text) &&
    target !== undefined &&
    AUTH_GUARD_TARGET_NAMES.has(target.text) &&
    isWithinGuardCondition(node)
  );
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

type AuthIntentBindings = {
  trusted: Set<string>;
};

function collectAuthIntentBindings(sourceFile: ts.SourceFile): AuthIntentBindings {
  const trusted = new Set<string>();

  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause) {
      continue;
    }

    const moduleName = ts.isStringLiteralLike(statement.moduleSpecifier) ? statement.moduleSpecifier.text : "";
    const knownModule = KNOWN_AUTH_MODULE_PATTERN.test(moduleName);
    const importClause = statement.importClause;

    if (importClause.name && CONDITIONAL_AUTH_CALL_NAMES.has(importClause.name.text)) {
      addAuthBinding(importClause.name.text, knownModule, trusted);
    }

    if (!importClause.namedBindings || ts.isNamespaceImport(importClause.namedBindings)) {
      continue;
    }

    for (const element of importClause.namedBindings.elements) {
      const importedName = element.propertyName?.text ?? element.name.text;
      if (!CONDITIONAL_AUTH_CALL_NAMES.has(importedName)) {
        continue;
      }

      addAuthBinding(element.name.text, knownModule, trusted);
    }
  }

  return { trusted };
}

function addAuthBinding(name: string, knownModule: boolean, trusted: Set<string>): void {
  if (knownModule) {
    trusted.add(name);
  }
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

function isRateLimitCall(expression: ts.Expression): boolean {
  if (ts.isIdentifier(expression)) {
    return RATE_LIMIT_CALL_NAMES.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression) || !RATE_LIMIT_METHOD_NAMES.has(expression.name.text)) {
    return false;
  }

  const receiver = rootIdentifier(expression.expression);
  return receiver !== undefined && RATE_LIMIT_RECEIVER_PATTERN.test(receiver.text);
}

function isRateLimitResponseCall(node: ts.CallExpression): boolean {
  const expression = node.expression;

  if (ts.isPropertyAccessExpression(expression)) {
    const receiver = rootIdentifier(expression.expression);
    if (receiver && RESPONSE_NAMES.has(receiver.text) && RESPONSE_FACTORY_NAMES.has(expression.name.text)) {
      return hasRateLimitStatusArgument(node.arguments[1]);
    }

    if (receiver && RESPONSE_OBJECT_NAMES.has(receiver.text) && expression.name.text === "status") {
      return isNumeric429(node.arguments[0]);
    }
  }

  return false;
}

function isRateLimitResponseConstructor(node: ts.NewExpression): boolean {
  return ts.isIdentifier(node.expression) && RESPONSE_NAMES.has(node.expression.text) && hasRateLimitStatusArgument(node.arguments?.[1]);
}

function isRateLimitStatusAssignment(node: ts.BinaryExpression): boolean {
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken || !ts.isPropertyAccessExpression(node.left)) {
    return false;
  }

  const receiver = rootIdentifier(node.left.expression);
  return (
    receiver !== undefined &&
    RESPONSE_OBJECT_NAMES.has(receiver.text) &&
    node.left.name.text === "statusCode" &&
    isNumeric429(node.right)
  );
}

function hasRateLimitStatusArgument(node: ts.Node | undefined): boolean {
  if (!node) {
    return false;
  }

  let found = false;
  visitRouteNodes(node, (child) => {
    if (found || !ts.isPropertyAssignment(child)) {
      return;
    }

    const propertyName = ts.isStringLiteralLike(child.name) ? child.name.text : child.name.getText();
    if (propertyName === "status") {
      found = isNumeric429(child.initializer);
    }
  });

  return found;
}

function isNumeric429(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isNumericLiteral(node) && Number(node.text) === 429;
}

function routeHandlerRoots(sourceFile: ts.SourceFile): ts.Node[] {
  const routeHandlers = sourceFile.statements.filter((statement) => {
    const name = exportedRouteHandlerName(statement);
    return name === "DEFAULT" || (name !== undefined && ROUTE_HANDLER_NAMES.has(name));
  });

  return routeHandlers.length > 0 ? routeHandlers : [sourceFile];
}

function rootIdentifier(expression: ts.Expression): ts.Identifier | undefined {
  if (ts.isIdentifier(expression)) {
    return expression;
  }

  if (ts.isPropertyAccessExpression(expression)) {
    return rootIdentifier(expression.expression);
  }

  if (ts.isElementAccessExpression(expression)) {
    return rootIdentifier(expression.expression);
  }

  return undefined;
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
