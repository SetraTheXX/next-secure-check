import ts from "typescript";
import { REQUEST_SOURCE_NAMES, ROUTE_PARAMS_NAMES, SEARCH_PARAMS_NAME } from "./command-ast.js";

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
const REQUEST_BOUNDARY_MEMBER_NAMES = new Set(["body", "cookies", "formData", "headers", "json", "nextUrl", "params", "query", "url"]);
const REQUEST_BOUNDARY_NORMALIZER_NAMES = new Set(["normalize", "normalizeInput", "normalizePath", "sanitize", "sanitizeInput"]);
const ALLOWLIST_NAME_PATTERN = /^(?:accept|allowed?|allowlist|permitted|supported|trusted|valid|whitelist)/i;
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

export function hasAuthIntentInFunction(sourceFile: ts.SourceFile, root: ts.Node): boolean {
  const bindings = collectAuthIntentBindings(sourceFile);
  let found = false;

  visitFunctionNodes(root, (node) => {
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

  return found;
}

export function hasValidationIntentInSource(sourceFile: ts.SourceFile): boolean {
  if (sourceFile.statements.some((node) => ts.isImportDeclaration(node) && isValidationLibraryImport(node))) {
    return true;
  }

  return routeHandlerRoots(sourceFile).some(hasValidationIntentInRoot);
}

export function hasValidationIntentInFunction(root: ts.Node): boolean {
  let found = false;
  visitFunctionNodes(root, (node) => {
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

  return found;
}

export type RequestBoundarySource = {
  node: ts.Node;
  path: string;
};

export function findRequestBoundarySources(sourceFile: ts.SourceFile): RequestBoundarySource[] {
  const sources: RequestBoundarySource[] = [];

  for (const root of routeHandlerRoots(sourceFile)) {
    visitRouteNodes(root, (node) => {
      const sourcePath = requestBoundarySourcePath(node);
      if (sourcePath) {
        sources.push({ node, path: sourcePath });
      }
    });
  }

  const seen = new Set<string>();
  return sources.filter(({ node, path: sourcePath }) => {
    const key = `${node.pos}:${node.end}:${sourcePath}`;
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

export function hasRequestBoundaryGuardInSource(sourceFile: ts.SourceFile): boolean {
  if (sourceFile.statements.some((node) => ts.isImportDeclaration(node) && isValidationLibraryImport(node))) {
    return true;
  }

  return routeHandlerRoots(sourceFile).some((root) => hasValidationIntentInRoot(root) || hasRequestBoundaryAllowlistInRoot(root));
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

function hasValidationIntentInRoot(root: ts.Node): boolean {
  let found = false;
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

  return found;
}

function hasRequestBoundaryAllowlistInRoot(root: ts.Node): boolean {
  let found = false;
  visitRouteNodes(root, (node) => {
    if (found) {
      return;
    }

    if (ts.isBinaryExpression(node) && isRequestBoundaryAllowlistComparison(node)) {
      found = true;
      return;
    }

    if (!ts.isCallExpression(node)) {
      return;
    }

    if (isRequestBoundaryAllowlistCall(node) || isRequestBoundaryNormalizationGuard(node)) {
      found = true;
    }
  });

  return found;
}

function isRequestBoundaryAllowlistCall(node: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || !["has", "includes"].includes(node.expression.name.text)) {
    return false;
  }

  if (!node.arguments.some((argument) => containsRequestBoundarySource(argument))) {
    return false;
  }

  const receiver = node.expression.expression;
  if (ts.isArrayLiteralExpression(receiver)) {
    return true;
  }

  if (ts.isNewExpression(receiver) && ts.isIdentifier(receiver.expression) && receiver.expression.text === "Set") {
    return true;
  }

  const receiverRoot = rootIdentifier(receiver);
  return receiverRoot !== undefined && ALLOWLIST_NAME_PATTERN.test(receiverRoot.text);
}

function isRequestBoundaryNormalizationGuard(node: ts.CallExpression): boolean {
  if (!ts.isIdentifier(node.expression) || !REQUEST_BOUNDARY_NORMALIZER_NAMES.has(node.expression.text)) {
    return false;
  }

  return node.arguments.some((argument) => containsRequestBoundarySource(argument)) && isWithinGuardCondition(node);
}

function isRequestBoundaryAllowlistComparison(node: ts.BinaryExpression): boolean {
  if (
    ![
      ts.SyntaxKind.EqualsEqualsToken,
      ts.SyntaxKind.EqualsEqualsEqualsToken,
      ts.SyntaxKind.ExclamationEqualsToken,
      ts.SyntaxKind.ExclamationEqualsEqualsToken
    ].includes(node.operatorToken.kind) ||
    !isWithinGuardCondition(node)
  ) {
    return false;
  }

  return (
    (containsRequestBoundarySource(node.left) && isStaticBoundaryValue(node.right)) ||
    (containsRequestBoundarySource(node.right) && isStaticBoundaryValue(node.left))
  );
}

function isStaticBoundaryValue(node: ts.Node): boolean {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword;
}

function containsRequestBoundarySource(node: ts.Node): boolean {
  let found = false;
  visitRouteNodes(node, (child) => {
    if (!found && requestBoundarySourcePath(child)) {
      found = true;
    }
  });
  return found;
}

function requestBoundarySourcePath(node: ts.Node): string | undefined {
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    if (isCallExpressionSource(node.expression)) {
      const memberPath = staticMemberPath(node.expression);
      return memberPath ? `${formatRequestBoundaryPath(memberPath)}()` : undefined;
    }

    return undefined;
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    if (isNestedMemberNode(node) || (ts.isCallExpression(node.parent) && node.parent.expression === node)) {
      return undefined;
    }

    const memberPath = staticMemberPath(node);
    return memberPath && isRequestBoundaryMemberPath(memberPath) ? formatRequestBoundaryPath(memberPath) : undefined;
  }

  if (!ts.isIdentifier(node) || !isBareRequestBoundaryIdentifier(node) || isDeclarationName(node)) {
    return undefined;
  }

  return isNestedMemberNode(node) ? undefined : node.text;
}

function isCallExpressionSource(expression: ts.PropertyAccessExpression): boolean {
  const memberPath = staticMemberPath(expression);
  if (!memberPath) {
    return false;
  }

  const methodName = memberPath.at(-1);
  if (REQUEST_SOURCE_NAMES.test(memberPath[0] ?? "") && (methodName === "formData" || methodName === "json")) {
    return true;
  }

  if (SEARCH_PARAMS_NAME.test(memberPath[0] ?? "") && methodName === "get") {
    return true;
  }

  if (
    REQUEST_SOURCE_NAMES.test(memberPath[0] ?? "") &&
    methodName === "get" &&
    (memberPath.includes("headers") || memberPath.includes("cookies"))
  ) {
    return true;
  }

  return (
    REQUEST_SOURCE_NAMES.test(memberPath[0] ?? "") &&
    methodName === "get" &&
    memberPath.includes("nextUrl") &&
    memberPath.includes("searchParams")
  );
}

function isRequestBoundaryMemberPath(memberPath: string[]): boolean {
  const [root, ...members] = memberPath;
  if (!root || members.length === 0) {
    return false;
  }

  if (ROUTE_PARAMS_NAMES.test(root) || SEARCH_PARAMS_NAME.test(root)) {
    return true;
  }

  return REQUEST_SOURCE_NAMES.test(root) && members.some((member) => REQUEST_BOUNDARY_MEMBER_NAMES.has(member));
}

function isBareRequestBoundaryIdentifier(node: ts.Identifier): boolean {
  return ROUTE_PARAMS_NAMES.test(node.text) || SEARCH_PARAMS_NAME.test(node.text);
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

function formatRequestBoundaryPath(memberPath: string[] | string): string {
  const path = typeof memberPath === "string" ? [memberPath] : memberPath;
  if (ROUTE_PARAMS_NAMES.test(path[0] ?? "")) {
    return path.join(" -> ");
  }

  return path.join(".");
}

function isNestedMemberNode(node: ts.Node): boolean {
  const parent = node.parent;
  return (
    ((ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) && parent.expression === node) ||
    (ts.isCallExpression(parent) && parent.expression === node)
  );
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

function visitFunctionNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => {
    if (isFunctionLikeNode(child)) {
      return;
    }

    visitFunctionNodes(child, callback);
  });
}

function isFunctionLikeNode(node: ts.Node): boolean {
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
