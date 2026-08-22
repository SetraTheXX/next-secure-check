import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";

export type AstMatch = {
  line: number;
  column: number;
  evidence: string;
  sourceLine: string;
};

export type DangerouslySetInnerHtmlMatch = AstMatch & {
  severity: Extract<Severity, "LOW" | "MEDIUM">;
};

const COMMAND_EXECUTION_NAMES = new Set(["exec", "execSync", "spawn", "spawnSync"]);
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

export function findCommandExecutionMatches(file: SourceFile): AstMatch[] {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  const commandIdentifiers = new Set<string>();
  const childProcessNamespaces = new Set<string>();
  const declarationNodes: ts.Node[] = [];

  visit(sourceFile, (node) => {
    collectChildProcessImports(node, commandIdentifiers, childProcessNamespaces, declarationNodes);
    collectChildProcessRequires(node, commandIdentifiers, childProcessNamespaces, declarationNodes);
  });

  const matches = declarationNodes.map((node) => matchFromNode(file, sourceFile, node));

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node) || !isCommandExecutionCall(node.expression, commandIdentifiers, childProcessNamespaces)) {
      return;
    }

    matches.push(matchFromNode(file, sourceFile, node));
  });

  return dedupeMatches(matches);
}

export function findRawSqlConcatMatches(file: SourceFile): AstMatch[] {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
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
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  const sanitizerIdentifiers = collectSanitizerIdentifiers(sourceFile);
  const safeHtmlIdentifiers = collectSafeHtmlIdentifiers(sourceFile, sanitizerIdentifiers);
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
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  const matches: AstMatch[] = [];

  if (hasPasswordHashingCall(sourceFile)) {
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
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  const matches: AstMatch[] = [];

  visit(sourceFile, (node) => {
    const name = exportedRouteHandlerName(node);
    if (name && (name === "DEFAULT" || ROUTE_HANDLER_NAMES.has(name))) {
      matches.push(matchFromNode(file, sourceFile, node));
    }
  });

  return dedupeMatches(matches);
}

export function hasAuthIntentSignal(file: SourceFile): boolean {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
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

export function hasValidationIntentSignal(file: SourceFile): boolean {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
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

export function findUploadRouteHandlerMatches(file: SourceFile): AstMatch[] {
  if (!isApiRouteFilePath(file.path)) {
    return [];
  }

  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  const routeHandlerMatches: AstMatch[] = [];
  let hasUploadHandling = false;

  visit(sourceFile, (node) => {
    const name = exportedRouteHandlerName(node);
    if (name && (name === "DEFAULT" || name === "POST" || name === "PUT" || name === "PATCH")) {
      routeHandlerMatches.push(matchFromNode(file, sourceFile, node));
    }

    if (!hasUploadHandling && isUploadHandlingNode(node)) {
      hasUploadHandling = true;
    }
  });

  return hasUploadHandling ? dedupeMatches(routeHandlerMatches) : [];
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
    declarationNodes.push(importSpecifier);
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
        declarationNodes.push(element);
      }
    }

    return;
  }

  if (ts.isPropertyAccessExpression(node.initializer) && isRequireChildProcessCall(node.initializer.expression)) {
    const importedName = node.initializer.name.text;
    if (ts.isIdentifier(node.name) && COMMAND_EXECUTION_NAMES.has(importedName)) {
      commandIdentifiers.add(node.name.text);
      declarationNodes.push(node);
    }
  }
}

function isCommandExecutionCall(
  expression: ts.Expression,
  commandIdentifiers: Set<string>,
  childProcessNamespaces: Set<string>
): boolean {
  if (ts.isIdentifier(expression)) {
    return commandIdentifiers.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression) || !COMMAND_EXECUTION_NAMES.has(expression.name.text)) {
    return false;
  }

  return ts.isIdentifier(expression.expression) && childProcessNamespaces.has(expression.expression.text);
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

function isInterpolatedSqlTemplate(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isTemplateExpression(node) && SQL_KEYWORD_PATTERN.test(node.getText());
}

function dangerouslySetInnerHtmlSeverity(
  initializer: ts.JsxAttribute["initializer"],
  sanitizerIdentifiers: Set<string>,
  safeHtmlIdentifiers: Set<string>
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

function isStaticHtmlExpression(expression: ts.Expression, safeHtmlIdentifiers: Set<string>): boolean {
  return ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression) || (ts.isIdentifier(expression) && safeHtmlIdentifiers.has(expression.text));
}

function isSanitizedHtmlExpression(expression: ts.Expression, sanitizerIdentifiers: Set<string>): boolean {
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
