import type { Severity, SourceFile } from "@next-secure-check/core";
import ts from "typescript";
import { SourceAnalysisCache, type AnalysisCacheStats } from "./analysis-cache.js";
import {
  COMMAND_EXECUTION_NAMES,
  bindingElementLocalName,
  bindingElementName,
  isChildProcessSpecifier
} from "./command-ast.js";
import { collectCommandSourcePaths, isAnalyzableCommandExecutionCall } from "./command-flow.js";
import { findRawSqlConcatNodes } from "./sql-ast.js";
import { createXssAnalysisFacts, findDangerouslySetInnerHtmlNodes } from "./xss-ast.js";

export type AstMatch = {
  line: number;
  column: number;
  evidence: string;
  sourceLine: string;
  evidencePath?: string;
};

export type DangerouslySetInnerHtmlMatch = AstMatch & {
  severity: Extract<Severity, "LOW" | "MEDIUM">;
};

const ROUTE_HANDLER_NAMES = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);
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

export type AnalysisFacts = {
  sourceFile: ts.SourceFile;
  commandIdentifiers: ReadonlySet<string>;
  childProcessNamespaces: ReadonlySet<string>;
  commandDeclarationNodes: readonly ts.Node[];
  commandSourcePaths: ReadonlyMap<ts.CallExpression, string>;
  routeHandlerNodes: readonly ts.Node[];
  sanitizerIdentifiers: ReadonlySet<string>;
  safeHtmlIdentifiers: ReadonlySet<string>;
  hasPasswordHashing: boolean;
  hasAuthIntent: boolean;
  hasValidationIntent: boolean;
  hasUploadHandling: boolean;
};

export type AnalysisFactsCacheStats = AnalysisCacheStats;

const analysisFactsCache = new SourceAnalysisCache<AnalysisFacts>();

export function getAnalysisFacts(file: SourceFile): AnalysisFacts {
  return analysisFactsCache.get(file, () => {
    const sourceFile = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKindForPath(file.path)
    );
    return createAnalysisFacts(sourceFile);
  });
}

export function getAnalysisFactsCacheStats(): AnalysisFactsCacheStats {
  return analysisFactsCache.stats();
}

export function resetAnalysisFactsCacheForTests(): void {
  analysisFactsCache.clear();
}

export function findCommandExecutionMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes, commandSourcePaths } = getAnalysisFacts(file);
  const matches = commandDeclarationNodes.map((node) => matchFromNode(file, sourceFile, node));

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node) || !isAnalyzableCommandExecutionCall(node, commandIdentifiers, childProcessNamespaces)) {
      return;
    }

    const match = matchFromNode(file, sourceFile, node);
    const evidencePath = commandSourcePaths.get(node);
    matches.push(evidencePath ? { ...match, evidencePath } : match);
  });

  return dedupeMatches(matches);
}

export function findRawSqlConcatMatches(file: SourceFile): AstMatch[] {
  const { sourceFile } = getAnalysisFacts(file);
  return dedupeMatches(findRawSqlConcatNodes(sourceFile).map((node) => matchFromNode(file, sourceFile, node)));
}

export function findDangerouslySetInnerHtmlMatches(file: SourceFile): DangerouslySetInnerHtmlMatch[] {
  const { sourceFile, sanitizerIdentifiers, safeHtmlIdentifiers } = getAnalysisFacts(file);
  return dedupeMatches(
    findDangerouslySetInnerHtmlNodes(sourceFile, sanitizerIdentifiers, safeHtmlIdentifiers).map(({ node, severity }) => ({
      ...matchFromNode(file, sourceFile, node),
      severity
    }))
  );
}

export function findPasswordHandlingMatches(file: SourceFile): AstMatch[] {
  const { sourceFile, hasPasswordHashing } = getAnalysisFacts(file);
  const matches: AstMatch[] = [];

  if (hasPasswordHashing) {
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
  const { sourceFile, routeHandlerNodes } = getAnalysisFacts(file);
  return dedupeMatches(routeHandlerNodes.map((node) => matchFromNode(file, sourceFile, node)));
}

export function hasAuthIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasAuthIntent;
}

export function hasValidationIntentSignal(file: SourceFile): boolean {
  return getAnalysisFacts(file).hasValidationIntent;
}

export function findUploadRouteHandlerMatches(file: SourceFile): AstMatch[] {
  if (!isApiRouteFilePath(file.path)) {
    return [];
  }

  const { sourceFile, routeHandlerNodes, hasUploadHandling } = getAnalysisFacts(file);
  const routeHandlerMatches = routeHandlerNodes
    .filter((node) => {
      const name = exportedRouteHandlerName(node);
      return name === "DEFAULT" || name === "POST" || name === "PUT" || name === "PATCH";
    })
    .map((node) => matchFromNode(file, sourceFile, node));

  return hasUploadHandling ? dedupeMatches(routeHandlerMatches) : [];
}

function createAnalysisFacts(sourceFile: ts.SourceFile): AnalysisFacts {
  const commandIdentifiers = new Set<string>();
  const childProcessNamespaces = new Set<string>();
  const commandDeclarationNodes: ts.Node[] = [];
  const routeHandlerNodes: ts.Node[] = [];
  let hasUploadHandling = false;

  visit(sourceFile, (node) => {
    collectChildProcessImports(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);
    collectChildProcessRequires(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);

    const routeName = exportedRouteHandlerName(node);
    if (routeName && (routeName === "DEFAULT" || ROUTE_HANDLER_NAMES.has(routeName))) {
      routeHandlerNodes.push(node);
    }

    if (!hasUploadHandling && isUploadHandlingNode(node)) {
      hasUploadHandling = true;
    }
  });

  const xssFacts = createXssAnalysisFacts(sourceFile);

  return {
    sourceFile,
    commandIdentifiers,
    childProcessNamespaces,
    commandDeclarationNodes,
    commandSourcePaths: collectCommandSourcePaths(sourceFile, commandIdentifiers, childProcessNamespaces),
    routeHandlerNodes,
    sanitizerIdentifiers: xssFacts.sanitizerIdentifiers,
    safeHtmlIdentifiers: xssFacts.safeHtmlIdentifiers,
    hasPasswordHashing: hasPasswordHashingCall(sourceFile),
    hasAuthIntent: hasAuthIntentInSource(sourceFile),
    hasValidationIntent: hasValidationIntentInSource(sourceFile),
    hasUploadHandling
  };
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
    if (importedName === "exec" || importedName === "execSync") {
      declarationNodes.push(importSpecifier);
    }
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
        if (importedName === "exec" || importedName === "execSync") {
          declarationNodes.push(element);
        }
      }
    }

    return;
  }

  if (ts.isPropertyAccessExpression(node.initializer) && isRequireChildProcessCall(node.initializer.expression)) {
    const importedName = node.initializer.name.text;
    if (ts.isIdentifier(node.name) && COMMAND_EXECUTION_NAMES.has(importedName)) {
      commandIdentifiers.add(node.name.text);
      if (importedName === "exec" || importedName === "execSync") {
        declarationNodes.push(node);
      }
    }
  }
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

function hasAuthIntentInSource(sourceFile: ts.SourceFile): boolean {
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

function hasValidationIntentInSource(sourceFile: ts.SourceFile): boolean {
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
