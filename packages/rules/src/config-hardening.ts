import ts from "typescript";
import type { SourceFile } from "@next-secure-check/core";

const SESSION_COOKIE_NAME_PARTS = new Set([
  "access",
  "auth",
  "authentication",
  "jwt",
  "refresh",
  "session",
  "sid",
  "token"
]);
const COOKIE_CONTAINER_NAMES = new Set(["cookieStore", "cookies", "response", "res", "reply", "nextResponse"]);
const SESSION_COOKIE_FLAGS = ["httpOnly", "secure", "sameSite"] as const;
const EMPTY_COOKIE_STORE_NAMES = new Set<string>();
const SECURITY_HEADER_GROUPS = [
  "Content-Security-Policy",
  "frame protection",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy"
] as const;

export type SessionCookieFlag = (typeof SESSION_COOKIE_FLAGS)[number];

export type SessionCookieMatch = {
  line: number;
  column: number;
  presentFlags: readonly SessionCookieFlag[];
  missingFlags: readonly SessionCookieFlag[];
  dynamicFlags: readonly SessionCookieFlag[];
};

export type SecurityHeaderGroup = (typeof SECURITY_HEADER_GROUPS)[number];

export type SecurityHeaderAnalysis = {
  configured: ReadonlySet<SecurityHeaderGroup>;
  evidencePaths: readonly string[];
  hasDynamicConfiguration: boolean;
};

export type BroadImageDomainMatch = {
  line: number;
  column: number;
};

export function findSessionCookieMatches(file: SourceFile): SessionCookieMatch[] {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
  if (hasDirective(sourceFile.statements, "use client")) {
    return [];
  }

  const cookieStoresByScope = collectCookieStoreNames(sourceFile);
  const matches: SessionCookieMatch[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node)) {
      return;
    }

    const cookieCall = cookieWriteCall(
      node,
      cookieStoresByScope.get(cookieScopeRoot(node) ?? sourceFile) ?? EMPTY_COOKIE_STORE_NAMES
    );
    if (!cookieCall) {
      return;
    }

    const cookieName = cookieNameFromCall(cookieCall);
    if (!cookieName || !isAuthLikeCookieName(cookieName)) {
      return;
    }

    const flagStates = inspectCookieFlags(cookieCall);
    const presentFlags = SESSION_COOKIE_FLAGS.filter((flag) => flagStates[flag] === "present");
    const missingFlags = SESSION_COOKIE_FLAGS.filter((flag) => flagStates[flag] === "missing");
    const dynamicFlags = SESSION_COOKIE_FLAGS.filter((flag) => flagStates[flag] === "dynamic");
    if (missingFlags.length === 0 && dynamicFlags.length === 0) {
      return;
    }

    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    matches.push({
      line: position.line + 1,
      column: position.character + 1,
      presentFlags,
      missingFlags,
      dynamicFlags
    });
  });

  return matches.sort((left, right) => left.line - right.line || left.column - right.column);
}

export function analyzeSecurityHeaders(files: readonly SourceFile[]): SecurityHeaderAnalysis {
  const configured = new Set<SecurityHeaderGroup>();
  const evidencePaths = new Set<string>();
  let hasDynamicConfiguration = false;

  for (const file of files) {
    const normalizedPath = file.path.replace(/\\/g, "/");
    const sourceFile = parseSourceFile(file);

    if (/^(?:.*\/)?next\.config\.(?:cjs|js|mjs|ts)$/i.test(normalizedPath)) {
      for (const root of nextConfigHeaderFunctions(sourceFile)) {
        let foundHeaderProperty = false;
        visit(root, (node) => {
          if (!ts.isPropertyAssignment(node) || propertyName(node.name) !== "key") {
            return;
          }

          foundHeaderProperty = true;
          const headerName = ts.isStringLiteralLike(node.initializer) ? securityHeaderGroup(node.initializer.text) : undefined;
          if (!headerName) {
            hasDynamicConfiguration = true;
            return;
          }

          const valueProperty = headerValueProperty(node.parent);
          if (!valueProperty || !ts.isStringLiteralLike(valueProperty.initializer)) {
            hasDynamicConfiguration = true;
          }

          configured.add(headerName);
          if (headerName === "Content-Security-Policy" && hasFrameAncestorsEvidence(node)) {
            configured.add("frame protection");
          }
          evidencePaths.add(`${normalizedPath}: headers()`);
        });

        if (!foundHeaderProperty) {
          hasDynamicConfiguration = true;
        }
      }
    }

    if (/(?:^|\/)(?:middleware|proxy)\.[tj]s$/i.test(normalizedPath)) {
      for (const root of middlewareEntryFunctions(sourceFile, normalizedPath)) {
        visit(root, (node) => {
          if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression) || !["set", "append"].includes(node.expression.name.text)) {
            return;
          }

          const receiver = node.expression.expression;
          if (!ts.isPropertyAccessExpression(receiver) || receiver.name.text !== "headers") {
            return;
          }

          const [headerArgument] = node.arguments;
          if (!headerArgument || !ts.isStringLiteralLike(headerArgument)) {
            hasDynamicConfiguration = true;
            return;
          }

          const headerName = securityHeaderGroup(headerArgument.text);
          if (!headerName) {
            return;
          }

          const [, valueArgument] = node.arguments;
          if (!valueArgument || !ts.isStringLiteralLike(valueArgument)) {
            hasDynamicConfiguration = true;
          }

          configured.add(headerName);
          if (headerName === "Content-Security-Policy" && hasFrameAncestorsEvidence(node)) {
            configured.add("frame protection");
          }
          evidencePaths.add(`${normalizedPath}: headers.${node.expression.name.text}()`);
        });
      }
    }
  }

  return {
    configured,
    evidencePaths: [...evidencePaths].sort(),
    hasDynamicConfiguration
  };
}

export function findBroadImageDomainMatches(file: SourceFile): BroadImageDomainMatch[] {
  const normalizedPath = file.path.replace(/\\/g, "/");
  if (!/(?:^|\/)next\.config\.(?:cjs|js|mjs|ts)$/i.test(normalizedPath)) {
    return [];
  }

  const sourceFile = parseSourceFile(file);
  const matches: BroadImageDomainMatch[] = [];
  visit(sourceFile, (node) => {
    if (!ts.isPropertyAssignment(node) || propertyName(node.name) !== "domains" || !ts.isArrayLiteralExpression(node.initializer)) {
      return;
    }

    if (!isImagesConfigProperty(node)) {
      return;
    }

    const hasStaticDomain = node.initializer.elements.some((element) => ts.isStringLiteralLike(element));
    if (!hasStaticDomain) {
      return;
    }

    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    matches.push({ line: position.line + 1, column: position.character + 1 });
  });

  return matches.sort((left, right) => left.line - right.line || left.column - right.column);
}

function cookieWriteCall(node: ts.CallExpression, cookieStores: ReadonlySet<string>): ts.CallExpression | undefined {
  if (isCookieSetCall(node, cookieStores)) {
    return node;
  }

  if (!isPagesCookieHeaderCall(node)) {
    return undefined;
  }

  const [, headerValue] = node.arguments;
  return headerValue && ts.isCallExpression(headerValue) && isCookieSerializerCall(headerValue) ? headerValue : undefined;
}

function isCookieSetCall(node: ts.CallExpression, cookieStores: ReadonlySet<string>): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== "set") {
    return false;
  }

  const receiver = unwrapParentheses(node.expression.expression);
  if (ts.isCallExpression(receiver) && ts.isIdentifier(receiver.expression)) {
    return receiver.expression.text === "cookies";
  }

  if (
    ts.isAwaitExpression(receiver) &&
    ts.isCallExpression(receiver.expression) &&
    ts.isIdentifier(receiver.expression.expression)
  ) {
    return receiver.expression.expression.text === "cookies";
  }

  if (ts.isIdentifier(receiver)) {
    return cookieStores.has(receiver.text);
  }

  if (ts.isPropertyAccessExpression(receiver) && receiver.name.text === "cookies") {
    const root = rootIdentifier(receiver.expression);
    return root !== undefined && COOKIE_CONTAINER_NAMES.has(root.text);
  }

  return false;
}

function isPagesCookieHeaderCall(node: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== "setHeader") {
    return false;
  }

  const root = rootIdentifier(node.expression.expression);
  const [headerName] = node.arguments;
  return (
    root !== undefined &&
    COOKIE_CONTAINER_NAMES.has(root.text) &&
    ts.isStringLiteralLike(headerName) &&
    headerName.text.toLowerCase() === "set-cookie"
  );
}

function isCookieSerializerCall(node: ts.CallExpression): boolean {
  return ts.isIdentifier(node.expression) && ["serialize", "serializeCookie"].includes(node.expression.text);
}

function parseSourceFile(file: SourceFile): ts.SourceFile {
  return ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindForPath(file.path));
}

type ConfigFunctionLike = ts.ArrowFunction | ts.FunctionDeclaration | ts.FunctionExpression | ts.MethodDeclaration;

function nextConfigHeaderFunctions(sourceFile: ts.SourceFile): ConfigFunctionLike[] {
  const functions: ConfigFunctionLike[] = [];
  visit(sourceFile, (node) => {
    if (ts.isPropertyAssignment(node) && propertyName(node.name) === "headers" && isConfigFunctionLike(node.initializer)) {
      functions.push(node.initializer);
      return;
    }

    if (ts.isMethodDeclaration(node) && propertyName(node.name) === "headers") {
      functions.push(node);
    }
  });
  return functions;
}

function middlewareEntryFunctions(sourceFile: ts.SourceFile, filePath: string): ConfigFunctionLike[] {
  const entryName = filePath.split("/").at(-1)?.split(".")[0] ?? "middleware";
  const functions: ConfigFunctionLike[] = [];

  visit(sourceFile, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === entryName) {
      functions.push(node);
      return;
    }

    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || node.name.text !== entryName || !node.initializer || !isConfigFunctionLike(node.initializer)) {
      return;
    }

    functions.push(node.initializer);
  });

  return functions;
}

function isConfigFunctionLike(node: ts.Node): node is ConfigFunctionLike {
  return ts.isArrowFunction(node) || ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isMethodDeclaration(node);
}

function securityHeaderGroup(headerName: string): SecurityHeaderGroup | undefined {
  switch (headerName.toLowerCase()) {
    case "content-security-policy":
      return "Content-Security-Policy";
    case "x-frame-options":
      return "frame protection";
    case "x-content-type-options":
      return "X-Content-Type-Options";
    case "referrer-policy":
      return "Referrer-Policy";
    case "permissions-policy":
      return "Permissions-Policy";
    default:
      return undefined;
  }
}

function headerValueProperty(node: ts.Node): ts.PropertyAssignment | undefined {
  if (!ts.isObjectLiteralExpression(node)) {
    return undefined;
  }

  const value = node.properties.find((property) => ts.isPropertyAssignment(property) && propertyName(property.name) === "value");
  return value && ts.isPropertyAssignment(value) ? value : undefined;
}

function isImagesConfigProperty(node: ts.PropertyAssignment): boolean {
  const object = node.parent;
  return ts.isObjectLiteralExpression(object) && ts.isPropertyAssignment(object.parent) && propertyName(object.parent.name) === "images";
}

function hasFrameAncestorsEvidence(node: ts.Node): boolean {
  let value: ts.Expression | undefined;

  if (ts.isPropertyAssignment(node) && ts.isObjectLiteralExpression(node.parent)) {
    value = headerValueProperty(node.parent)?.initializer;
  } else if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    value = node.arguments[1];
  }

  return value !== undefined && ts.isStringLiteralLike(value) && /frame-ancestors/i.test(value.text);
}

function cookieNameFromCall(node: ts.CallExpression): string | undefined {
  const [firstArgument] = node.arguments;
  if (!firstArgument) {
    return undefined;
  }

  if (ts.isStringLiteralLike(firstArgument)) {
    return firstArgument.text;
  }

  if (!ts.isObjectLiteralExpression(firstArgument)) {
    return undefined;
  }

  const nameProperty = firstArgument.properties.find((property) => {
    if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) {
      return false;
    }

    return propertyName(property.name) === "name";
  });
  if (!nameProperty || !ts.isPropertyAssignment(nameProperty) || !ts.isStringLiteralLike(nameProperty.initializer)) {
    return undefined;
  }

  return nameProperty.initializer.text;
}

function isAuthLikeCookieName(cookieName: string): boolean {
  const normalized = cookieName.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
  return normalized.split(/[^a-z0-9]+/).some((part) => SESSION_COOKIE_NAME_PARTS.has(part));
}

type CookieFlagState = Record<SessionCookieFlag, "present" | "missing" | "dynamic">;

function inspectCookieFlags(node: ts.CallExpression): CookieFlagState {
  const firstArgument = node.arguments[0];
  const thirdArgument = node.arguments[2];
  if (firstArgument && ts.isObjectLiteralExpression(firstArgument)) {
    return inspectCookieOptionsObject(firstArgument);
  }

  if (node.arguments.length < 3) {
    return allFlagState("missing");
  }

  if (!thirdArgument || !ts.isObjectLiteralExpression(thirdArgument)) {
    return allFlagState("dynamic");
  }

  return inspectCookieOptionsObject(thirdArgument);
}

function inspectCookieOptionsObject(options: ts.ObjectLiteralExpression): CookieFlagState {
  const state = allFlagState("missing");
  for (const property of options.properties) {
    if (ts.isSpreadAssignment(property)) {
      SESSION_COOKIE_FLAGS.forEach((flag) => (state[flag] = "dynamic"));
      continue;
    }

    if (ts.isShorthandPropertyAssignment(property)) {
      const flag = propertyName(property.name);
      if (isSessionCookieFlag(flag)) {
        state[flag] = "dynamic";
      }
      continue;
    }

    if (!ts.isPropertyAssignment(property)) {
      continue;
    }

    const flag = propertyName(property.name);
    if (!isSessionCookieFlag(flag)) {
      continue;
    }

    state[flag] = flagValueState(flag, property.initializer);
  }

  return state;
}

function allFlagState(state: CookieFlagState[SessionCookieFlag]): CookieFlagState {
  return {
    httpOnly: state,
    secure: state,
    sameSite: state
  };
}

function flagValueState(flag: SessionCookieFlag, value: ts.Expression): CookieFlagState[SessionCookieFlag] {
  if (flag === "sameSite") {
    return ts.isStringLiteralLike(value) && /^(?:lax|strict|none)$/i.test(value.text) ? "present" : "dynamic";
  }

  if (value.kind === ts.SyntaxKind.TrueKeyword) {
    return "present";
  }

  if (value.kind === ts.SyntaxKind.FalseKeyword) {
    return "missing";
  }

  return "dynamic";
}

function isSessionCookieFlag(value: string | undefined): value is SessionCookieFlag {
  return value !== undefined && (SESSION_COOKIE_FLAGS as readonly string[]).includes(value);
}

function collectCookieStoreNames(sourceFile: ts.SourceFile): WeakMap<ts.Node, Set<string>> {
  const names = new WeakMap<ts.Node, Set<string>>();
  visit(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) {
      return;
    }

    if (isCookiesFactoryCall(node.initializer)) {
      const scope = cookieScopeRoot(node) ?? sourceFile;
      const scopeNames = names.get(scope) ?? new Set<string>();
      scopeNames.add(node.name.text);
      names.set(scope, scopeNames);
    }
  });
  return names;
}

function cookieScopeRoot(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isSourceFile(current) || isCookieFunctionLike(current)) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

function isCookieFunctionLike(node: ts.Node): boolean {
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

function isCookiesFactoryCall(expression: ts.Expression): boolean {
  const unwrapped = ts.isAwaitExpression(expression) ? expression.expression : expression;
  return ts.isCallExpression(unwrapped) && ts.isIdentifier(unwrapped.expression) && unwrapped.expression.text === "cookies";
}

function propertyName(name: ts.PropertyName | undefined): string | undefined {
  if (!name) {
    return undefined;
  }

  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }

  return undefined;
}

function rootIdentifier(expression: ts.Expression): ts.Identifier | undefined {
  let current: ts.Expression = expression;
  while (ts.isPropertyAccessExpression(current)) {
    current = current.expression;
  }
  return ts.isIdentifier(current) ? current : undefined;
}

function unwrapParentheses(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current)) {
    current = current.expression;
  }
  return current;
}

function hasDirective(statements: readonly ts.Statement[], directive: string): boolean {
  for (const statement of statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteralLike(statement.expression)) {
      return false;
    }

    if (statement.expression.text === directive) {
      return true;
    }
  }

  return false;
}

function visit(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visit(child, callback));
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
