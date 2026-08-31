import ts from "typescript";
import { COMMAND_ALIAS_LIMIT, ROUTE_PARAMS_NAMES, SEARCH_PARAMS_NAME } from "./command-ast.js";
import {
  collectCommandFlowFacts,
  type BoundedFlowCallbacks,
  type BoundedFlowContext
} from "./command-flow.js";

const REQUEST_ROOT_NAMES = new Set([
  "body",
  "context",
  "formData",
  "params",
  "query",
  "req",
  "request",
  "routeParams",
  "searchParams"
]);
const REQUEST_OBJECT_MEMBERS = new Set(["body", "formData", "nextUrl", "params", "query", "url"]);
const URL_FIELD_NAMES = new Set(["callbackUrl", "destination", "endpoint", "href", "redirectUrl", "target", "uri", "url", "webhookUrl"]);
const HTTP_METHOD_NAMES = new Set(["get"]);
const ROUTE_HANDLER_NAMES = new Set(["DELETE", "GET", "PATCH", "POST", "PUT", "getServerSideProps"]);
const SAFE_URL_HELPER_NAME_PATTERN = /(?:allowed|allowlist|public|safe|valid|private|internal|host|origin|network|url)/i;

type SsrfFunctionLike =
  | ts.ArrowFunction
  | ts.ConstructorDeclaration
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.GetAccessorDeclaration
  | ts.MethodDeclaration
  | ts.SetAccessorDeclaration;

type SsrfFlowValue = {
  path: string;
  origin: string;
  aliasDepth: number;
  urlLike: boolean;
};

type SsrfBindings = {
  axiosNames: ReadonlySet<string>;
  gotNames: ReadonlySet<string>;
  moduleDeclaredNames: ReadonlySet<string>;
  staticAllowlistNames: ReadonlySet<string>;
  safeUrlHelpers: ReadonlySet<string>;
};

type SsrfFlowState = {
  scopeRoot: ts.Node;
  supported: boolean;
  parameterNames: ReadonlySet<string>;
  bindings: SsrfBindings;
  staticAllowlistNames: Set<string>;
  declared: Set<string>;
  initialized: Set<string>;
  invalidated: Set<string>;
  tracked: Map<string, SsrfFlowValue>;
  precedingGuardedOrigins: Set<string>;
};

type SsrfSink = {
  argument: ts.Expression;
  name: string;
};

export type SsrfFlowMatch = {
  node: ts.Node;
  evidencePath: string;
  sinkName: string;
};

export type SsrfFlowAnalysis = {
  callbacks: BoundedFlowCallbacks;
  getMatches: () => SsrfFlowMatch[];
};

export function findUnvalidatedOutboundRequestTargets(sourceFile: ts.SourceFile): SsrfFlowMatch[] {
  const analysis = createSsrfFlowAnalysis(sourceFile);
  collectCommandFlowFacts(sourceFile, new Set(), new Set(), analysis.callbacks);
  return analysis.getMatches();
}

export function createSsrfFlowAnalysis(sourceFile: ts.SourceFile): SsrfFlowAnalysis {
  const bindings = collectSsrfBindings(sourceFile);
  const states = new WeakMap<ts.Node, SsrfFlowState>();
  const matches: SsrfFlowMatch[] = [];
  const disabled = hasDirective(sourceFile.statements, "use client");

  const stateFor = (context: BoundedFlowContext): SsrfFlowState => {
    const existing = states.get(context.scopeRoot);
    if (existing) {
      return existing;
    }
    const state = createSsrfFlowState(context.scopeRoot, bindings, disabled);
    states.set(context.scopeRoot, state);
    return state;
  };

  const callbacks: BoundedFlowCallbacks = {
    onVariableDeclaration: (node, context) => {
      const state = stateFor(context);
      if (state.supported) {
        recordSsrfDeclaration(node, state);
      }
    },
    onAssignment: (node, context) => {
      const state = stateFor(context);
      if (state.supported) {
        recordSsrfAssignment(node, state);
      }
    },
    onCall: (node, context) => {
      const state = stateFor(context);
      if (!state.supported) {
        return;
      }

      const sink = ssrfSinkForCall(node, state);
      if (sink) {
        const value = ssrfValueForExpression(sink.argument, state);
        const guardedOrigins = ssrfGuardOriginsForSink(node, state);
        if (value?.urlLike && !guardedOrigins.has(value.origin)) {
          matches.push({ node, evidencePath: value.path, sinkName: sink.name });
        }
        return;
      }

      for (const guard of enclosingIfGuards(node)) {
        if (guard.branch === "condition" && isRejectingGuard(guard.statement, state)) {
          collectSsrfGuardOrigins(guard.condition, state, false).forEach((origin) => state.precedingGuardedOrigins.add(origin));
        }
      }
      if (!isNonEscapingSsrfCall(node, state)) {
        invalidateSsrfReferences(node, state);
      }
    },
    shouldSkipCallInvalidation: (node, context) => {
      const state = stateFor(context);
      return state.supported && (ssrfSinkForCall(node, state) !== undefined || isNonEscapingSsrfCall(node, state));
    },
    onInvalidation: (identifier, _reason, context) => {
      const state = stateFor(context);
      if (state.supported) {
        state.precedingGuardedOrigins.clear();
        state.tracked.delete(identifier);
        state.invalidated.add(identifier);
      }
    }
  };

  return { callbacks, getMatches: () => dedupeSsrfMatches(matches) };
}

function createSsrfFlowState(scopeRoot: ts.Node, bindings: SsrfBindings, disabled: boolean): SsrfFlowState {
  const scopeFunction = ts.isSourceFile(scopeRoot) ? undefined : ssrfFunctionForBody(scopeRoot);
  const parameterNames = !scopeFunction
    ? new Set<string>()
    : new Set(scopeFunction.parameters.flatMap((parameter) => bindingIdentifiers(parameter.name).map((id) => id.text)));
  const declared = new Set(parameterNames);
  collectSsrfScopeDeclarations(scopeRoot, declared);
  const staticAllowlistNames = new Set(bindings.staticAllowlistNames);
  collectSsrfScopeAllowlistNames(scopeRoot, staticAllowlistNames);
  const functionName = scopeFunction ? ssrfFunctionName(scopeFunction) : undefined;
  if (functionName) {
    declared.add(functionName);
  }

  return {
    scopeRoot,
    supported: !disabled && scopeFunction !== undefined && isSupportedServerEntry(scopeFunction),
    parameterNames,
    bindings,
    staticAllowlistNames,
    declared,
    initialized: new Set(),
    invalidated: new Set(),
    tracked: new Map(),
    precedingGuardedOrigins: new Set()
  };
}

function ssrfFunctionForBody(node: ts.Node): SsrfFunctionLike | undefined {
  let current: ts.Node | undefined = node;
  while (current?.parent) {
    const parent: ts.Node = current.parent;
    if (isSsrfFunctionLike(parent) && parent.body === current) {
      return parent;
    }
    current = parent;
  }
  return undefined;
}

function isSupportedServerEntry(node: SsrfFunctionLike): boolean {
  const name = ssrfFunctionName(node);
  if (name && ROUTE_HANDLER_NAMES.has(name)) {
    return true;
  }
  if (hasExportModifier(node) || hasDefaultExportModifier(node)) {
    return true;
  }
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    const statement = parent.parent.parent;
    return ts.isVariableStatement(statement) && hasExportModifier(statement);
  }
  return ts.isExportAssignment(parent);
}

function ssrfSinkForCall(node: ts.CallExpression, state: SsrfFlowState): SsrfSink | undefined {
  if (ts.isIdentifier(node.expression)) {
    if (node.expression.text === "fetch" && !isSsrfNameDeclared("fetch", state)) {
      return firstSsrfSinkArgument(node, "fetch");
    }
    if (state.bindings.axiosNames.has(node.expression.text) && !state.declared.has(node.expression.text)) {
      return firstSsrfSinkArgument(node, "axios");
    }
    if (state.bindings.gotNames.has(node.expression.text) && !state.declared.has(node.expression.text)) {
      return firstSsrfSinkArgument(node, "got");
    }
    return undefined;
  }

  if (!ts.isPropertyAccessExpression(node.expression)) {
    return undefined;
  }
  const root = rootIdentifier(node.expression.expression)?.text;
  const method = node.expression.name.text;
  if (!root || !HTTP_METHOD_NAMES.has(method)) {
    return undefined;
  }
  if (state.bindings.axiosNames.has(root) && !state.declared.has(root)) {
    return firstSsrfSinkArgument(node, `axios.${method}`);
  }
  if (state.bindings.gotNames.has(root) && !state.declared.has(root)) {
    return firstSsrfSinkArgument(node, `got.${method}`);
  }
  return undefined;
}

function firstSsrfSinkArgument(node: ts.CallExpression, name: string): SsrfSink | undefined {
  const argument = node.arguments[0];
  return argument ? { argument, name } : undefined;
}

function recordSsrfDeclaration(node: ts.VariableDeclaration, state: SsrfFlowState): void {
  if (ts.isIdentifier(node.name)) {
    const name = node.name.text;
    state.declared.add(name);
    if (!node.initializer) {
      state.tracked.delete(name);
      state.initialized.delete(name);
      state.staticAllowlistNames.delete(name);
      return;
    }
    state.initialized.add(name);
    if (isStaticAllowlistExpression(node.initializer)) {
      state.staticAllowlistNames.add(name);
    } else {
      state.staticAllowlistNames.delete(name);
    }
    trackSsrfValue(name, ssrfValueForAssignment(node.initializer, name, state), state);
    return;
  }

  if (!ts.isObjectBindingPattern(node.name) || !node.initializer) {
    return;
  }
  const base = ssrfValueForExpression(node.initializer, state);
  for (const element of node.name.elements) {
    const localName = bindingElementLocalName(element);
    const memberName = bindingElementName(element);
    if (!localName) {
      continue;
    }
    state.declared.add(localName);
    state.initialized.add(localName);
    trackSsrfValue(localName, base && memberName ? withSsrfMember(base, memberName) : undefined, state);
  }
}

function recordSsrfAssignment(node: ts.BinaryExpression, state: SsrfFlowState): void {
  const target = rootIdentifier(node.left)?.text;
  if (!target) {
    invalidateSsrfReferences(node.left, state);
    return;
  }
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken || state.initialized.has(target)) {
    invalidateSsrfTarget(node.left, state);
    return;
  }
  state.declared.add(target);
  state.initialized.add(target);
  if (isStaticAllowlistExpression(node.right)) {
    state.staticAllowlistNames.add(target);
  } else {
    state.staticAllowlistNames.delete(target);
  }
  trackSsrfValue(target, ssrfValueForAssignment(node.right, target, state), state);
}

function ssrfValueForAssignment(expression: ts.Expression, targetName: string, state: SsrfFlowState): SsrfFlowValue | undefined {
  const normalized = unwrapSsrfExpression(expression);
  if (ts.isIdentifier(normalized)) {
    const existing = ssrfValueForExpression(normalized, state);
    return existing ? withSsrfAlias(existing, targetName) : undefined;
  }
  return ssrfValueForExpression(normalized, state);
}

function ssrfValueForExpression(expression: ts.Expression, state: SsrfFlowState): SsrfFlowValue | undefined {
  const normalized = unwrapSsrfExpression(expression);
  if (ts.isBinaryExpression(normalized)) {
    return ssrfValueForExpression(normalized.left, state) ?? ssrfValueForExpression(normalized.right, state);
  }
  if (ts.isConditionalExpression(normalized)) {
    return ssrfValueForExpression(normalized.whenTrue, state) ?? ssrfValueForExpression(normalized.whenFalse, state);
  }
  if (ts.isIdentifier(normalized)) {
    if (state.invalidated.has(normalized.text) || isDeclarationName(normalized)) {
      return undefined;
    }
    return state.tracked.get(normalized.text);
  }
  if (ts.isPropertyAccessExpression(normalized)) {
    const path = staticMemberPath(normalized);
    const direct = path && directSsrfSourceForPath(path, state);
    if (direct) {
      return direct;
    }
    const base = ssrfValueForExpression(normalized.expression, state);
    return base && (base.urlLike || URL_FIELD_NAMES.has(normalized.name.text))
      ? withSsrfMember(base, normalized.name.text)
      : undefined;
  }
  if (ts.isElementAccessExpression(normalized)) {
    const member = normalized.argumentExpression && literalText(normalized.argumentExpression);
    if (!member) {
      return undefined;
    }
    const path = staticMemberPath(normalized);
    const direct = path && directSsrfSourceForPath(path, state);
    if (direct) {
      return direct;
    }
    const base = ssrfValueForExpression(normalized.expression, state);
    return base && (base.urlLike || URL_FIELD_NAMES.has(member)) ? withSsrfMember(base, member) : undefined;
  }
  if (ts.isCallExpression(normalized)) {
    return ssrfValueForCall(normalized, state);
  }
  if (ts.isNewExpression(normalized) && ts.isIdentifier(normalized.expression) && normalized.expression.text === "URL") {
    const source = (normalized.arguments ?? []).map((argument) => ssrfValueForExpression(argument, state)).find((value) => value?.urlLike);
    return source ? { ...source, path: `${source.path} -> URL()` } : undefined;
  }
  return undefined;
}

function ssrfValueForCall(node: ts.CallExpression, state: SsrfFlowState): SsrfFlowValue | undefined {
  if (!ts.isPropertyAccessExpression(node.expression)) {
    return undefined;
  }
  const path = staticMemberPath(node.expression);
  if (path && isRequestSourceCallPath(path, state)) {
    const method = path.at(-1);
    if (method === "json" || method === "formData") {
      return directSsrfSourceForPath(path, state, true);
    }
    if (method === "get" && isUrlFieldArgument(node)) {
      return directSsrfSourceForPath(path, state, true, true);
    }
  }
  if (node.expression.name.text === "get" && isUrlFieldArgument(node)) {
    const base = ssrfValueForExpression(node.expression.expression, state);
    return base ? withSsrfMember(base, "get()", true) : undefined;
  }
  return undefined;
}

function directSsrfSourceForPath(path: string[], state: SsrfFlowState, call = false, urlLike = false): SsrfFlowValue | undefined {
  const [root, ...members] = path;
  if (!root || !isRequestRootReference(root, state) || members.length === 0) {
    return undefined;
  }
  const last = members.at(-1) ?? "";
  const recognized = (call && ["formData", "get", "json"].includes(last)) ||
    ROUTE_PARAMS_NAMES.test(root) || SEARCH_PARAMS_NAME.test(root) || REQUEST_OBJECT_MEMBERS.has(members[0] ?? "");
  if (!recognized) {
    return undefined;
  }
  const formatted = formatSsrfPath(path);
  const displayPath = call ? `${formatted}()` : formatted;
  return { path: displayPath, origin: displayPath, aliasDepth: 0, urlLike: urlLike || URL_FIELD_NAMES.has(last) };
}

function isRequestSourceCallPath(path: string[], state: SsrfFlowState): boolean {
  const method = path.at(-1);
  const root = path[0];
  if (!root || !method || !isRequestRootReference(root, state)) {
    return false;
  }
  if (method === "json" || method === "formData") {
    return true;
  }
  return method === "get" && (SEARCH_PARAMS_NAME.test(root) || (path.includes("nextUrl") && path.includes("searchParams")));
}

function isRequestRootReference(name: string, state: SsrfFlowState): boolean {
  return REQUEST_ROOT_NAMES.has(name) && (state.parameterNames.has(name) ||
    (!state.declared.has(name) && !state.bindings.moduleDeclaredNames.has(name)));
}

function isSsrfNameDeclared(name: string, state: SsrfFlowState): boolean {
  return state.declared.has(name) || state.bindings.moduleDeclaredNames.has(name);
}

function isUrlFieldArgument(node: ts.CallExpression): boolean {
  const [argument] = node.arguments;
  return argument !== undefined && ts.isStringLiteralLike(argument) && URL_FIELD_NAMES.has(argument.text);
}

function ssrfGuardOriginsForSink(node: ts.Node, state: SsrfFlowState): Set<string> {
  const origins = new Set(state.precedingGuardedOrigins);
  for (const guard of enclosingIfGuards(node)) {
    if (guard.branch === "then") {
      collectSsrfGuardOrigins(guard.condition, state, true).forEach((origin) => origins.add(origin));
    } else if (guard.branch === "else") {
      collectSsrfGuardOrigins(guard.condition, state, false).forEach((origin) => origins.add(origin));
    } else if (guard.branch === "condition" && isRejectingGuard(guard.statement, state)) {
      collectSsrfGuardOrigins(guard.condition, state, false).forEach((origin) => origins.add(origin));
    }
  }
  return origins;
}

function collectSsrfGuardOrigins(condition: ts.Expression, state: SsrfFlowState, safeWhenConditionIs: boolean): Set<string> {
  const origins = new Set<string>();
  visitAllSsrfNodes(condition, (node) => {
    if (ts.isBinaryExpression(node) && isEqualityOperator(node.operatorToken.kind)) {
      const left = ssrfOriginsForExpression(node.left, state);
      const right = ssrfOriginsForExpression(node.right, state);
      const equalityMeansSafe = isEqualSsrfOperator(node.operatorToken.kind);
      if (left.size > 0 && isSsrfGuardValueExpression(node.left, state) && isStaticSsrfValue(node.right) &&
        isSafeSsrfGuardPath(node, condition, safeWhenConditionIs, equalityMeansSafe)) {
        left.forEach((origin) => origins.add(origin));
      }
      if (right.size > 0 && isSsrfGuardValueExpression(node.right, state) && isStaticSsrfValue(node.left) &&
        isSafeSsrfGuardPath(node, condition, safeWhenConditionIs, equalityMeansSafe)) {
        right.forEach((origin) => origins.add(origin));
      }
    }
    if (ts.isCallExpression(node) && isSsrfAllowlistCall(node, state) && isSafeSsrfGuardPath(node, condition, safeWhenConditionIs, true)) {
      ssrfOriginsForCallArguments(node, state).forEach((origin) => origins.add(origin));
    }
    if (ts.isCallExpression(node) && isSafeUrlHelperCall(node, state)) {
      const helperName = ssrfHelperName(node);
      const helperMeansSafe = helperName !== undefined && !isRejectingSsrfHelperName(helperName);
      if (helperName && isSafeSsrfGuardPath(node, condition, safeWhenConditionIs, helperMeansSafe)) {
        ssrfOriginsForCallArguments(node, state).forEach((origin) => origins.add(origin));
      }
    }
  });
  return origins;
}

function isSafeSsrfGuardPath(
  node: ts.Node,
  condition: ts.Expression,
  safeWhenConditionIs: boolean,
  nodeMeansSafe: boolean
): boolean {
  const nodeValueOnConditionTrue = ssrfConditionValueOnTrue(node, condition);
  if (nodeValueOnConditionTrue === undefined) {
    return false;
  }
  const nodeValueOnSafePath = safeWhenConditionIs ? nodeValueOnConditionTrue : !nodeValueOnConditionTrue;
  return nodeValueOnSafePath === nodeMeansSafe;
}

function ssrfConditionValueOnTrue(node: ts.Node, condition: ts.Expression): boolean | undefined {
  let current: ts.Node = node;
  let value = true;
  while (current !== condition) {
    const parent = current.parent;
    if (!parent) {
      return undefined;
    }
    if (ts.isParenthesizedExpression(parent) && parent.expression === current) {
      current = parent;
      continue;
    }
    if (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.ExclamationToken && parent.operand === current) {
      value = !value;
      current = parent;
      continue;
    }
    return undefined;
  }
  return value;
}

function isSsrfAllowlistCall(node: ts.CallExpression, state: SsrfFlowState): boolean {
  if (!ts.isPropertyAccessExpression(node.expression) || !["has", "includes"].includes(node.expression.name.text)) {
    return false;
  }
  if (!node.arguments.some((argument) => isSsrfGuardValueExpression(argument, state))) {
    return false;
  }
  const receiver = unwrapSsrfExpression(node.expression.expression);
  if (isStaticAllowlistExpression(receiver)) {
    return true;
  }
  const root = rootIdentifier(receiver)?.text;
  return root !== undefined && state.staticAllowlistNames.has(root) && !state.invalidated.has(root);
}

function isSsrfGuardValueExpression(expression: ts.Expression, state: SsrfFlowState): boolean {
  const normalized = unwrapSsrfExpression(expression);
  const value = ssrfValueForExpression(normalized, state);
  if (!value?.urlLike) {
    return false;
  }
  if (ts.isIdentifier(normalized) || ts.isCallExpression(normalized) || ts.isNewExpression(normalized)) {
    return true;
  }
  if (ts.isPropertyAccessExpression(normalized)) {
    return URL_FIELD_NAMES.has(normalized.name.text) || ["host", "hostname", "origin"].includes(normalized.name.text);
  }
  if (ts.isElementAccessExpression(normalized)) {
    const member = normalized.argumentExpression && literalText(normalized.argumentExpression);
    return member !== undefined && (URL_FIELD_NAMES.has(member) || ["host", "hostname", "origin"].includes(member));
  }
  return false;
}

function isSafeUrlHelperCall(node: ts.CallExpression, state: SsrfFlowState): boolean {
  const name = ssrfHelperName(node);
  return name !== undefined && node.arguments.length === 1 && !state.declared.has(name) && state.bindings.safeUrlHelpers.has(name) &&
    node.arguments.some((argument) => isSsrfGuardValueExpression(argument, state));
}

function ssrfHelperName(node: ts.CallExpression): string | undefined {
  return ts.isIdentifier(node.expression)
    ? node.expression.text
    : ts.isPropertyAccessExpression(node.expression)
      ? node.expression.name.text
      : undefined;
}

function isRejectingSsrfHelperName(name: string): boolean {
  return /(?:private|internal|blocked|deny)/i.test(name);
}

function ssrfOriginsForCallArguments(node: ts.CallExpression, state: SsrfFlowState): Set<string> {
  const origins = new Set<string>();
  node.arguments.forEach((argument) => ssrfOriginsForExpression(argument, state).forEach((origin) => origins.add(origin)));
  return origins;
}

function ssrfOriginsForExpression(node: ts.Node, state: SsrfFlowState): Set<string> {
  const origins = new Set<string>();
  const value = ssrfValueForExpression(node as ts.Expression, state);
  if (value?.urlLike) {
    origins.add(value.origin);
  }
  ts.forEachChild(node, (child) => ssrfOriginsForExpression(child, state).forEach((origin) => origins.add(origin)));
  return origins;
}

function isNonEscapingSsrfCall(node: ts.CallExpression, state: SsrfFlowState): boolean {
  return Boolean(ssrfValueForCall(node, state)) || isSsrfAllowlistCall(node, state) || isSafeUrlHelperCall(node, state) ||
    isSsrfGuardCandidateCall(node, state);
}

function isSsrfGuardCandidateCall(node: ts.CallExpression, state: SsrfFlowState): boolean {
  const hasSourceArgument = node.arguments.some((argument) => ssrfOriginsForExpression(argument, state).size > 0);
  if (!hasSourceArgument) {
    return false;
  }
  if (ts.isPropertyAccessExpression(node.expression) && ["has", "includes"].includes(node.expression.name.text)) {
    return true;
  }
  const name = ssrfHelperName(node);
  return name !== undefined && SAFE_URL_HELPER_NAME_PATTERN.test(name);
}

function invalidateSsrfTarget(node: ts.Node, state: SsrfFlowState): void {
  state.precedingGuardedOrigins.clear();
  const target = rootIdentifier(node)?.text;
  if (target) {
    state.tracked.delete(target);
    state.invalidated.add(target);
    state.staticAllowlistNames.delete(target);
  }
  invalidateSsrfReferences(node, state);
}

function invalidateSsrfReferences(node: ts.Node, state: SsrfFlowState): void {
  const names = new Set<string>();
  visitSsrfNodes(node, (child) => {
    if (ts.isIdentifier(child) && !isPropertyName(child) && (state.tracked.has(child.text) || state.staticAllowlistNames.has(child.text))) {
      names.add(child.text);
    }
  });
  if (names.size > 0) {
    state.precedingGuardedOrigins.clear();
  }
  names.forEach((name) => {
    state.tracked.delete(name);
    state.staticAllowlistNames.delete(name);
    state.invalidated.add(name);
  });
}

function trackSsrfValue(name: string, value: SsrfFlowValue | undefined, state: SsrfFlowState): void {
  if (!value || value.aliasDepth > COMMAND_ALIAS_LIMIT || state.invalidated.has(name)) {
    state.tracked.delete(name);
    return;
  }
  state.tracked.set(name, value);
}

function withSsrfAlias(value: SsrfFlowValue, aliasName: string): SsrfFlowValue {
  return { ...value, path: `${value.path} -> ${aliasName}`, aliasDepth: value.aliasDepth + 1 };
}

function withSsrfMember(value: SsrfFlowValue, memberName: string, urlLike = false): SsrfFlowValue {
  return { ...value, path: `${value.path} -> ${memberName}`, urlLike: value.urlLike || urlLike || URL_FIELD_NAMES.has(memberName.replace(/\(\)$/, "")) };
}

function collectSsrfScopeAllowlistNames(node: ts.Node, names: Set<string>): void {
  visitSsrfNodes(node, (child) => {
    if (!ts.isVariableDeclaration(child) || !ts.isIdentifier(child.name)) {
      return;
    }
    if (child.initializer && isStaticAllowlistExpression(child.initializer)) {
      names.add(child.name.text);
    } else {
      names.delete(child.name.text);
    }
  });
}

function collectSsrfBindings(sourceFile: ts.SourceFile): SsrfBindings {
  const axiosNames = new Set<string>();
  const gotNames = new Set<string>();
  const moduleDeclaredNames = new Set<string>();
  const staticAllowlistNames = new Set<string>();
  collectSsrfScopeDeclarations(sourceFile, moduleDeclaredNames);
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && statement.importClause) {
      const moduleName = ts.isStringLiteralLike(statement.moduleSpecifier) ? statement.moduleSpecifier.text : "";
      if (moduleName === "axios" && statement.importClause.name) {
        axiosNames.add(statement.importClause.name.text);
      }
      if (moduleName === "got" && statement.importClause.name) {
        gotNames.add(statement.importClause.name.text);
      }
      if (statement.importClause.namedBindings && ts.isNamespaceImport(statement.importClause.namedBindings)) {
        if (moduleName === "axios") {
          axiosNames.add(statement.importClause.namedBindings.name.text);
        }
        if (moduleName === "got") {
          gotNames.add(statement.importClause.namedBindings.name.text);
        }
      }
    }
    if (ts.isVariableStatement(statement)) {
      statement.declarationList.declarations.forEach((declaration) => {
        const name = ts.isIdentifier(declaration.name) ? declaration.name.text : undefined;
        const moduleName = declaration.initializer && requiredModuleName(declaration.initializer);
        if (name && moduleName === "axios") {
          axiosNames.add(name);
        }
        if (name && moduleName === "got") {
          gotNames.add(name);
        }
      });
    }
  }
  collectSsrfScopeAllowlistNames(sourceFile, staticAllowlistNames);
  return {
    axiosNames,
    gotNames,
    moduleDeclaredNames,
    staticAllowlistNames,
    safeUrlHelpers: collectVisibleSafeUrlHelpers(sourceFile, staticAllowlistNames)
  };
}

function collectVisibleSafeUrlHelpers(sourceFile: ts.SourceFile, staticAllowlistNames: ReadonlySet<string>): ReadonlySet<string> {
  const helpers = new Set<string>();
  visitAllSsrfNodes(sourceFile, (node) => {
    if (!isSsrfFunctionLike(node)) {
      return;
    }
    const name = ssrfFunctionName(node);
    if (name && node.body && SAFE_URL_HELPER_NAME_PATTERN.test(name) && isVisibleSafeUrlHelperBody(node.body, staticAllowlistNames)) {
      helpers.add(name);
    }
  });
  return helpers;
}

function isVisibleSafeUrlHelperBody(body: ts.Node, staticAllowlistNames: ReadonlySet<string>): boolean {
  const owner = body.parent;
  if (!isSsrfFunctionLike(owner) || owner.parameters.length !== 1) {
    return false;
  }
  const parameterNames = new Set(owner.parameters.flatMap((parameter) => bindingIdentifiers(parameter.name).map((id) => id.text)));
  const helperAllowlistNames = new Set(staticAllowlistNames);
  collectSsrfScopeAllowlistNames(body, helperAllowlistNames);

  const parsedNames = new Set<string>();
  let parser = false;
  let host = false;
  let protection = false;
  visitSsrfNodes(body, (node) => {
    if (ts.isNewExpression(node) && isHelperUrlConstructor(node, parameterNames)) {
      parser = true;
      if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
        parsedNames.add(node.parent.name.text);
      }
    }
    if (ts.isPropertyAccessExpression(node) && ["host", "hostname", "origin"].includes(node.name.text)) {
      const receiver = unwrapSsrfExpression(node.expression);
      host = host || parsedNames.has(rootIdentifier(receiver)?.text ?? "") || isHelperUrlConstructor(receiver, parameterNames);
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ["has", "includes"].includes(node.expression.name.text)) {
      const receiver = unwrapSsrfExpression(node.expression.expression);
      const receiverName = rootIdentifier(receiver)?.text;
      const isStaticAllowlist = isStaticAllowlistExpression(receiver) ||
        (receiverName !== undefined && helperAllowlistNames.has(receiverName));
      protection = protection || isStaticAllowlist &&
        node.arguments.some((argument) => containsHelperGuardValue(argument, parsedNames, parameterNames));
    }
    if (ts.isBinaryExpression(node) && isEqualityOperator(node.operatorToken.kind)) {
      protection = protection ||
        (containsHelperGuardValue(node.left, parsedNames, parameterNames) && isStaticSsrfValue(node.right)) ||
        (containsHelperGuardValue(node.right, parsedNames, parameterNames) && isStaticSsrfValue(node.left));
    }
  });
  return parser && host && protection;
}

function isHelperUrlConstructor(node: ts.Node, parameterNames: ReadonlySet<string>): boolean {
  const normalized = ts.isExpression(node) ? unwrapSsrfExpression(node) : node;
  if (!ts.isNewExpression(normalized) || !ts.isIdentifier(normalized.expression) || normalized.expression.text !== "URL") {
    return false;
  }
  const [argument] = normalized.arguments ?? [];
  const input = argument && unwrapSsrfExpression(argument);
  return ts.isIdentifier(input) && parameterNames.has(input.text);
}

function containsHelperGuardValue(node: ts.Node, parsedNames: ReadonlySet<string>, parameterNames: ReadonlySet<string>): boolean {
  const normalized = ts.isExpression(node) ? unwrapSsrfExpression(node) : node;
  if (isHelperUrlConstructor(normalized, parameterNames)) {
    return true;
  }
  if (ts.isPropertyAccessExpression(normalized)) {
    const receiver = unwrapSsrfExpression(normalized.expression);
    const receiverName = rootIdentifier(receiver)?.text;
    return ["host", "hostname", "origin", "href", "url"].includes(normalized.name.text) &&
      (parsedNames.has(receiverName ?? "") || isHelperUrlConstructor(receiver, parameterNames));
  }
  if (ts.isElementAccessExpression(normalized)) {
    const member = normalized.argumentExpression && literalText(normalized.argumentExpression);
    const receiver = unwrapSsrfExpression(normalized.expression);
    const receiverName = rootIdentifier(receiver)?.text;
    return member !== undefined && ["host", "hostname", "origin", "href", "url"].includes(member) &&
      (parsedNames.has(receiverName ?? "") || isHelperUrlConstructor(receiver, parameterNames));
  }
  return false;
}

function collectSsrfScopeDeclarations(node: ts.Node, declared: Set<string>): void {
  ts.forEachChild(node, (child) => {
    if (isSsrfFunctionLike(child)) {
      if (ts.isFunctionDeclaration(child) && child.name) {
        declared.add(child.name.text);
      }
      return;
    }
    if (ts.isClassDeclaration(child) && child.name) {
      declared.add(child.name.text);
      return;
    }
    if (ts.isImportDeclaration(child) && child.importClause) {
      const clause = child.importClause;
      if (clause.name) {
        declared.add(clause.name.text);
      }
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          declared.add(clause.namedBindings.name.text);
        } else {
          clause.namedBindings.elements.forEach((element) => declared.add(element.name.text));
        }
      }
      return;
    }
    if (ts.isVariableDeclaration(child)) {
      bindingIdentifiers(child.name).forEach((identifier) => declared.add(identifier.text));
    }
    collectSsrfScopeDeclarations(child, declared);
  });
}

function enclosingIfGuards(node: ts.Node): Array<{ statement: ts.IfStatement; condition: ts.Expression; branch: "then" | "else" | "condition" }> {
  const guards: Array<{ statement: ts.IfStatement; condition: ts.Expression; branch: "then" | "else" | "condition" }> = [];
  let current: ts.Node | undefined = node;
  while (current?.parent) {
    const parent: ts.Node = current.parent;
    if (ts.isIfStatement(parent)) {
      const branch = isWithin(node, parent.expression)
        ? "condition"
        : isWithin(node, parent.thenStatement)
          ? "then"
          : parent.elseStatement && isWithin(node, parent.elseStatement)
            ? "else"
            : undefined;
      if (branch) {
        guards.push({ statement: parent, condition: parent.expression, branch });
      }
    }
    current = parent;
  }
  return guards;
}

function isRejectingGuard(statement: ts.IfStatement, state: SsrfFlowState): boolean {
  if (!isExitStatement(statement.thenStatement)) {
    return false;
  }
  const condition = statement.expression;
  return collectSsrfGuardOrigins(condition, state, false).size > 0;
}

function isExitStatement(node: ts.Statement): boolean {
  if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) {
    return true;
  }
  if (!ts.isBlock(node) || node.statements.length === 0) {
    return false;
  }
  const last = node.statements.at(-1);
  return last !== undefined && (ts.isReturnStatement(last) || ts.isThrowStatement(last));
}

function isWithin(node: ts.Node, ancestor: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current) {
    if (current === ancestor) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

function requiredModuleName(initializer: ts.Expression): string | undefined {
  return ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression) && initializer.expression.text === "require" &&
    initializer.arguments[0] && ts.isStringLiteralLike(initializer.arguments[0])
    ? initializer.arguments[0].text
    : undefined;
}

function rootIdentifier(node: ts.Node): ts.Identifier | undefined {
  if (ts.isIdentifier(node)) {
    return node;
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return rootIdentifier(node.expression);
  }
  return undefined;
}

function staticMemberPath(expression: ts.Expression): string[] | undefined {
  if (ts.isIdentifier(expression)) {
    return [expression.text];
  }
  if (ts.isPropertyAccessExpression(expression)) {
    const parent = staticMemberPath(expression.expression);
    return parent ? [...parent, expression.name.text] : undefined;
  }
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression && ts.isStringLiteralLike(expression.argumentExpression)) {
    const parent = staticMemberPath(expression.expression);
    return parent ? [...parent, expression.argumentExpression.text] : undefined;
  }
  return undefined;
}

function formatSsrfPath(path: string[]): string {
  const [root, first, ...rest] = path;
  if (!root || !first) {
    return path.join(".");
  }
  if (ROUTE_PARAMS_NAMES.test(root)) {
    return `${root} -> ${[first, ...rest].join(" -> ")}`;
  }
  if (["body", "formData", "params", "query"].includes(first)) {
    return rest.length > 0 ? `${root}.${first} -> ${rest.join(" -> ")}` : `${root}.${first}`;
  }
  return path.join(".");
}

function isStaticAllowlistExpression(node: ts.Expression): boolean {
  const normalized = unwrapSsrfExpression(node);
  if (ts.isArrayLiteralExpression(normalized)) {
    return normalized.elements.every((element) => !ts.isSpreadElement(element) && isStaticSsrfValue(element));
  }
  if (!ts.isNewExpression(normalized) || !ts.isIdentifier(normalized.expression) || normalized.expression.text !== "Set") {
    return false;
  }
  return (normalized.arguments ?? []).every((argument) =>
    (ts.isArrayLiteralExpression(argument) && argument.elements.every((element) => !ts.isSpreadElement(element) && isStaticSsrfValue(element))) ||
    isStaticSsrfValue(argument)
  );
}

function isStaticSsrfValue(node: ts.Node): boolean {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword;
}

function literalText(node: ts.Expression): string | undefined {
  return ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ? node.text : undefined;
}

function bindingElementName(element: ts.BindingElement): string | undefined {
  if (element.propertyName && (ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName))) {
    return element.propertyName.text;
  }
  return ts.isIdentifier(element.name) ? element.name.text : undefined;
}

function bindingElementLocalName(element: ts.BindingElement): string | undefined {
  return ts.isIdentifier(element.name) ? element.name.text : undefined;
}

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  return ts.isIdentifier(name)
    ? [name]
    : name.elements.flatMap((element) => (ts.isBindingElement(element) ? bindingIdentifiers(element.name) : []));
}

function unwrapSsrfExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isAwaitExpression(current) || ts.isNonNullExpression(current) || ts.isAsExpression(current) || ts.isTypeAssertionExpression(current)) {
    current = current.expression;
  }
  return current;
}

function isEqualityOperator(kind: ts.SyntaxKind): boolean {
  return [ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(kind);
}

function isEqualSsrfOperator(kind: ts.SyntaxKind): boolean {
  return kind === ts.SyntaxKind.EqualsEqualsToken || kind === ts.SyntaxKind.EqualsEqualsEqualsToken;
}

function isDeclarationName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (ts.isParameter(parent) && parent.name === node) || (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isBindingElement(parent) && parent.name === node) || (ts.isFunctionDeclaration(parent) && parent.name === node);
}

function isPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (ts.isPropertyAccessExpression(parent) && parent.name === node) || (ts.isMethodDeclaration(parent) && parent.name === node) ||
    (ts.isPropertyDeclaration(parent) && parent.name === node);
}

function isSsrfFunctionLike(node: ts.Node): node is SsrfFunctionLike {
  return ts.isArrowFunction(node) || ts.isConstructorDeclaration(node) || ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) ||
    ts.isGetAccessorDeclaration(node) || ts.isMethodDeclaration(node) || ts.isSetAccessorDeclaration(node);
}

function ssrfFunctionName(node: SsrfFunctionLike): string | undefined {
  if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
    return node.name && ts.isIdentifier(node.name) ? node.name.text : undefined;
  }
  return ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name) ? node.parent.name.text : undefined;
}

function hasExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
}

function hasDefaultExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword);
}

function hasDirective(statements: readonly ts.Statement[], directive: string): boolean {
  return statements.some((statement) => ts.isExpressionStatement(statement) && ts.isStringLiteralLike(statement.expression) && statement.expression.text === directive);
}

function visitSsrfNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => {
    if (!isSsrfFunctionLike(child)) {
      visitSsrfNodes(child, callback);
    }
  });
}

function visitAllSsrfNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitAllSsrfNodes(child, callback));
}

function dedupeSsrfMatches(matches: SsrfFlowMatch[]): SsrfFlowMatch[] {
  const seen = new Set<string>();
  return matches.filter((match) => {
    const key = `${match.node.pos}:${match.node.end}:${match.evidencePath}:${match.sinkName}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  }).sort((left, right) => left.node.getStart() - right.node.getStart());
}
