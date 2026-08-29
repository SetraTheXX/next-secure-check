import ts from "typescript";
import { COMMAND_ALIAS_LIMIT } from "./command-ast.js";
import type { BoundedFlowCallbacks, BoundedFlowContext } from "./command-flow.js";

const SQL_QUERY_METHOD_NAMES = new Set(["query", "execute", "$queryRaw", "$executeRaw"]);
const SQL_RAW_TAG_NAMES = new Set(["$queryRaw", "$executeRaw"]);
const SQL_KEYWORD_PATTERN = /\b(SELECT|INSERT|UPDATE|DELETE)\b/i;

type RawSqlFlowValue = {
  path?: string;
  aliasDepth: number;
};

type RawSqlScopeState = {
  values: Map<string, RawSqlFlowValue>;
  initialized: Set<string>;
};

export function createRawSqlFlowCallbacks(): BoundedFlowCallbacks {
  const states = new WeakMap<ts.Node, RawSqlScopeState>();

  return {
    onVariableDeclaration: (node, context) => {
      if (!ts.isIdentifier(node.name)) {
        return;
      }

      const state = rawSqlScopeState(states, context);
      if (!node.initializer) {
        state.values.delete(node.name.text);
        state.initialized.delete(node.name.text);
        return;
      }

      state.initialized.add(node.name.text);
      const value = rawSqlValueForExpression(node.initializer, node.name.text, state, context);
      if (value) {
        state.values.set(node.name.text, value);
      } else {
        state.values.delete(node.name.text);
      }
    },
    onAssignment: (node, context) => {
      const target = rawSqlTargetIdentifier(node.left);
      if (!target) {
        return;
      }

      const state = rawSqlScopeState(states, context);
      if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken || state.initialized.has(target)) {
        state.values.delete(target);
        state.initialized.add(target);
        return;
      }

      state.initialized.add(target);
      const value = rawSqlValueForExpression(node.right, target, state, context);
      if (value) {
        state.values.set(target, value);
      } else {
        state.values.delete(target);
      }
    },
    onCall: (node, context) => {
      const state = rawSqlScopeState(states, context);
      if (isSqlQuerySinkCall(node)) {
        const [firstArgument] = node.arguments;
        if (firstArgument) {
          const directExpression = isInterpolatedSqlExpression(firstArgument);
          const normalized = unwrapRawSqlExpression(firstArgument);
          const aliasedValue = ts.isIdentifier(normalized) ? state.values.get(normalized.text) : undefined;
          if (directExpression || aliasedValue) {
            context.recordSink(node, "raw-sql");
            const evidencePath = directExpression
              ? context.findSourcePathInExpression(firstArgument)
              : aliasedValue?.path;
            if (evidencePath) {
              context.recordEvidencePath(node, evidencePath);
            }
          }
        }
      }

      if (!isSqlQuerySinkCall(node)) {
        invalidateRawSqlReferences(node, state);
      }
    },
    onTaggedTemplate: (node, context) => {
      if (!isRawSqlTaggedTemplate(node)) {
        return;
      }

      const evidencePath = context.findSourcePathInExpression(node.template);
      if (evidencePath) {
        context.recordEvidencePath(node, evidencePath);
      }
    },
    onInvalidation: (identifier, _reason, context) => {
      const state = rawSqlScopeState(states, context);
      state.values.delete(identifier);
      state.initialized.add(identifier);
    }
  };
}

export function findRawSqlConcatNodes(sourceFile: ts.SourceFile): ts.Node[] {
  const matches: ts.Node[] = [];

  visitSqlNodes(sourceFile, (node) => {
    if (ts.isCallExpression(node) && isSqlQuerySinkCall(node)) {
      const [firstArgument] = node.arguments;
      if (isInterpolatedSqlExpression(firstArgument)) {
        matches.push(node);
      }
      return;
    }

    if (ts.isTaggedTemplateExpression(node) && isRawSqlTaggedTemplate(node) && isInterpolatedSqlExpression(node.template)) {
      matches.push(node);
    }
  });

  return matches;
}

function isSqlQuerySinkCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  return ts.isPropertyAccessExpression(expression) && SQL_QUERY_METHOD_NAMES.has(expression.name.text);
}

function isRawSqlTaggedTemplate(node: ts.TaggedTemplateExpression): boolean {
  const tag = node.tag;
  return ts.isPropertyAccessExpression(tag) && SQL_RAW_TAG_NAMES.has(tag.name.text);
}

function rawSqlScopeState(states: WeakMap<ts.Node, RawSqlScopeState>, context: BoundedFlowContext): RawSqlScopeState {
  const existing = states.get(context.scopeRoot);
  if (existing) {
    return existing;
  }

  const created: RawSqlScopeState = { values: new Map<string, RawSqlFlowValue>(), initialized: new Set<string>() };
  states.set(context.scopeRoot, created);
  return created;
}

function rawSqlValueForExpression(
  expression: ts.Expression,
  targetName: string,
  state: RawSqlScopeState,
  context: BoundedFlowContext
): RawSqlFlowValue | undefined {
  if (isInterpolatedSqlExpression(expression)) {
    return {
      path: context.findSourcePathInExpression(expression),
      aliasDepth: 0
    };
  }

  const normalized = unwrapRawSqlExpression(expression);
  if (!ts.isIdentifier(normalized)) {
    return undefined;
  }

  const existing = state.values.get(normalized.text);
  if (!existing || existing.aliasDepth >= COMMAND_ALIAS_LIMIT) {
    return undefined;
  }

  return {
    path: existing.path ? `${existing.path} -> ${targetName}` : undefined,
    aliasDepth: existing.aliasDepth + 1
  };
}

export function isInterpolatedSqlExpression(node: ts.Node | undefined): boolean {
  const normalized = node && unwrapRawSqlExpression(node as ts.Expression);
  if (!normalized || !SQL_KEYWORD_PATTERN.test(normalized.getText())) {
    return false;
  }

  if (ts.isTemplateExpression(normalized)) {
    return true;
  }

  return ts.isBinaryExpression(normalized) && hasStringConcatenation(normalized);
}

function hasStringConcatenation(node: ts.BinaryExpression): boolean {
  if (node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return !isStaticStringExpression(node.left) || !isStaticStringExpression(node.right);
  }

  return (
    (ts.isBinaryExpression(node.left) && hasStringConcatenation(node.left)) ||
    (ts.isBinaryExpression(node.right) && hasStringConcatenation(node.right))
  );
}

function isStaticStringExpression(node: ts.Expression): boolean {
  const normalized = unwrapRawSqlExpression(node);
  if (
    ts.isStringLiteralLike(normalized) ||
    ts.isNumericLiteral(normalized) ||
    ts.isBigIntLiteral(normalized) ||
    normalized.kind === ts.SyntaxKind.TrueKeyword ||
    normalized.kind === ts.SyntaxKind.FalseKeyword ||
    normalized.kind === ts.SyntaxKind.NullKeyword
  ) {
    return true;
  }

  return ts.isBinaryExpression(normalized) &&
    normalized.operatorToken.kind === ts.SyntaxKind.PlusToken &&
    isStaticStringExpression(normalized.left) &&
    isStaticStringExpression(normalized.right);
}

function rawSqlTargetIdentifier(node: ts.Node): string | undefined {
  if (ts.isIdentifier(node)) {
    return node.text;
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return rawSqlTargetIdentifier(node.expression);
  }

  return undefined;
}

function invalidateRawSqlReferences(node: ts.Node, state: RawSqlScopeState): void {
  visitSqlNodes(node, (child) => {
    if (!ts.isIdentifier(child) || !state.values.has(child.text)) {
      return;
    }

    if (ts.isPropertyAccessExpression(child.parent) && child.parent.name === child) {
      return;
    }

    state.values.delete(child.text);
    state.initialized.add(child.text);
  });
}

function unwrapRawSqlExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAwaitExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression;
  }

  return current;
}

function visitSqlNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitSqlNodes(child, callback));
}
