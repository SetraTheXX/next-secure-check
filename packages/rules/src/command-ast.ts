import ts from "typescript";

export const COMMAND_EXECUTION_NAMES = new Set(["exec", "execSync", "spawn", "spawnSync"]);
export const COMMAND_ALIAS_LIMIT = 2;
export const REQUEST_SOURCE_NAMES = /^(?:req|request)$/i;
export const ROUTE_PARAMS_NAMES = /^(?:params|routeParams)$/i;
export const SEARCH_PARAMS_NAME = /^searchParams$/i;

export function isCommandExecutionCall(
  expression: ts.Expression,
  commandIdentifiers: ReadonlySet<string>,
  childProcessNamespaces: ReadonlySet<string>
): boolean {
  if (ts.isIdentifier(expression)) {
    return commandIdentifiers.has(expression.text);
  }

  if (!ts.isPropertyAccessExpression(expression) || !COMMAND_EXECUTION_NAMES.has(expression.name.text)) {
    return false;
  }

  return ts.isIdentifier(expression.expression) && childProcessNamespaces.has(expression.expression.text);
}

export function commandExecutionName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }

  return ts.isPropertyAccessExpression(expression) ? expression.name.text : undefined;
}

export function isCommandMutationOperator(operator: ts.PrefixUnaryOperator | ts.PostfixUnaryOperator): boolean {
  return operator === ts.SyntaxKind.PlusPlusToken || operator === ts.SyntaxKind.MinusMinusToken;
}

export function isCommandAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}
