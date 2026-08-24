import ts from "typescript";

const SQL_QUERY_METHOD_NAMES = new Set(["query", "execute"]);
const SQL_RAW_TAG_NAMES = new Set(["$queryRaw", "$executeRaw"]);
const SQL_KEYWORD_PATTERN = /\b(SELECT|INSERT|UPDATE|DELETE)\b/i;

export function findRawSqlConcatNodes(sourceFile: ts.SourceFile): ts.Node[] {
  const matches: ts.Node[] = [];

  visitSqlNodes(sourceFile, (node) => {
    if (ts.isCallExpression(node) && isSqlQuerySinkCall(node)) {
      const [firstArgument] = node.arguments;
      if (isInterpolatedSqlTemplate(firstArgument)) {
        matches.push(node);
      }
      return;
    }

    if (ts.isTaggedTemplateExpression(node) && isRawSqlTaggedTemplate(node) && isInterpolatedSqlTemplate(node.template)) {
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

function isInterpolatedSqlTemplate(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isTemplateExpression(node) && SQL_KEYWORD_PATTERN.test(node.getText());
}

function visitSqlNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitSqlNodes(child, callback));
}
