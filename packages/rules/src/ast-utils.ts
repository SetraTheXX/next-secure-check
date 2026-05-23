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
const SQL_QUERY_METHOD_NAMES = new Set(["query", "execute"]);
const SQL_RAW_TAG_NAMES = new Set(["$queryRaw", "$executeRaw"]);
const SQL_KEYWORD_PATTERN = /\b(SELECT|INSERT|UPDATE|DELETE)\b/i;

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
  const matches: DangerouslySetInnerHtmlMatch[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isJsxAttribute(node) || !ts.isIdentifier(node.name) || node.name.text !== "dangerouslySetInnerHTML") {
      return;
    }

    const severity = dangerouslySetInnerHtmlSeverity(node.initializer);
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

function isInterpolatedSqlTemplate(node: ts.Node | undefined): boolean {
  return node !== undefined && ts.isTemplateExpression(node) && SQL_KEYWORD_PATTERN.test(node.getText());
}

function dangerouslySetInnerHtmlSeverity(initializer: ts.JsxAttribute["initializer"]): "LOW" | "MEDIUM" | undefined {
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

  if (!htmlExpression || isStaticHtmlExpression(htmlExpression)) {
    return undefined;
  }

  return "MEDIUM";
}

function propertyNameText(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }

  return undefined;
}

function isStaticHtmlExpression(expression: ts.Expression): boolean {
  return ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression);
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
