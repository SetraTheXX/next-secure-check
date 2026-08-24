import ts from "typescript";

const SANITIZER_MODULE_PATTERN = /^(?:dompurify|sanitize-html)$/i;

export type XssSeverity = "LOW" | "MEDIUM";

export type XssAnalysisFacts = {
  sanitizerIdentifiers: ReadonlySet<string>;
  safeHtmlIdentifiers: ReadonlySet<string>;
};

export type DangerouslySetInnerHtmlNode = {
  node: ts.JsxAttribute;
  severity: XssSeverity;
};

export function createXssAnalysisFacts(sourceFile: ts.SourceFile): XssAnalysisFacts {
  const sanitizerIdentifiers = collectSanitizerIdentifiers(sourceFile);

  return {
    sanitizerIdentifiers,
    safeHtmlIdentifiers: collectSafeHtmlIdentifiers(sourceFile, sanitizerIdentifiers)
  };
}

export function findDangerouslySetInnerHtmlNodes(
  sourceFile: ts.SourceFile,
  sanitizerIdentifiers: ReadonlySet<string>,
  safeHtmlIdentifiers: ReadonlySet<string>
): DangerouslySetInnerHtmlNode[] {
  const matches: DangerouslySetInnerHtmlNode[] = [];

  visitXssNodes(sourceFile, (node) => {
    if (!ts.isJsxAttribute(node) || !ts.isIdentifier(node.name) || node.name.text !== "dangerouslySetInnerHTML") {
      return;
    }

    const severity = dangerouslySetInnerHtmlSeverity(node.initializer, sanitizerIdentifiers, safeHtmlIdentifiers);
    if (severity) {
      matches.push({ node, severity });
    }
  });

  return matches;
}

function dangerouslySetInnerHtmlSeverity(
  initializer: ts.JsxAttribute["initializer"],
  sanitizerIdentifiers: ReadonlySet<string>,
  safeHtmlIdentifiers: ReadonlySet<string>
): XssSeverity | undefined {
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

  visitXssNodes(sourceFile, (node) => {
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

  visitXssNodes(sourceFile, (node) => {
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

function isStaticHtmlExpression(expression: ts.Expression, safeHtmlIdentifiers: ReadonlySet<string>): boolean {
  return ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression) || (ts.isIdentifier(expression) && safeHtmlIdentifiers.has(expression.text));
}

function isSanitizedHtmlExpression(expression: ts.Expression, sanitizerIdentifiers: ReadonlySet<string>): boolean {
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

function visitXssNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitXssNodes(child, callback));
}
