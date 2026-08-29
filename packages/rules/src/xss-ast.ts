import ts from "typescript";
import type { BoundedFlowFacts } from "./analysis-facts.js";

const SANITIZER_MODULE_PATTERN = /^(?:dompurify|sanitize-html)$/i;
const SANITIZER_FUNCTION_PATTERN = /^(?:sanitizeHtml|sanitizeMarkdown)$/i;
const SANITIZER_METHOD_NAME = "sanitize";

export type XssSeverity = "LOW" | "MEDIUM";

export type XssAnalysisFacts = {
  sanitizerIdentifiers: ReadonlySet<string>;
  untrustedSanitizerIdentifiers: ReadonlySet<string>;
  safeHtmlIdentifiers: ReadonlySet<string>;
};

export type DangerouslySetInnerHtmlNode = {
  node: ts.JsxAttribute;
  severity: XssSeverity;
  evidencePath?: string;
};

export function createXssAnalysisFacts(sourceFile: ts.SourceFile): XssAnalysisFacts {
  const { sanitizerIdentifiers, untrustedSanitizerIdentifiers } = collectSanitizerIdentifiers(sourceFile);

  return {
    sanitizerIdentifiers,
    untrustedSanitizerIdentifiers,
    safeHtmlIdentifiers: collectSafeHtmlIdentifiers(sourceFile, sanitizerIdentifiers, untrustedSanitizerIdentifiers)
  };
}

export function findDangerouslySetInnerHtmlNodes(
  sourceFile: ts.SourceFile,
  sanitizerIdentifiers: ReadonlySet<string>,
  safeHtmlIdentifiers: ReadonlySet<string>,
  boundedFlow: BoundedFlowFacts,
  untrustedSanitizerIdentifiers: ReadonlySet<string>
): DangerouslySetInnerHtmlNode[] {
  const matches: DangerouslySetInnerHtmlNode[] = [];

  visitXssNodes(sourceFile, (node) => {
    if (!ts.isJsxAttribute(node) || !ts.isIdentifier(node.name) || node.name.text !== "dangerouslySetInnerHTML") {
      return;
    }

    const severity = dangerouslySetInnerHtmlSeverity(
      node.initializer,
      sanitizerIdentifiers,
      safeHtmlIdentifiers,
      untrustedSanitizerIdentifiers
    );
    if (severity) {
      const valueExpression = dangerouslySetInnerHtmlValueExpression(node.initializer);
      const evidencePath = valueExpression ? findBoundedSourcePath(valueExpression, boundedFlow) : undefined;
      matches.push({ node, severity, ...(evidencePath ? { evidencePath } : {}) });
    }
  });

  return matches;
}

function dangerouslySetInnerHtmlSeverity(
  initializer: ts.JsxAttribute["initializer"],
  sanitizerIdentifiers: ReadonlySet<string>,
  safeHtmlIdentifiers: ReadonlySet<string>,
  untrustedSanitizerIdentifiers: ReadonlySet<string>
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

  if (
    !htmlExpression ||
    isStaticHtmlExpression(htmlExpression, safeHtmlIdentifiers) ||
    isSanitizedHtmlExpression(htmlExpression, sanitizerIdentifiers, untrustedSanitizerIdentifiers)
  ) {
    return undefined;
  }

  return "MEDIUM";
}

function collectSanitizerIdentifiers(sourceFile: ts.SourceFile): {
  sanitizerIdentifiers: Set<string>;
  untrustedSanitizerIdentifiers: Set<string>;
} {
  const sanitizerIdentifiers = new Set<string>();
  const untrustedSanitizerIdentifiers = new Set<string>();

  visitXssNodes(sourceFile, (node) => {
    if (!ts.isImportDeclaration(node) || !ts.isStringLiteralLike(node.moduleSpecifier)) {
      return;
    }

    const moduleName = node.moduleSpecifier.text;
    const isKnownSanitizerModule = SANITIZER_MODULE_PATTERN.test(moduleName);
    const importClause = node.importClause;
    if (!importClause) {
      return;
    }

    if (importClause.name && isKnownSanitizerModule) {
      sanitizerIdentifiers.add(importClause.name.text);
    } else if (importClause.name && isSanitizerFunctionName(importClause.name.text)) {
      untrustedSanitizerIdentifiers.add(importClause.name.text);
    }

    const namedBindings = importClause.namedBindings;
    if (!namedBindings || !ts.isNamedImports(namedBindings)) {
      return;
    }

    for (const importSpecifier of namedBindings.elements) {
      const localName = importSpecifier.name.text;
      const importedName = importSpecifier.propertyName?.text ?? importSpecifier.name.text;
      if (isKnownSanitizerModule && isSanitizerFunctionName(importedName)) {
        sanitizerIdentifiers.add(localName);
      } else if (!isKnownSanitizerModule && isSanitizerFunctionName(localName)) {
        untrustedSanitizerIdentifiers.add(localName);
      }
    }
  });

  return { sanitizerIdentifiers, untrustedSanitizerIdentifiers };
}

function collectSafeHtmlIdentifiers(
  sourceFile: ts.SourceFile,
  sanitizerIdentifiers: Set<string>,
  untrustedSanitizerIdentifiers: Set<string>
): Set<string> {
  const safeHtmlIdentifiers = new Set<string>();

  visitXssNodes(sourceFile, (node) => {
    if (!ts.isVariableStatement(node) || (node.declarationList.flags & ts.NodeFlags.Const) === 0) {
      return;
    }

    for (const declaration of node.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) {
        continue;
      }

      if (
        isStaticHtmlExpression(declaration.initializer, safeHtmlIdentifiers) ||
        isSanitizedHtmlExpression(declaration.initializer, sanitizerIdentifiers, untrustedSanitizerIdentifiers)
      ) {
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

function isSanitizedHtmlExpression(
  expression: ts.Expression,
  sanitizerIdentifiers: ReadonlySet<string>,
  untrustedSanitizerIdentifiers: ReadonlySet<string>
): boolean {
  if (!ts.isCallExpression(expression)) {
    return false;
  }

  if (ts.isIdentifier(expression.expression)) {
    return (
      sanitizerIdentifiers.has(expression.expression.text) ||
      (!untrustedSanitizerIdentifiers.has(expression.expression.text) && isSanitizerFunctionName(expression.expression.text))
    );
  }

  if (ts.isPropertyAccessExpression(expression.expression)) {
    const receiver = expression.expression.expression;
    return (
      expression.expression.name.text === SANITIZER_METHOD_NAME &&
      ts.isIdentifier(receiver) &&
      (receiver.text === "DOMPurify" || sanitizerIdentifiers.has(receiver.text))
    );
  }

  return false;
}

function isSanitizerFunctionName(name: string): boolean {
  return SANITIZER_FUNCTION_PATTERN.test(name);
}

function dangerouslySetInnerHtmlValueExpression(initializer: ts.JsxAttribute["initializer"]): ts.Expression | undefined {
  if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression) {
    return undefined;
  }

  if (!ts.isObjectLiteralExpression(initializer.expression)) {
    return initializer.expression;
  }

  return initializer.expression.properties
    .filter(ts.isPropertyAssignment)
    .find((property) => propertyNameText(property.name) === "__html")?.initializer;
}

function findBoundedSourcePath(expression: ts.Node, boundedFlow: BoundedFlowFacts): string | undefined {
  const directSource = boundedFlow.sources.find((source) => source.node === expression);
  if (directSource) {
    return directSource.path;
  }

  if (ts.isFunctionLike(expression)) {
    return undefined;
  }

  let evidencePath: string | undefined;
  ts.forEachChild(expression, (child) => {
    if (!evidencePath) {
      evidencePath = findBoundedSourcePath(child, boundedFlow);
    }
  });

  return evidencePath;
}

function visitXssNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitXssNodes(child, callback));
}
