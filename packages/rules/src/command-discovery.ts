import ts from "typescript";
import {
  COMMAND_EXECUTION_NAMES,
  bindingElementLocalName,
  bindingElementName,
  isChildProcessSpecifier
} from "./command-ast.js";

export type CommandDiscoveryFacts = {
  commandIdentifiers: Set<string>;
  childProcessNamespaces: Set<string>;
  commandDeclarationNodes: ts.Node[];
};

export function collectCommandDiscovery(sourceFile: ts.SourceFile): CommandDiscoveryFacts {
  const commandIdentifiers = new Set<string>();
  const childProcessNamespaces = new Set<string>();
  const commandDeclarationNodes: ts.Node[] = [];

  visitCommandDiscoveryNodes(sourceFile, (node) => {
    collectChildProcessImports(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);
    collectChildProcessRequires(node, commandIdentifiers, childProcessNamespaces, commandDeclarationNodes);
  });

  return {
    commandIdentifiers,
    childProcessNamespaces,
    commandDeclarationNodes
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

function isRequireChildProcessCall(node: ts.Node): boolean {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "require") {
    return false;
  }

  const [specifier] = node.arguments;
  return isChildProcessSpecifier(specifier);
}

function visitCommandDiscoveryNodes(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visitCommandDiscoveryNodes(child, callback));
}
