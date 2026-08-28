import ts from "typescript";

export type BoundedFlowSourceFact = {
  readonly node: ts.Node;
  readonly path: string;
  readonly scope: ts.Node;
};

export type BoundedFlowSinkFact = {
  readonly node: ts.CallExpression;
  readonly scope: ts.Node;
  readonly kind?: string;
};

export type BoundedFlowGuardFact = {
  readonly node: ts.CallExpression;
  readonly scope: ts.Node;
  readonly kind: string;
  readonly identifier?: string;
};

export type BoundedFlowAliasFact = {
  readonly node: ts.VariableDeclaration | ts.BinaryExpression;
  readonly scope: ts.Node;
  readonly from: string;
  readonly to: string;
  readonly depth: number;
  readonly path?: string;
};

export type BoundedFlowInvalidationReason = "reassignment" | "mutation" | "call-escape";

export type BoundedFlowInvalidationFact = {
  readonly node: ts.Node;
  readonly scope: ts.Node;
  readonly identifier: string;
  readonly reason: BoundedFlowInvalidationReason;
};

export type BoundedFlowFunctionBoundaryFact = {
  readonly node: ts.Node;
};

export type BoundedFlowEvidencePathFact = {
  readonly sink: ts.Node;
  readonly path: string;
};

export type BoundedFlowFacts = {
  readonly sources: readonly BoundedFlowSourceFact[];
  readonly sinks: readonly BoundedFlowSinkFact[];
  readonly guards: readonly BoundedFlowGuardFact[];
  readonly aliases: readonly BoundedFlowAliasFact[];
  readonly invalidations: readonly BoundedFlowInvalidationFact[];
  readonly functionBoundaries: readonly BoundedFlowFunctionBoundaryFact[];
  readonly evidencePaths: ReadonlyMap<ts.Node, string>;
  readonly guardedSinks: ReadonlySet<ts.CallExpression>;
};

export type BoundedFlowFactsBuilder = {
  readonly sourceFacts: Map<ts.Node, BoundedFlowSourceFact>;
  readonly sinkFacts: Map<ts.CallExpression, BoundedFlowSinkFact>;
  readonly guardFacts: Map<ts.CallExpression, BoundedFlowGuardFact>;
  readonly aliasFacts: BoundedFlowAliasFact[];
  readonly invalidationFacts: BoundedFlowInvalidationFact[];
  readonly functionBoundaryFacts: BoundedFlowFunctionBoundaryFact[];
  readonly evidencePaths: Map<ts.Node, string>;
  readonly guardedSinks: Set<ts.CallExpression>;
};

export function createBoundedFlowFactsBuilder(): BoundedFlowFactsBuilder {
  return {
    sourceFacts: new Map(),
    sinkFacts: new Map(),
    guardFacts: new Map(),
    aliasFacts: [],
    invalidationFacts: [],
    functionBoundaryFacts: [],
    evidencePaths: new Map(),
    guardedSinks: new Set()
  };
}

export function finalizeBoundedFlowFacts(builder: BoundedFlowFactsBuilder): BoundedFlowFacts {
  const invalidations = new Map<string, BoundedFlowInvalidationFact>();
  for (const invalidation of builder.invalidationFacts) {
    invalidations.set(
      `${invalidation.node.pos}:${invalidation.node.end}:${invalidation.identifier}:${invalidation.reason}`,
      invalidation
    );
  }

  return {
    sources: Object.freeze([...builder.sourceFacts.values()]),
    sinks: Object.freeze([...builder.sinkFacts.values()]),
    guards: Object.freeze([...builder.guardFacts.values()]),
    aliases: Object.freeze([...builder.aliasFacts]),
    invalidations: Object.freeze([...invalidations.values()]),
    functionBoundaries: Object.freeze([...builder.functionBoundaryFacts]),
    evidencePaths: new Map(builder.evidencePaths),
    guardedSinks: new Set(builder.guardedSinks)
  };
}
