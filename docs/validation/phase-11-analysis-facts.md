# Phase 11: Shared AnalysisFacts Foundation

Date: 2026-08-29

Issue: [#14](https://github.com/SetraTheXX/next-secure-check/issues/14)

## Purpose

This phase extends the existing per-source-file `AnalysisFacts` cache with a
shared, syntax-only bounded-flow vocabulary. It is a foundation for later rule
work; it does not turn the scanner into a universal taint engine and does not
change a rule's behavior by itself.

## Implemented facts

`AnalysisFacts.boundedFlow` now exposes deterministic facts collected during the
existing command-flow traversal:

- direct request-derived sources and their safe labels;
- recognized command sinks and their sink kind;
- rule-specific command allowlist guards;
- one- and two-hop identifier aliases with their bounded depth;
- reassignment, mutation, and call-escape invalidations;
- function-like nodes that form analysis boundaries;
- proven source-to-sink evidence paths and guarded sink nodes.

The existing `commandSourcePaths` and `safeCommandCalls` projections continue to
use the finalized bounded facts, so existing command findings retain their
behavior until a later rule explicitly consumes the new fields. SQL, HTML, and
command safety remain separate concepts; no universal `safe` or `sanitized`
fact was introduced.

## Boundaries preserved

- Parsing remains syntax-first and uses the existing one-parse-per-source-file
  cache lifecycle.
- The flow remains local to a source file and function scope, with at most two
  identifier alias hops.
- Reassignment, mutation, callback/call escape, function boundaries, dynamic
  properties, cross-file flow, call graphs, and type resolution remain outside
  the supported proof boundary.
- Direct command sink matching remains available when no bounded source path is
  proven.
- Malformed JavaScript, JSX, TypeScript, and TSX input is still handled without
  throwing.
- Scanned repository code is read as data only; it is not executed.

## Validation

Focused AST/fact tests cover:

- direct request source plus two aliases;
- command allowlist guard facts;
- reassignment and mutation invalidation;
- callback/call escape and function-boundary facts;
- malformed `.js`, `.jsx`, `.ts`, and `.tsx` input;
- cache identity and one-parse-per-source-file behavior.

The fixture summaries remained equal to the #13 baseline:

| Target | Preset | Score | Risk | Findings | HIGH | MEDIUM | LOW | INFO |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| `examples/vulnerable-next-app` | `strict` | `0` | `critical` | `26` | `12` | `11` | `2` | `1` |
| `examples/secure-next-app` | `app` | `99` | `excellent` | `1` | `0` | `0` | `1` | `0` |
| repository self-scan | `app` | `100` | `excellent` | `0` | `0` | `0` | `0` | `0` |

Fresh local gates:

```txt
pnpm build       -> pass
pnpm typecheck   -> pass
pnpm lint        -> pass
pnpm test        -> 326 package tests + 146 web tests = 472 total
```

The package and web tests both passed, and the baseline fixture scans preserved
finding IDs, severities, risk summaries, and counts. SARIF/report behavior is
covered by the existing package regression suite; no report contract or
fingerprint code was changed in this phase.

## Review note

These facts are review signals, not proof of exploitability. A later rule may
opt in to the shared vocabulary only after its own source/sink semantics,
fallback behavior, fixture changes, and report impact are measured.
