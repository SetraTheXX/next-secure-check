# Phase 12: Raw SQL Bounded Source-to-Sink Pilot

Date: 2026-08-29

Issue: [#15](https://github.com/SetraTheXX/next-secure-check/issues/15)

## Purpose

This phase opts `injection/raw-sql-concat` into the shared syntax-only
bounded-flow traversal. The goal is to distinguish a SQL-looking value that
reaches a recognized query sink from a SQL-looking value that is never sent to
one, while keeping the existing direct sink review signal and public finding
identity intact.

## Implemented scope

- Direct source labels cover `request.json()`, `request.formData()`,
  `req.body`, `req.query`, `searchParams.get(...)`, and route-parameter
  members such as `params.id`.
- Query sinks cover `.query(...)`, `.execute(...)`, `$queryRaw(...)`, and
  `$executeRaw(...)` calls, plus the existing `$queryRaw` and `$executeRaw`
  tagged-template forms.
- SQL template interpolation and dynamic `+` concatenation are recognized at
  the sink. SQL-valued local variables may reach the sink through at most two
  same-function identifier aliases.
- A bounded `evidencePath` is added only when the source relationship is
  visible, for example `request.json() -> email -> alias`.
- Reassignment, mutation, unknown call escape, function boundaries,
  cross-file flow, dynamic properties, and aliases beyond the two-hop limit
  stop bounded evidence propagation.
- Static SQL and placeholder-plus-array parameterized calls remain outside
  this interpolation/concatenation finding path.

The implementation reuses the existing per-source-file parse/cache lifecycle
and command-flow traversal through rule-specific callbacks. It does not add a
TypeChecker path, project graph, call graph, full CFG, unrestricted plugin
execution, or scanned-repository code execution.

## Bug fixed alongside the pilot

Direct route-parameter use such as `exec(params)` already produced a command
evidence path but did not add the corresponding source fact to
`AnalysisFacts.boundedFlow.sources`. A regression test now covers the missing
fact, and the source branch records the same direct source fact as the other
recognized sources.

## Regression coverage

Focused rule tests cover:

- direct raw SQL source-to-sink evidence;
- a SQL-valued variable and two same-function aliases;
- template interpolation and dynamic string concatenation;
- all supported request/query/search/route source labels;
- reassignment, mutation, unknown call escape, function-boundary,
  cross-function, and over-limit alias stops;
- repeated use of a SQL-valued alias across recognized query sinks;
- static SQL concatenation with fixed primitive literals;
- SQL templates without a sink;
- static and placeholder-parameterized queries;
- query-style `$queryRaw`/`$executeRaw` calls and tagged templates;
- context tuning behavior for API, app, example, template, and component
  paths.

The existing direct sink matcher remains the fallback for unproven source
paths, so the rule continues to provide a review signal without presenting an
unproven flow as exploit evidence.

## Post-merge review follow-up

The review of PR #23 found two bounded-flow edge cases that did not change the
checked-in fixture counts but could affect individual SQL expressions:

- A recognized query sink no longer invalidates the SQL-valued alias it
  consumes, so a later recognized sink can still report the same tracked value.
- Fixed primitive literals such as numeric values are treated as static parts of
  a SQL expression, avoiding a dynamic-concatenation false positive.

Unknown call escapes, reassignment, mutation, and function-boundary invalidation
remain unchanged.

## Fixture and compatibility result

The current checked-in vulnerable, secure, and self-scan fixtures retain their
baseline results:

| Target | Preset | Score | Risk | Findings | HIGH | MEDIUM | LOW | INFO |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| `examples/vulnerable-next-app` | `strict` | `0` | `critical` | `26` | `12` | `11` | `2` | `1` |
| `examples/secure-next-app` | `app` | `99` | `excellent` | `1` | `0` | `0` | `1` | `0` |
| repository self-scan | `app` | `100` | `excellent` | `0` | `0` | `0` | `0` | `0` |

Finding IDs, rule IDs, locations, context tuning, CLI flags, and report-format
contracts remain unchanged. Proven paths continue to use the existing
optional `evidencePath` field; SARIF keeps it under result properties and
retains deterministic fingerprints.

## Performance sample

Nine independent runs of the existing 100-file syntax fixture harness were
used. The p95 uses the nearest-rank method (`n=9`). These are local directional
measurements, not a universal performance claim:

| State | Median | p95 |
| --- | ---: | ---: |
| cold | `50.6 ms` | `54.7 ms` |
| warm | `51.0 ms` | `56.6 ms` |

The 1,000-file corpus, repeated release benchmark, and acceptance budget are
reserved for [#19](https://github.com/SetraTheXX/next-secure-check/issues/19).

## Gate status

The focused raw-SQL tests, package tests, web tests, typecheck, lint, build,
fixture scans, and JSON/SARIF compatibility smoke checks must remain green at
merge time. Demo GIF/tape changes are intentionally deferred until the full
v0.5 feature set and release validation are complete.

Findings remain review signals, not proof of exploitability.
