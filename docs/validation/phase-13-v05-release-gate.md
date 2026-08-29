# Phase 13: v0.5 Regression, Benchmark, and Release Gate

Date: 2026-08-29

Issue: [#19](https://github.com/SetraTheXX/next-secure-check/issues/19)

## Purpose

This note records the repeatable quality gate for the v0.5 bounded-analysis
line. It protects the checked-in vulnerable, secure, and self-scan behavior;
keeps public reports deterministic and private; and records a small and medium
synthetic-corpus performance envelope.

The gate reads project files as scanner input. It does not execute code from a
scanned project, clone an external repository, or require a network service.

## Commands

After the workspace has been built, the focused gate is:

```bash
pnpm release:gate
```

The complete local release validation sequence is:

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
```

CI runs the same gate after build, typecheck, lint, and package/web tests. The
implementation is [`scripts/v05-release-gate.mjs`](../../scripts/v05-release-gate.mjs).

## Frozen fixture and finding inventory

The gate checks the score, risk level, severity totals, and a deterministic
inventory keyed by `ruleId`, `context`, `severity`, and `confidence`:

| Target | Preset | Score | Risk | Findings | Inventory status |
| --- | --- | ---: | --- | ---: | --- |
| `examples/vulnerable-next-app` | `strict` | `0/100` | `critical` | 26 | unchanged: 19 inventory keys |
| `examples/secure-next-app` | `app` | `99/100` | `excellent` | 1 LOW | unchanged: 1 inventory key |
| repository self-scan | `app` | `100/100` | `excellent` | 0 | unchanged: empty |

An intentional fixture change must update the gate inventory, this validation
note, and the changelog with the reviewed reason. A changed count is not
silently accepted as a passing release result.

The surrounding regression suite covers the existing bounded command matrix,
raw SQL sources/sinks and aliases, reassignment and function-boundary stops,
parameterized SQL, XSS static/sanitized/user-controlled cases, auth and
middleware intent, and malformed configuration fallback. The earlier command
flow validation records five confirmed static-spawn noise reductions; these
are signal-quality evidence, not universal accuracy claims.

## Output contracts

The gate verifies:

- `scan --help` documents `--summary`.
- JSON plus `--summary` is rejected instead of mixing machine and human output.
- Each fixture summary stays at or below 14 output lines.
- Repeated JSON reports match after removing only volatile `scannedAt` and
  `durationMs` metadata.
- SARIF remains version `2.1.0`, with 26 vulnerable-fixture results, 19 rule
  identities, and a partial fingerprint on every result; repeated SARIF is
  deterministic after JSON parsing.
- Absolute local paths, credential-shaped tokens, and the privacy-fixture
  marker do not appear in public JSON, Markdown, GitHub, or SARIF output.
- Secret finding evidence is `[REDACTED]` in JSON, terminal, and Markdown
  output; SARIF does not embed evidence. Non-secret evidence remains available
  in detailed reports.
- `npm pack --dry-run` succeeds for the CLI package.

## Benchmark protocol and local result

The gate creates disposable source-only corpora with 100 and 1,000 TypeScript
files. It runs nine cold samples in fresh Node processes and nine warm samples
in one process. Median and p95 use nearest-rank percentile selection. Cold
scanner time excludes process startup; cold process time includes the fresh
Node worker. A same-process no-rule scan is recorded as a bounded-analysis
overhead proxy, not as a historical cross-commit syntax baseline.

Documented budgets and ratio targets:

| Corpus | Cold scanner p95 | Cold process p95 | Warm p95 | Analysis overhead | Warm scaling |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100 files | <= 2,000 ms | <= 4,000 ms | <= 2,000 ms | <= 20x | — |
| 1,000 files | <= 8,000 ms | <= 10,000 ms | <= 8,000 ms | <= 20x | <= 20x |

Local result from the validation run:

```txt
Environment: Node v24.6.0, pnpm 10.20.0, Windows 10 Home Single Language 64-bit, AMD Ryzen 5 5600
Samples: 9 cold + 9 warm per corpus
100 files: cold scanner 117.4/123.7 ms, cold process 517.7/553.2 ms, warm 76.6/103.3 ms, overhead 1.12x
1000 files: cold scanner 841.8/971.0 ms, cold process 1290.0/1409.5 ms, warm 733.1/829.2 ms, overhead 1.10x
Warm scaling ratio: 9.57x
```

These are reproducibility measurements for the documented machine and are
not universal performance guarantees. The external-repository smoke path
remains opt-in.

## Result

The gate passed locally with no fixture regression, deterministic reports and
fingerprints, redacted public evidence, valid package dry-run, and benchmark
values inside the documented budgets. Remaining intentional false-positive
and false-negative boundaries are the bounded-flow limits already described in
the v0.5 decision and Phase 12 notes; a full taint engine, cross-file flow,
call graph, and type-aware default path remain out of scope.

The GitHub release page and final v0.5 package publication remain Phase 7 /
issue #20 work and are not implied by this local gate result.
