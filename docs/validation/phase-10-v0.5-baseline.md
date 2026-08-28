# Phase 10: v0.5 Baseline and Bounded-Flow Contract

Date: 2026-08-29

Baseline implementation: `ca2ad1dda1473074466dba0f08535358bc280625`

## Purpose

This note freezes the observable v0.4.1 behavior before the v0.5 bounded-flow
work begins. It records fixture summaries, finding identity, output contracts,
and intentional analysis boundaries. It is a review baseline, not a promise
that fixture counts can never change.

The decision behind this note is
[`0002-v0.5-bounded-flow-contract.md`](../decisions/0002-v0.5-bounded-flow-contract.md).

## Fixture summary baseline

The commands below use the checked-in fixtures and the local built CLI. The
scanner reads repository files as input; it does not execute scanned project
code.

```bash
pnpm build

node packages/cli/dist/index.js scan examples/vulnerable-next-app --preset strict --format json
node packages/cli/dist/index.js scan examples/secure-next-app --preset app --format json
node packages/cli/dist/index.js scan . --preset app --format json
```

| Target | Preset | Project metadata | Score | Risk | Total | HIGH | MEDIUM | LOW | INFO |
| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| `examples/vulnerable-next-app` | `strict` | Next.js / App Router / mixed | `0` | `critical` | `26` | `12` | `11` | `2` | `1` |
| `examples/secure-next-app` | `app` | Next.js / router unknown / JavaScript | `99` | `excellent` | `1` | `0` | `0` | `1` | `0` |
| repository self-scan | `app` | Next.js / App Router / TypeScript | `100` | `excellent` | `0` | `0` | `0` | `0` | `0` |

## Finding identity inventory

The ID format is:

```txt
`${ruleId}:${filePath}:${line ?? 0}:${column ?? 0}`
```

The following inventory intentionally records identity and review metadata
only. It does not copy source snippets, evidence strings, secret literals,
tokens, or absolute local paths.

### Vulnerable fixture: 26 findings

| # | Finding ID | Severity | Confidence | Context |
| ---: | --- | --- | --- | --- |
| 1 | `validation/api-route-without-validation:app/api/admin/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 2 | `auth/admin-route-without-auth:app/api/admin/route.ts:3:1` | HIGH | MEDIUM | api-code |
| 3 | `validation/api-route-without-validation:app/api/debug/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 4 | `injection/command-exec:app/api/debug/route.ts:1:10` | HIGH | MEDIUM | api-code |
| 5 | `injection/command-exec:app/api/debug/route.ts:9:3` | HIGH | MEDIUM | api-code |
| 6 | `injection/no-new-function:app/api/debug/route.ts:15:18` | HIGH | HIGH | api-code |
| 7 | `auth/login-without-rate-limit:app/api/login/route.ts:0:0` | HIGH | MEDIUM | api-code |
| 8 | `validation/api-route-without-validation:app/api/login/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 9 | `secrets/weak-jwt-secret:app/api/login/route.ts:1:7` | HIGH | HIGH | api-code |
| 10 | `secrets/hardcoded-secret:app/api/login/route.ts:2:20` | HIGH | HIGH | api-code |
| 11 | `injection/raw-sql-concat:app/api/login/route.ts:11:17` | HIGH | MEDIUM | api-code |
| 12 | `auth/password-without-hashing-library:app/api/login/route.ts:12:9` | MEDIUM | MEDIUM | api-code |
| 13 | `injection/no-eval:app/api/login/route.ts:13:20` | HIGH | HIGH | api-code |
| 14 | `config/insecure-cors-wildcard:app/api/login/route.ts:27:10` | MEDIUM | HIGH | api-code |
| 15 | `auth/register-without-rate-limit:app/api/register/route.ts:0:0` | HIGH | MEDIUM | api-code |
| 16 | `validation/api-route-without-validation:app/api/register/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 17 | `validation/api-route-without-validation:app/api/upload/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 18 | `upload/missing-file-size-limit:app/api/upload/route.ts:3:1` | MEDIUM | MEDIUM | api-code |
| 19 | `upload/missing-file-type-validation:app/api/upload/route.ts:3:1` | MEDIUM | MEDIUM | api-code |
| 20 | `validation/api-route-without-validation:app/api/users/route.ts:0:0` | MEDIUM | MEDIUM | api-code |
| 21 | `xss/dangerously-set-inner-html:app/profile/page.tsx:3:16` | MEDIUM | HIGH | app-code |
| 22 | `secrets/hardcoded-secret:config/secrets.ts:3:14` | HIGH | MEDIUM | unknown |
| 23 | `secrets/next-public-secret:config/secrets.ts:3:28` | HIGH | MEDIUM | unknown |
| 24 | `config/next-powered-by-header:next.config.js:0:0` | INFO | MEDIUM | unknown |
| 25 | `config/production-browser-source-maps:next.config.js:0:0` | LOW | HIGH | unknown |
| 26 | `headers/missing-security-headers:package.json:0:0` | LOW | LOW | unknown |

### Secure fixture: 1 finding

| Finding ID | Severity | Confidence | Context |
| --- | --- | --- | --- |
| `headers/missing-security-headers:package.json:0:0` | LOW | LOW | unknown |

### Self-scan

No findings were returned by the repository self-scan with `--preset app`.

## Bounded-flow coverage

The existing executable matrix is in
[`packages/rules/src/regression-fixtures.test.ts`](../../packages/rules/src/regression-fixtures.test.ts):

- 30 syntax-only command-flow fixtures;
- direct `request.json()` and `request.formData()` sources;
- `req.body`, `req.query`, `searchParams.get(...)`, and route parameters;
- direct members, assignments, one-hop and two-hop identifier aliases;
- `exec`, `execSync`, `spawn`, and `spawnSync` sinks;
- imported, namespace, and `require` sink discovery;
- JavaScript, JSX, TypeScript, TSX, App Router, and Pages Router syntax;
- unrelated object methods and static non-shell spawn as no-source/no-flow
  cases;
- reassignment, mutation, callback escape, and cross-function stop cases;
- explicit same-function allowlist guards;
- dynamic executable values and `shell: true` remaining detectable.

The current alias limit is two identifier hops. A missing `evidencePath` means
that the bounded source path was not proven; it does not mean that the sink is
safe.

## Output and determinism contract

- Detailed terminal output remains the default human-readable report.
- `--summary` is an opt-in terminal-only presentation with score, risk,
  counts, and up to three deterministically ordered findings; it omits long
  evidence/fix blocks.
- JSON remains valid machine-readable output with project, summary, findings,
  and metadata fields.
- Markdown and GitHub output retain finding identity and review metadata.
- SARIF remains version `2.1.0` with deterministic rule/result metadata and
  `partialFingerprints`.
- Findings are ordered deterministically by relative file path, location, and
  rule ID. Summary representative findings use deterministic severity/location/
  rule ordering.
- `scannedAt` and `durationMs` are volatile metadata and are excluded from
  exact-output comparisons.
- Raw secret evidence, tokens, absolute local paths, and stack traces are not
  part of this public baseline inventory.

## Performance protocol

The local environment captured for the next measurement is:

```txt
Node: v24.6.0
pnpm: 10.20.0
OS: Windows 10 x64
CPU: AMD Ryzen 5 5600 6-Core Processor
Repository: 167 tracked files, 92 JavaScript/TypeScript source files, 17 example files
```

The existing Phase 6 100-file syntax-only gate recorded directional values of
`124.9ms` cold and `115.2ms` warm. #19 must replace this single-pair signal
with repeated samples and publish:

- cold and warm median;
- cold and warm p95;
- corpus size and file mix;
- process-startup versus scanner-only timing;
- syntax-only versus bounded-flow timing and the resulting ratio.

Until then, no performance number in this note is a universal benchmark or a
release promise.

## Validation record

The #13 validation run must keep the existing gates green:

```txt
pnpm build       -> pass
pnpm typecheck   -> pass
pnpm lint        -> pass
pnpm test        -> 323 package tests + 146 web tests = 469 total
```

Fixture scans, JSON parsing, SARIF parsing, and report smoke checks are
recorded alongside this note. No scanner behavior, rule ID, CLI flag, output
format, or SARIF fingerprint is intentionally changed by #13.

## Review rule for later changes

Fixture count changes are reviewed as behavioral alarms. A later slice must
explain changed IDs, severity/confidence, context, score/risk, evidence paths,
and report compatibility. Intentional false negatives at reassignment,
mutation, callback/function boundaries, dynamic resolution, and cross-file
flow remain documented limitations until a separately measured scope expands
them.
