# Phase 22 — v0.6 Bounded SSRF Flow (#33)

Status: Complete locally; the implementation, tests, and release gate passed on
the final working tree.

## Goal

Validate the bounded `ssrf/unvalidated-outbound-url` review signal without
turning the scanner into a network probe or a full taint engine.

## Contract

The slice covers server-oriented exported functions and route handlers where
URL-like request/query/route/form/body values reach global `fetch` or the
documented `axios`/`got` allowlist. It follows direct assignments and up to two
same-function aliases. Visible static host/origin checks, URL host validation,
private-network rejection helpers, and safe proxy helpers can suppress the
signal when their relationship is explicit.

The slice stops at `"use client"`, module scope, non-exported helpers, unknown
wrappers, dynamic properties/sinks, reassignment/mutation, unsupported request
fields, aliases beyond two hops, cross-file/cross-function source-to-sink flow,
network/DNS work, and exploit confirmation.

## Focused Coverage

- direct `request.url`, query, route, JSON, form-data, and search-param sources
- URL-like field filtering and concise evidence paths
- global `fetch`, recognized `axios`, and recognized `got` sinks
- constant URL negatives and client/shadowed-fetch negatives
- static host allowlists and visible same-file safe/private helpers
- URL parsing without validation remains reportable
- inverted private-network checks remain reportable
- reassignment, mutation, unknown wrappers, dynamic fields, helper boundaries,
  and alias-budget stops
- malformed syntax does not throw
- deterministic evidence and no raw URL value in the bounded result metadata
- scanner-level positive and safe-negative integration coverage
- CLI rule listing and `explain` coverage

## Shared-Flow Regression

The SSRF policy is attached to the existing bounded walker through a callback
contract and the cached `AnalysisFacts` path. The shared walker still records
the source facts needed by raw SQL and XSS rules; SSRF-specific known calls can
opt out of generic call-escape invalidation without changing other rule IDs or
report formats.

## Validation Commands

```bash
pnpm exec vitest run packages/rules/src/ssrf-flow.test.ts
pnpm exec vitest run packages/rules/src
pnpm exec vitest run packages/cli/src/index.test.ts
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
```

The final validation record includes the fresh package/web/total test counts,
fixture inventories, SARIF determinism, public-output privacy, pack dry-run, and
100/1,000-file benchmark results. The published v0.5.0 baseline was not silently
rewritten; no historical fixture inventory changed.

## Results

The focused SSRF suite passed with 22 tests. The complete rules source suite
passed with 248 tests and the CLI suite passed with 15 tests. The full workspace
run passed with 426 package tests, 147 web tests, and 573 total tests.

The following commands passed on the final local working tree:

```txt
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
```

The release gate preserved the historical fixture contracts: the vulnerable
fixture remained `0/100`, `critical`, with 26 findings; the secure fixture
remained `99/100`, `excellent`, with one LOW finding; and the self-scan remained
`100/100`, `excellent`, with no findings. Repeated JSON/SARIF output, public
output privacy, pack dry-run, and the existing SARIF identity checks passed.

Benchmark samples also remained inside the v0.6 contract: the 100-file corpus
reported 146.9/198.9 ms cold scanner median/p95, 88.3/138.2 ms warm median/p95,
and 1.18x analysis overhead; the 1,000-file corpus reported 990.1/2337.6 ms,
823.9/943.1 ms, and 1.13x respectively. Warm scaling was 9.33x.

## References

- [Issue #33](https://github.com/SetraTheXX/next-secure-check/issues/33)
- [Decision 0006](../decisions/0006-v0.6-ssrf-signal.md)
- [v0.6 request-boundary contract](../decisions/0003-v0.6-request-boundary-contract.md)
