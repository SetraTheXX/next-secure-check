# Phase 21: v0.6 Unvalidated Redirect Source-to-Sink Flow

Date: 2026-08-31

Issue: [#32](https://github.com/SetraTheXX/next-secure-check/issues/32)

Status: Implementation complete; release-gate validation recorded below.

## Scope

This slice adds the development-line rule
`redirect/unvalidated-target`. It gives a bounded review signal when a
request-derived value reaches a recognized Next.js redirect sink without a
visible destination guard.

The published v0.5.0 behavior remains the frozen 20-rule baseline. This new
rule is development-line behavior until a future v0.6 release is published.

## Supported sources and sinks

- Query, search, route, request URL, body, JSON, form-data, header, and cookie
  values are recognized only through static, request-like syntax.
- Direct `redirect`/`permanentRedirect` imports from `next/navigation` and
  named `NextResponse.redirect` from `next/server` are recognized.
- Pages Router `getServerSideProps` `redirect.destination` objects are
  recognized, including shorthand local destinations.
- Same-function assignments and at most two local aliases preserve a short
  evidence path.

## Guard and stop coverage

Focused fixtures cover fixed destinations, static allowlists, safe internal
path checks, weak single-prefix checks, same-origin/host-style guard syntax,
URL normalization, internal-relative and external-looking destination shapes,
reassignment, mutation, unknown wrappers, alias depth, client components,
unrelated local helpers, App Router, Pages Router, JavaScript/TypeScript
syntax, and malformed input safety.

The analyzer stops at cross-file/cross-function flow, dynamic properties,
unsupported router/config sinks, unknown wrappers, reassignment or mutation,
and aliases beyond the bounded budget. Normalization alone does not suppress a
finding; unknown helpers are not silently trusted.

## Compatibility and privacy

The existing v0.5 rule IDs, CLI flags, report formats, finding identity,
deterministic SARIF behavior, exit-code behavior, and no-repository-code-
execution boundary are preserved. The development line now has 22 built-in
rules; the published npm line remains at 20.

Findings include only a bounded source path and static sink/context wording.
Raw URL values, secrets, tokens, absolute local paths, and stack traces are
not emitted.

## Validation evidence

The final full workspace results are recorded here after the release gate:

```txt
build: passed
typecheck: passed
lint: passed
package tests: 401 passed
web tests: 147 passed
total tests: 548 passed
release gate: passed
```

The release gate preserved the historical vulnerable/secure/self fixture
inventories, deterministic JSON/SARIF output, privacy checks, package dry-run,
and bounded performance checks. The run measured 1.37x small-corpus analysis
overhead, 1.17x medium-corpus analysis overhead, and an 8.04x warm-corpus
scaling ratio.
