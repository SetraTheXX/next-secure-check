# Phase 20: v0.6 Server Action and Server Function Guard Signals

Date: 2026-08-31

Issue: [#31](https://github.com/SetraTheXX/next-secure-check/issues/31)

Status: Implementation complete; release-gate validation recorded below.

## Scope

This slice adds one new, syntax-first review signal for Server Actions and
Server Functions. It recognizes direct exports in file-level `use server`
modules and functions with an inline `use server` directive, including nested
inline Server Functions whose boundary is explicit in source.

The signal requires action/request input. It reports missing authentication or
input-validation intent in the same function, lowering a partial signal to LOW
when one control is visible. Both controls suppress the signal.

## Supported evidence and guards

- direct action parameters and short local input aliases;
- request-like values such as `request.json()`, `formData.get()`, `params.id`,
  `searchParams.get()`, `headers()`, and `cookies()`;
- known auth calls and role/permission checks;
- known validation calls, `typeof` checks, static allowlists, equality checks,
  and direct normalizer guards;
- reassigned aliases are not trusted for a guard relationship;
- findings carry the function location and a bounded input `evidencePath`.

The rule has a dedicated explanation entry and rule document. Evidence remains
compatible with the existing reporter redaction, JSON/Markdown/GitHub output,
SARIF properties, and deterministic finding identity.

## Stop conditions

The analyzer does not prove runtime reachability, follow re-exports or dynamic
imports, build an auth/data-access graph, cross function boundaries, perform
type-aware taint analysis, or treat unknown wrappers as safe. Missing visible
intent is a review signal, not proof of exploitability.

## Compatibility decision

The existing v0.5 rule identities and release-gate fixture inventories remain
unchanged. v0.6 main adds only `auth/server-action-without-guards`, taking the
development rule surface from 20 to 21. The published v0.5.0 npm package still
contains its historical 20-rule surface.

See [Decision 0004](../decisions/0004-v0.6-server-action-guard-signal.md) for
the source, guard, identity, and stop-condition contract.

## Validation evidence

The focused Server Action fixtures cover file-level and inline directives,
nested inline functions, exported function variables, input-free functions,
ordinary helpers, auth-only and validation-only partial signals, both guards,
unknown wrappers, two-hop aliases, reassignment, and malformed syntax.

The full workspace validation passed:

```txt
build: passed
typecheck: passed
lint: passed
package tests: 388 passed
web tests: 147 passed
total tests: 535 passed
release gate: passed
```

The release gate also confirmed the historical vulnerable/secure/self fixture
inventories, deterministic JSON/SARIF output, privacy redaction, package dry
run, and bounded 100/1,000-file benchmark checks. The current measurements were
1.15x small-corpus analysis overhead, 1.09x medium-corpus overhead, and an
8.32x warm-corpus scaling ratio.
