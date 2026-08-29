# Phase 15: Auth and Middleware Intent

Date: 2026-08-29

Issue: [#17](https://github.com/SetraTheXX/next-secure-check/issues/17)

Status: Implemented on the v0.5 development line; the published npm line
remains v0.4.1 until issue #20 is completed.

## Purpose

Reduce keyword-only assumptions in authentication, authorization, API-route,
and login/register rate-limit findings while keeping unknown wrappers
conservative. This phase remains syntax-first and does not build a full route
graph, call graph, or TypeChecker-backed resolution path.

## Behavior changes

- Login and register rules now require an App Router or Pages Router API route
  file with an exported route handler. UI pages, forms, components, comments,
  strings, and helper files are not treated as endpoints.
- Route-local rate-limit evidence is structural: recognized limiter calls,
  limiter methods, or explicit 429 responses. A variable named `rateLimit`, an
  import without a call, or a rate-limit word in a comment/string is not enough.
- Admin auth intent is inspected in every exported route-handler body. Recognized
  wrapper names and known auth-provider imports are supported; an `auth`
  binding imported from an unknown local module, an unbound/incorrectly aliased
  `auth`, an unrelated role-property read, and an unused helper remain review
  signals.
- Middleware auth and rate-limit signals ignore comments, strings, and generic
  `role`/`permission` words. Matchers continue to protect only routes in the
  same root app/package.
- App Router root routes, `src/pages/api`, and monorepo `apps/*`/`packages/*`
  router variants are covered by the route-path helpers.

Rule IDs, CLI flags, report formats, SARIF identities, and the no-repository
code-execution boundary are unchanged.

## Regression matrix

The focused fixtures cover:

| Area | Covered cases |
| --- | --- |
| Login/register | API handlers, UI paths, route-local limiter calls, limiter methods, 429 responses, unrelated files, middleware matcher coverage |
| Admin auth | App and Pages Router handlers, provider imports, recognized wrappers, role/permission properties, unused helpers, unknown local wrappers |
| API validation/upload | exported-handler gating, root App Router route, Pages Router and `src/pages` variants, helper-file exclusion |
| Middleware | same-app scope, matcher coverage, comments/strings, generic role words, known-provider auth imports, unknown local auth imports |

## Verification

The focused auth/rules/core checks pass, followed by the full workspace suite:

```text
package tests: 362
web tests: 146
total: 508
```

The local release gate also passes with the established fixture inventory:

```text
vulnerable fixture: 0/100, critical, 26 findings
secure fixture: 99/100, excellent, 1 LOW finding
self-scan: 100/100, excellent, 0 findings
```

The gate continues to validate concise-summary line limits, deterministic
JSON/SARIF, public-output privacy, CLI help/rejection behavior, package
dry-run, and the 100/1,000-file benchmark. The fixture inventory did not
change as a side effect of this phase.

The README demo was re-recorded after this phase at `1280x620`, `14.60` seconds,
and approximately `305 KB`; it uses the same three concise `--summary` scans
shown above.

## Intentional boundaries

An infrastructure WAF, an external gateway, a custom wrapper whose
implementation is not visible in the route, cross-file auth flow, middleware
reachability, dynamic imports, and type-aware role resolution may still need
manual review. These are intentional bounded-analysis limits, not proof that a
route is exploitable or safe.
