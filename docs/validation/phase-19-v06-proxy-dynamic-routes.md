# Phase 19: v0.6 Proxy and Dynamic Route Boundaries

Date: 2026-08-31

Issue: [#30](https://github.com/SetraTheXX/next-secure-check/issues/30)

Status: Complete for the bounded implementation slice

## Scope

This slice extends the existing syntax-first rule pipeline to the Next.js 16
`proxy.ts` convention while retaining `middleware.ts` compatibility. It also
adds bounded evidence to the existing API input-validation rule for statically
recognizable request sources and dynamic route parameters.

The implementation does not add a new rule ID or a route graph. Existing
middleware signals continue to use same-app scope and matcher coverage for the
login, registration, and admin protection rules.

## Supported signals

- Root and app/package-scoped `proxy.ts` and `proxy.js` files are collected with
  the same scope behavior as `middleware.ts` and `middleware.js`.
- Named `proxy` functions and arrow entry points provide auth/rate-limit intent;
  unrelated helpers do not.
- Static matcher strings, string arrays, and matcher objects with a static
  `source` are accepted. Environment values, template interpolation, and other
  dynamic matcher expressions are ignored.
- Recognized API route handlers may report bounded source paths for `req.body`,
  `req.query`, `request.json()`, `request.formData()`,
  `request.nextUrl.searchParams.get()`, `searchParams.get()`, and route
  parameters such as `params.id`.
- Visible schema/type validation and static allowlists such as
  `["public"].includes(params.id)` or `ALLOWED_IDS.has(params.id)` suppress the
  existing validation review signal. A direct normalization guard is accepted
  only when its request-source relationship is visible in the same condition;
  normalization alone and unknown wrappers remain reviewable.

## Stop conditions

The slice deliberately stops at dynamic matcher resolution, cross-file and
cross-function flow, full middleware/proxy-to-route reachability, type-aware
resolution, and unknown local wrappers. A matcher or source path is context for
review; it does not prove runtime execution or exploitability.

## Validation evidence

Focused core/rules tests passed with 199 tests. The full workspace validation
then passed:

```txt
build: passed
typecheck: passed
lint: passed
package tests: 379 passed
web tests: 147 passed
total tests: 526 passed
release gate: passed
```

The release gate also passed fixture, concise-summary, help, deterministic
SARIF, privacy, package dry-run, and 100/1,000-file performance checks. The
current run measured 1.12x analysis overhead on the small corpus and 1.08x
on the medium corpus, with a 9.72x warm-corpus scaling ratio.

No existing rule ID, CLI flag, report format, or SARIF fingerprint contract was
changed. The existing 20 built-in rules remain the product surface.
