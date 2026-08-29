# Phase 14: XSS Source and Sanitizer Refinement

Date: 2026-08-29

Issue: [#16](https://github.com/SetraTheXX/next-secure-check/issues/16)

## Purpose

This note records the bounded refinement of
`xss/dangerously-set-inner-html`. The rule keeps JSX attribute syntax as its
first boundary, leaves variable and member-expression values visible, excludes
static HTML literals, and trusts only a small documented sanitizer allowlist.

The implementation does not execute scanned code, load project TypeScript
types, build a cross-file graph, or claim that a finding proves exploitability.
Findings remain deterministic review signals.

## Sanitizer boundary

The recognized syntax-only cases are:

- `DOMPurify.sanitize(...)`.
- direct `sanitizeHtml(...)` and `sanitizeMarkdown(...)` calls.
- default imports from `dompurify` and `sanitize-html`, including aliases used
  with `.sanitize(...)`.
- same-file `const` values derived from a recognized literal or sanitizer call.

Generic `sanitize(...)`, `sanitizeContent(...)`, `toSafeHtml(...)`, arbitrary
`wrapper.sanitize(...)`, and sanitizer-looking imports from unknown local modules
remain findings. The analyzer does not silently trust custom wrappers because
their implementation cannot be proven in the syntax-only boundary.

## Bounded source evidence

The shared `AnalysisFacts` source collection is reused for direct request-derived
expressions visible inside the `__html` value. For example, a direct
`request.json()` expression can carry `evidencePath: "request.json()"` to the
finding and supported reports. This is structural evidence only; aliases across
function boundaries, cross-file flow, mutation, and a universal sanitizer trust
model remain out of scope.

## Regression coverage

The rules suite covers:

- variable and member-expression values staying at MEDIUM severity;
- static literals, ordinary JSX text, and unrelated props staying clean;
- `DOMPurify.sanitize`, `sanitizeHtml`, `sanitizeMarkdown`, and known package
  aliases staying clean;
- six unknown wrapper forms remaining MEDIUM findings;
- direct `request.json()` evidence reaching the XSS finding;
- existing context tuning and strict/audit preset contracts remaining explicit.

## Validation evidence

The full local sequence passed:

```text
pnpm build       PASS
pnpm typecheck   PASS
pnpm lint        PASS
pnpm test        PASS — 342 package tests, 146 web tests, 488 total
```

The v0.5 release gate also passed without changing the frozen fixture
inventories:

```text
pnpm release:gate PASS
vulnerable fixture: 0/100, critical, 26 findings
secure fixture: 99/100, excellent, 1 LOW finding
self-scan: 100/100, excellent, 0 findings
```

The gate continued to validate deterministic JSON/SARIF, concise summary line
limits, public-output privacy, pack dry-run, and the small/medium benchmark
corpus. No fixture result changed as a side effect of this XSS refinement.
