# Phase 23 — v0.6 Cookie and Next.js Configuration Hardening (#34)

Date: 2026-08-31

Issue: [#34](https://github.com/SetraTheXX/next-secure-check/issues/34)

Status: Implementation complete; focused tests, full workspace validation, and
the v0.5 release gate passed on the final local working tree.

## Goal

Improve common session-cookie and Next.js configuration review signals without
turning static syntax into a universal claim about runtime security.

## Bounded coverage

- `auth/session-cookie-without-security-flags` recognizes auth/session-like
  cookie names and visible `httpOnly`, `secure`, and `sameSite` states.
- Supported cookie forms include direct `cookies().set(...)`, same-function
  `await cookies()` aliases, bounded `response.cookies.set(...)`, and the
  limited Pages Router `res.setHeader("Set-Cookie", serialize(...))` shape.
- Cookie evidence reports only visible, missing, or dynamic flag names. Cookie
  names, values, tokens, credentials, and option expressions are omitted.
- `headers/missing-security-headers` recognizes static security-header names in
  supported `next.config.cjs/.js/.mjs/.ts` `headers()` patterns and named
  `middleware`/`proxy` response header setters.
- `config/next-image-domains` flags non-empty static `images.domains` arrays;
  `remotePatterns`, dynamic values, empty arrays, and unrelated objects are
  safe negatives.
- Tests cover safe, incomplete, partial, dynamic, client, alias-boundary,
  App Router, Pages Router, JavaScript, TypeScript, CommonJS config, malformed
  syntax handling, and CLI explanations.

The slice stops at custom wrappers/serializers, dynamic names and values,
cross-file/cross-function flow, complete CSP proof, reverse-proxy or hosting
headers, runtime TLS/browser behavior, and exploit confirmation.

## Validation commands

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
```

Focused red-green checks also covered the new rules and CommonJS file
collection before the full run.

## Results

```txt
build: passed
typecheck: passed
lint: passed
package tests: 453 passed
web tests: 147 passed
total tests: 600 passed
release gate: passed
```

The release gate preserved the historical fixture contracts:

```txt
self/app: 100/100, excellent, 0 findings
secure/app: 99/100, excellent, 1 LOW finding
vulnerable/strict: 0/100, critical, 26 findings
```

It also passed repeated JSON/SARIF determinism, public-output privacy,
summary/help compatibility, CLI pack dry-run, and the bounded performance
checks. The measured analysis overhead was 1.20x for the 100-file corpus and
1.12x for the 1,000-file corpus; warm-corpus scaling was 9.15x.

The published v0.5.0 packages and the v1.1.0 Action were not republished or
retagged. The two #34 rules are available only from the unreleased v0.6
development line until the separate #35 release-quality gate and feedback
decision.

## References

- [Issue #34](https://github.com/SetraTheXX/next-secure-check/issues/34)
- [Decision 0007](../decisions/0007-v0.6-config-hardening-signals.md)
- [v0.6 request-boundary contract](../decisions/0003-v0.6-request-boundary-contract.md)
