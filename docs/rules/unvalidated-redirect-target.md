# redirect/unvalidated-target

## Severity: MEDIUM

## Confidence: MEDIUM

## Category: redirect

## Description

Flags a request-derived value reaching a recognized Next.js redirect sink
without a visible internal-path, host allowlist, or same-origin guard. The
rule covers imported `redirect`/`permanentRedirect`, imported
`NextResponse.redirect`, and Pages Router `getServerSideProps` redirect
destinations.

This is a deterministic, bounded review signal—not proof of an exploitable
open redirect.

## Why This Matters

Redirect destinations that can be influenced by a request may send users to an
attacker-controlled location. That can support phishing, misleading login
flows, or other trust-boundary confusion even when the redirect code itself is
small.

## Detection Logic

The rule recognizes request-derived values from query/search/route parameters,
request URL fields, request body or JSON/form data, and visible `get()` values
from request-derived containers. Direct assignments and at most two local
aliases are followed in the same function.

Recognized sinks are:

- named `redirect` and `permanentRedirect` imports from `next/navigation`;
- `NextResponse.redirect(...)` from a named `next/server` import;
- `redirect.destination` returned by `getServerSideProps`.

The following visible forms suppress the signal: static destination equality,
static array/`Set` allowlists, a `/` check paired with rejection of `//`, and
same-origin or host/origin allowlists. A single `startsWith('/')` check,
`new URL(...)` alone, or an unknown helper such as `isSafeRedirect(...)` is not
treated as sufficient proof. A same-file helper is accepted only when its
single return expression visibly proves the internal-path or static-allowlist
predicate.

Request-derived destinations with an internal-relative static prefix are
lowered to LOW. Dynamic and external-looking destinations remain MEDIUM.

## Example

```tsx
import { redirect } from 'next/navigation'

export default function Login({ searchParams }) {
  redirect(searchParams.get('next'))
}
```

The destination is request-derived and reaches `redirect` without a
recognized guard, so the rule reports it.

```tsx
import { redirect } from 'next/navigation'

const ALLOWED_PATHS = ['/dashboard', '/settings']

export default function Login({ searchParams }) {
  const target = searchParams.get('next')
  if (!ALLOWED_PATHS.includes(target)) return null
  redirect(target)
}
```

The static allowlist is visible in the same function, so this bounded rule does
not report the redirect.

## Common False Positives

- A reverse proxy, authentication gateway, or framework adapter validates the
  destination outside the scanned file
- A custom helper performs a complete allowlist check but is not one of the
  explicitly recognized guard forms
- A value is request-derived but is constrained by deployment-specific routing
  rules that are not represented in source
- A same-function source relationship is broken by a helper or function
  boundary that the bounded analyzer intentionally does not follow

## Recommendation

Prefer a fixed internal destination. Otherwise, validate the destination as an
internal relative path while rejecting protocol-relative `//` values, or map a
short request key through a fixed allowlist. For external redirects, compare
the parsed origin/host against an explicit allowlist before calling the sink.

## Boundary

The rule does not follow cross-file or cross-function flow, dynamic properties,
unknown wrappers, `res.redirect`, client-side router navigation,
`getStaticProps`, or `next.config` redirect entries. It does not execute the
scanned project, perform network access, or claim runtime reachability.

## References

- [Next.js redirecting](https://nextjs.org/docs/app/guides/redirecting)
- [Next.js `getServerSideProps`](https://nextjs.org/docs/pages/api-reference/functions/get-server-side-props)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
