# ssrf/unvalidated-outbound-url

## Severity: HIGH

## Confidence: MEDIUM

## Category: ssrf

## Description

Flags a request-derived, URL-like value that reaches a recognized server-side
outbound HTTP sink without a visible host allowlist, URL guard, private-network
rejection, or safe proxy helper.

This is a deterministic, bounded review signal—not proof that an SSRF exploit is
reachable or exploitable.

## Why This Matters

When a server uses attacker-influenced URL input for an outbound request, the
server may be used as a bridge to internal services, loopback endpoints, cloud
metadata endpoints, or other destinations that should not be reachable by the
caller. The actual risk depends on deployment, network policy, authentication,
and the validation performed at runtime.

## Detection Logic

The rule runs only for server-oriented function boundaries: exported functions,
default exports, named route handlers such as `GET`/`POST`, and
`getServerSideProps`. Files with a top-level `"use client"` directive are
ignored. Module-scope calls and non-exported helper functions are not treated as
server entry points.

Recognized URL-like request sources are intentionally small:

- `request.url` and `request.nextUrl.*` URL fields
- `request.json()` or `request.formData()` followed by URL-like fields
- `req.body.url`, `req.query.url`, and equivalent `body`/`query` members
- `params.url`, route-parameter fields, and `searchParams.get("url")`
- URL-like field names such as `url`, `href`, `uri`, `endpoint`, `target`,
  `destination`, `callbackUrl`, `redirectUrl`, and `webhookUrl`

The flow follows direct assignments and at most two local aliases inside the
same function. `new URL(value)` preserves the source evidence, but parsing alone
is not considered validation.

The documented outbound sink allowlist is:

- the global `fetch(...)` function
- recognized `axios(...)`, `axios.get(...)`, `got(...)`, and `.get(...)`
  bindings imported from `axios`/`got` or loaded with `require(...)`

Visible guards can suppress the signal when their relationship to the same URL
source is explicit:

- static array/`Set` host membership or equality checks
- same-file helpers whose body visibly parses a URL and checks its
  `host`/`hostname`/`origin` against a static membership/equality condition
- early-exit checks for recognized safe-URL or private-network helpers

Unknown wrappers, dynamic properties, unsupported HTTP clients, reassignment,
mutation, and aliases beyond the two-hop budget remain unproven.

## Example

```ts
export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("url");
  if (!target) return Response.json({ error: "missing url" }, { status: 400 });

  return fetch(target);
}
```

The request-derived value reaches `fetch` without a recognized destination
guard, so the rule reports it.

```ts
const ALLOWED_HOSTS = ["api.example.com"];

export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("url");
  if (!target) return Response.json({ error: "missing url" }, { status: 400 });

  if (!ALLOWED_HOSTS.includes(new URL(target).hostname)) {
    return Response.json({ error: "blocked" }, { status: 400 });
  }

  return fetch(target);
}
```

The static host allowlist is visible in the same function, so this bounded rule
does not report the flow. Runtime network controls and URL validation should
still enforce the policy independently.

## Evidence and Privacy

Findings include the outbound sink and a concise syntax path such as
`request.json() -> url -> target`. The path describes recognized source-to-sink
syntax; it does not contain runtime URL values, credentials, tokens, or absolute
local paths. The normal source-line evidence is handled by the existing reporter
redaction contract.

## Recommendation

Prefer fixed outbound destinations. If a request must select a destination,
parse and validate the URL, compare its normalized host/origin against an
explicit allowlist, reject loopback/private/link-local or otherwise forbidden
network ranges, and apply network egress controls. Keep proxy helpers and
destination maps narrow and reviewable.

## Boundary

The rule does not make network requests, resolve DNS, probe SSRF payloads, run
scanned code, or confirm exploitability. It does not build a cross-file or
cross-function taint graph, full URL semantics, call graph, CFG, or type-aware
model. It does not discover arbitrary HTTP clients, follow dynamic dispatch,
inspect every request header/cookie field, or trust unknown wrappers. A clean
result is not a complete SSRF assessment.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
