# auth/session-cookie-without-security-flags

- **Rule ID:** `auth/session-cookie-without-security-flags`
- **Severity:** MEDIUM (LOW when the flag state is partial or dynamic)
- **Confidence:** MEDIUM (LOW when the flag state is partial or dynamic)
- **Category:** auth

## What it detects

Flags a statically recognized auth/session-like cookie write when `httpOnly`,
`secure`, or `sameSite` is missing or cannot be proven from the local options
object. The supported forms are Next.js `cookies().set(...)`, a same-function
`await cookies()` store alias, bounded `response.cookies.set(...)` calls, and
Pages Router `res.setHeader("Set-Cookie", serialize(...))` calls.

Only cookie names that look session/auth-related are considered. Ordinary
preference cookies are not treated as authentication cookies.

## Why it matters

Session cookies should have deliberate browser and transport protections:

- `httpOnly` reduces direct JavaScript access;
- `secure` limits transmission to HTTPS;
- `sameSite` makes cross-site request behavior explicit.

The rule is a deterministic review signal, not proof of an insecure runtime
cookie or deployment configuration.

## Example

Potentially incomplete:

```ts
import { cookies } from "next/headers";

export async function POST() {
  cookies().set("session", process.env.SESSION_TOKEN);
}
```

Explicit flags:

```ts
import { cookies } from "next/headers";

export async function POST() {
  cookies().set("session", process.env.SESSION_TOKEN, {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  });
}
```

## Privacy and limitations

Finding evidence identifies only which security flags are visibly present,
missing, or dynamic; it omits cookie names, values, tokens, and option
expressions. Dynamic options, custom serializers/wrappers, dynamic cookie
names, runtime TLS/browser behavior, cross-file helpers, and unsupported
cookie APIs are not resolved. A LOW finding with dynamic flags means the
source did not provide enough static evidence; it does not claim that the
runtime value is unsafe.

## Recommendation

Set `httpOnly: true`, `secure: true`, and an intentional `sameSite` value such
as `"lax"` or `"strict"` where the application flow allows it. Review any
cross-site authentication requirement before choosing `"none"`.

## References

- [Next.js `cookies` API](https://nextjs.org/docs/app/api-reference/functions/cookies)
- [OWASP Secure Cookie Attribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
