# NEXT_PUBLIC secret-like value requires review

| Rule ID | Severity | Confidence | Category |
|---------|----------|------------|----------|
| `secrets/next-public-secret` | HIGH | MEDIUM | secrets |

## What it detects

This rule identifies environment variables that start with the `NEXT_PUBLIC_` prefix but contain names suggesting they hold sensitive information (e.g., `SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`). The variable name is a risk signal; the rule does not prove that the assigned value is a credential.

## Why it matters

In Next.js, any environment variable prefixed with `NEXT_PUBLIC_` is automatically bundled into browser-side JavaScript. If a credential is assigned to such a variable, it may become visible to anyone visiting the site. That is why secret-like names deserve review, even though some public client tokens are intentionally exposed.

## Example

### ❌ Vulnerable

```env
# .env.local
NEXT_PUBLIC_STRIPE_SECRET=sk_live_...
NEXT_PUBLIC_AUTH_TOKEN=my-secret-token
```

### ✅ Secure

```env
# .env.local
STRIPE_SECRET=sk_live_...
AUTH_TOKEN=my-secret-token
```

### ⚠️ Intentionally public, but worth reviewing

```env
# This may be a public client identifier, not a credential.
NEXT_PUBLIC_ANALYTICS_TOKEN=public-client-id
```

The rule may still flag this example because the name looks sensitive. If the value is intentionally public, consider renaming it to make its audience clear.

## Recommendation

Review the assigned value and its intended audience. Move credentials to server-only environment variables by removing the `NEXT_PUBLIC_` prefix. Ensure server-only values are accessed only from Server Components, API Routes, or `getServerSideProps`.

## False Positives

If a variable is intentionally public despite having a name like `TOKEN` (for example, a public analytics client identifier), treat the finding as a review signal and rename the variable when practical. Do not put credentials in the value just to silence the warning.
