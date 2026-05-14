# NEXT_PUBLIC secret-like variable detected

| Rule ID | Severity | Confidence | Category |
|---------|----------|------------|----------|
| `secrets/next-public-secret` | HIGH | MEDIUM | secrets |

## What it detects

This rule identifies environment variables that start with the `NEXT_PUBLIC_` prefix but contain names suggesting they hold sensitive information (e.g., `SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`).

## Why it matters

In Next.js, any environment variable prefixed with `NEXT_PUBLIC_` is automatically bundled into the browser-side JavaScript. If a secret value is assigned to such a variable, it becomes visible to anyone visiting the site, leading to potential credential theft or unauthorized API access.

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

## Recommendation

Move secret values to server-only environment variables by removing the `NEXT_PUBLIC_` prefix. Ensure these values are only accessed in Server Components, API Routes, or `getServerSideProps`.

## False Positives

If a variable is intentionally public despite having a name like "TOKEN" (e.g., a public analytics token), you can ignore this warning. However, it is generally better to use more descriptive names for public tokens to avoid confusion.