# Register endpoint may be missing rate limiting

| ID | Severity | Confidence | Category |
|----|----------|------------|----------|
| auth/register-without-rate-limit | HIGH | MEDIUM | auth |

## What it detects

This rule identifies App Router and Pages Router registration or signup route
handlers that do not appear to implement rate limiting or abuse protection.

Only files with an exported route handler are considered. A registration page,
form component, comment, string, or helper file is not an endpoint for this
rule.

It looks for exact route-handler path segments named:
- `register`
- `signup`
- `sign-up`
- `create-account`

And checks for structural route-local signals such as:
- calls to `rateLimit()`, `checkRateLimit()`, `applyRateLimit()`, or `withRateLimit()`
- limiter methods such as `limiter.limit(...)` or `ratelimit.limit(...)`
- explicit 429 responses such as `Response.json(..., { status: 429 })`, `new Response(..., { status: 429 })`, or `res.status(429)`
- a conservative same-app `middleware.ts` or Next.js 16 `proxy.ts` matcher with
  a structural limiter signal

Names in comments, strings, unused assignments, or unknown wrappers are not
treated as proof of rate limiting.

## Why it matters

Registration endpoints are high-value targets for attackers. Without rate limiting, they can be abused for:
- **Spam Account Creation**: Automating the creation of thousands of fake accounts.
- **Brute Force**: Testing lists of emails to see which ones are already registered.
- **Resource Exhaustion**: Overwhelming the database or downstream services (like email providers) with registration requests.

## Example

### Insecure

```typescript
// app/api/register/route.ts
export async function POST(req: Request) {
  const body = await req.json();
  // Directly creating user without rate limiting
  const user = await db.user.create({ data: body });
  return Response.json(user);
}
```

### Secure

```typescript
// app/api/register/route.ts
import { ratelimit } from "@/lib/ratelimit";

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") ?? "127.0.0.1";
  const { success } = await ratelimit.limit(ip);
  
  if (!success) {
    return new Response("Too Many Requests", { status: 429 });
  }

  const body = await req.json();
  const user = await db.user.create({ data: body });
  return Response.json(user);
}
```

## Recommendation

Add per-IP and abuse-aware rate limiting to registration/signup endpoints. Consider using libraries like `upstash/ratelimit` for serverless environments or standard middleware for traditional servers.

## False Positive Note

If you are using a global rate limiter or a web application firewall (WAF) that isn't visible in the source code, this rule might produce a finding. You can ignore it if you have verified that protection is in place at the infrastructure level.
