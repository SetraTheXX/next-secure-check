# Register endpoint may be missing rate limiting

| ID | Severity | Confidence | Category |
|----|----------|------------|----------|
| auth/register-without-rate-limit | HIGH | MEDIUM | auth |

## What it detects

This rule identifies registration or signup endpoints that do not appear to implement rate limiting or abuse protection.

It looks for files with paths containing:
- `register`
- `signup`
- `sign-up`
- `create-account`

And checks if the file or project contains rate limiting signals like:
- `rateLimit`
- `rate-limit`
- `ratelimit`
- `limiter`
- `upstash`
- `slowDown`
- `throttle`

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