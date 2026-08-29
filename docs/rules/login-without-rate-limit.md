# auth/login-without-rate-limit

## Description
Detects App Router and Pages Router authentication route handlers (for example
`/api/login`, `/api/signin`, or `/api/auth/*`) whose path contains an exact
authentication segment and that do not show a bounded rate-limit signal.

UI pages, forms, components, comments, strings, and helper files without an
exported route handler are not treated as authentication endpoints.

The rule recognizes route-local limiter calls such as `checkRateLimit()` or
`rateLimit()`, limiter methods such as `limiter.limit(...)`, and explicit 429
responses such as `Response.json(..., { status: 429 })`, `new Response(...,
{ status: 429 })`, or `res.status(429)`. A matching same-app `middleware.ts`
matcher can also provide a conservative signal. Unknown local wrappers remain
review signals because the scanner does not resolve their implementations.

## Why is this a problem?
Authentication endpoints are prime targets for brute-force and credential stuffing attacks. If an attacker can submit thousands of login requests per minute without being blocked, they have a high chance of guessing weak passwords or using leaked credentials from other breaches to compromise user accounts.

## How to fix
1. Implement rate limiting on all authentication endpoints.
2. Use a library like `@upstash/ratelimit` (with Redis) or a similar robust solution.
3. Limit requests based on the client's IP address and the targeted username/email.
4. Consider implementing account lockout mechanisms after a certain number of failed attempts.
