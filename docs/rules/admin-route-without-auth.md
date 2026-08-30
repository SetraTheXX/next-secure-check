# auth/admin-route-without-auth

## Severity: HIGH

## Confidence: MEDIUM

## Category: auth

## Description

Admin routes should include authentication and authorization checks.

## Why This Matters

Admin and dashboard routes typically provide access to sensitive functionality: user management, data exports, configuration changes, or system-level controls. Without proper authentication, anyone can access these routes, potentially leading to data breaches, privilege escalation, or system compromise.

## Detection Logic

The rule first requires an API route path with an exported route handler, such as `app/api/admin/**/route.ts` or `pages/api/admin/**`. It then inspects every exported handler for a small set of structural auth-intent signals: recognized calls such as `auth()` from a known provider module, `getServerSession()`, `requireAuth()`, `isAdmin()`, `currentUser()`, `withAuth()`, or `clerkMiddleware()`, plus role/permission access checks when they participate in a control condition. Comments, string literals, unused helper functions, unrelated role-property reads, and identifiers such as `const role = "admin"` do not count as auth protection.

`middleware.ts` and Next.js 16 `proxy.ts` matchers that cover the route are
evaluated separately and are scoped to the same app/package root. An
`auth`/`clerk`/`getUser` binding from a known provider module is recognized; an
unknown local wrapper remains conservative and may still be reported. The
scanner does not resolve a full auth graph or prove middleware/proxy
reachability.

## Common False Positives

- Routes protected by middleware at a higher level (e.g., edge middleware)
- Routes that are intentionally public (e.g., marketing dashboard for public stats)
- Routes using third-party auth providers that are not detected by the pattern

## Recommendation

Protect admin routes with authentication and role/permission checks before returning sensitive data.

## References

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [NextAuth.js Authentication](https://next-auth.js.org/)
- [Clerk Authentication](https://clerk.dev/)
