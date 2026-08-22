# auth/admin-route-without-auth

## Severity: HIGH

## Confidence: MEDIUM

## Category: auth

## Description

Admin routes should include authentication and authorization checks.

## Why This Matters

Admin and dashboard routes typically provide access to sensitive functionality: user management, data exports, configuration changes, or system-level controls. Without proper authentication, anyone can access these routes, potentially leading to data breaches, privilege escalation, or system compromise.

## Detection Logic

The rule first requires an API route path with an exported route handler, such as `app/api/admin/**/route.ts` or `pages/api/admin/**`. It then looks for a small set of structural auth-intent signals: recognized calls such as `auth()`, `getServerSession()`, `requireAuth()`, `isAdmin()`, `currentUser()`, `withAuth()`, or `middleware()`, plus access checks such as `session.role`, `session.permission`, `user.role`, or `user.permission`. Comments, string literals, and unrelated identifiers such as `const role = "admin"` do not count as auth protection.

Middleware matchers that cover the route are evaluated separately. Unknown custom wrappers remain conservative and may still be reported until they are made visible through a recognized signal.

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
