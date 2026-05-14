# auth/admin-route-without-auth

## Severity: HIGH

## Confidence: MEDIUM

## Category: auth

## Description

Admin routes should include authentication and authorization checks.

## Why This Matters

Admin and dashboard routes typically provide access to sensitive functionality: user management, data exports, configuration changes, or system-level controls. Without proper authentication, anyone can access these routes, potentially leading to data breaches, privilege escalation, or system compromise.

## Detection Logic

The rule looks for files with path indicators suggesting admin, dashboard, or management functionality. If the file content does not contain any authentication or authorization patterns (e.g., `getServerSession`, `clerk`, `middleware`, `session`, `jwt.verify`, `isAdmin`), the route is flagged.

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