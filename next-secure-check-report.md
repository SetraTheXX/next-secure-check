# next-secure-check report

- Project: vulnerable-next-app
- Framework: nextjs
- Score: 7/100
- Risk level: critical
- Findings: 10 (HIGH 6, MEDIUM 2, LOW 2, INFO 0)

## HIGH

### Login endpoint may be missing rate limiting

- Location: `app/api/login/route.ts`
- Rule: `auth/login-without-rate-limit`
- Confidence: `MEDIUM`
- Recommendation: Add per-IP and per-account rate limiting to login/auth endpoints.

### Weak JWT secret detected

- Location: `app/api/login/route.ts:1`
- Rule: `secrets/weak-jwt-secret`
- Confidence: `HIGH`
- Evidence: `const JWT_SECRET = "secret";`
- Recommendation: Use a high-entropy secret of at least 32 bytes and rotate weak/default values.

### Possible hardcoded secret detected

- Location: `app/api/login/route.ts:2`
- Rule: `secrets/hardcoded-secret`
- Confidence: `HIGH`
- Evidence: `const stripeKey = "sk_live_demo123456789";`
- Recommendation: Remove the token from source control and rotate it immediately.

### Possible raw SQL string interpolation detected

- Location: `app/api/login/route.ts:6`
- Rule: `injection/raw-sql-concat`
- Confidence: `MEDIUM`
- Evidence: `const query = 'SELECT * FROM users WHERE email = '${body.email}'';`
- Recommendation: Use parameterized queries, prepared statements, or a safe ORM query builder.

### eval() usage detected

- Location: `app/api/login/route.ts:8`
- Rule: `injection/no-eval`
- Confidence: `HIGH`
- Evidence: `const computed = eval("1 + 1");`
- Recommendation: Replace eval() with explicit parsing or a safe interpreter for the expected input.

### Possible hardcoded secret detected

- Location: `app/api/login/route.ts:16`
- Rule: `secrets/hardcoded-secret`
- Confidence: `MEDIUM`
- Evidence: `token: "demo-token",`
- Recommendation: Move secrets to server-side environment variables and rotate any value that may have been exposed.

## MEDIUM

### Password handling without bcrypt or argon2 detected

- Location: `app/api/login/route.ts`
- Rule: `auth/password-without-hashing-library`
- Confidence: `MEDIUM`
- Recommendation: Hash passwords with argon2 or bcrypt and avoid storing or comparing plaintext passwords.

### Wildcard CORS origin detected

- Location: `app/api/login/route.ts:22`
- Rule: `config/insecure-cors-wildcard`
- Confidence: `HIGH`
- Evidence: `"Access-Control-Allow-Origin": "*",`
- Recommendation: Restrict CORS origins to trusted domains and avoid credentials with wildcard origins.

## LOW

### dangerouslySetInnerHTML usage detected

- Location: `app/profile/page.tsx:2`
- Rule: `xss/dangerously-set-inner-html`
- Confidence: `HIGH`
- Evidence: `return <main dangerouslySetInnerHTML={{ __html: "<h1>Demo profile</h1>" }} />;`
- Recommendation: Avoid raw HTML rendering or sanitize trusted markup with a proven sanitizer.

### Security headers were not detected

- Location: `package.json`
- Rule: `headers/missing-security-headers`
- Confidence: `LOW`
- Recommendation: Configure CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.