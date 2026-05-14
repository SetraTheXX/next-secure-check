# Rule Documentation

Each rule document should include:

- **Rule ID** — Unique identifier
- **Severity** — LOW / MEDIUM / HIGH / INFO
- **Confidence** — LOW / MEDIUM / HIGH
- **What it detects** — Description of the vulnerability pattern
- **Why it matters** — Security impact and risk explanation
- **Example** — Vulnerable and secure code examples
- **Recommendation** — How to fix the issue
- **False positive note** — Scenarios where the finding may not be actionable

## Built-In Rules

### Secrets
- `secrets/env-file-committed`
- `secrets/hardcoded-secret`
- `secrets/weak-jwt-secret`
- `secrets/next-public-secret`

### Injection
- `injection/no-eval`
- `injection/no-new-function`
- `injection/command-exec`
- `injection/raw-sql-concat`

### Authentication & Authorization
- `auth/login-without-rate-limit`
- `auth/register-without-rate-limit`
- `auth/password-without-hashing-library`
- `auth/admin-route-without-auth`

### API & Validation
- `validation/api-route-without-validation`

### Upload Security
- `upload/missing-file-type-validation`
- `upload/missing-file-size-limit`

### Cross-Site Scripting (XSS)
- `xss/dangerously-set-inner-html`

### Configuration
- `config/insecure-cors-wildcard`
- `config/production-browser-source-maps`
- `config/next-powered-by-header`

### Headers
- `headers/missing-security-headers`
