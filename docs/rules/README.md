# Rule Documentation

Each rule should document:

- Risk
- Detection strategy
- Example vulnerable code
- Recommended fix
- False-positive notes
- Confidence level

## Phase 1 Built-In Rules

- `secrets/env-file-committed`
- `secrets/hardcoded-secret`
- `secrets/weak-jwt-secret`
- `injection/no-eval`
- `xss/dangerously-set-inner-html`
- `config/insecure-cors-wildcard`
- `auth/login-without-rate-limit`
- `auth/password-without-hashing-library`
- `injection/raw-sql-concat`
- `headers/missing-security-headers`
