# next-secure-check

## GitHub Actions Demo

The CLI is exercised in GitHub Actions as part of this repository's CI.

- The workflow runs the scanner with `--format github` and writes the markdown report to the job **Step Summary** via `$GITHUB_STEP_SUMMARY`.
- When `--fail-on high` is used, the job fails if any HIGH severity finding is reported (as demonstrated with the `examples/vulnerable-next-app` demo).
- The step order is: build → typecheck → test → security check, ensuring workspace packages are compiled before typechecking.
- The findings are deterministic pattern matches; no proof‑of‑exploit is executed.

Deterministic security checks for Next.js projects. No AI required.

`next-secure-check` helps developers find common security mistakes before they reach production: leaked secrets, unsafe API routes, missing rate limits, weak configuration, XSS risks, raw SQL patterns, and missing security headers.

> Current status: This project is in early development. The CLI MVP is functional and can scan local projects to report deterministic findings.

Started on May 9, 2026.

## Why This Exists

AI-assisted development makes it easy to ship fast and miss security basics. This project focuses on checks that are evidence-based, understandable, and useful for junior developers, freelancers, small SaaS teams, and agencies.

## Learning Project and Development Philosophy

This is a student-built learning project. I am developing it to improve my skills in TypeScript, Next.js security, static analysis, open-source project structure, testing, and product thinking.

The project is built with an AI-assisted development workflow, but the scanner itself is deterministic and does not require AI to run. Every rule is intended to be documented, tested, and designed to produce evidence-based findings rather than vague guesses.

AI helps with speed, structure, and iteration. Technical ownership, product direction, review, testing, and release decisions remain my responsibility.

## Current Rules

The scanner currently checks for 12 common security patterns. You can read more about each rule in the [docs/rules](./docs/rules) directory.

1. **[secrets/env-file-committed](./docs/rules/env-file-committed.md)**: Detects committed `.env` files.
2. **[secrets/hardcoded-secret](./docs/rules/hardcoded-secret.md)**: Detects hardcoded API keys and tokens.
3. **[secrets/weak-jwt-secret](./docs/rules/weak-jwt-secret.md)**: Detects weak or default `JWT_SECRET` values.
4. **[injection/no-eval](./docs/rules/no-eval.md)**: Detects `eval()` usage.
5. **[xss/dangerously-set-inner-html](./docs/rules/dangerously-set-inner-html.md)**: Detects raw HTML rendering in React.
6. **[config/insecure-cors-wildcard](./docs/rules/insecure-cors-wildcard.md)**: Detects wildcard CORS origins.
7. **[auth/login-without-rate-limit](./docs/rules/login-without-rate-limit.md)**: Detects login endpoints missing rate limiting.
8. **[auth/register-without-rate-limit](./docs/rules/register-without-rate-limit.md)**: Detects registration endpoints missing rate limiting.
9. **[auth/password-without-hashing-library](./docs/rules/password-without-hashing-library.md)**: Detects password handling without bcrypt/argon2.
10. **[injection/raw-sql-concat](./docs/rules/raw-sql-concat.md)**: Detects raw SQL string interpolation.
11. **[headers/missing-security-headers](./docs/rules/missing-security-headers.md)**: Detects missing security headers in Next.js config.
12. **[secrets/next-public-secret](./docs/rules/next-public-secret.md)**: Detects `NEXT_PUBLIC_` secret-like variables.

## CLI Usage

```bash
npx next-secure-check scan .
npx next-secure-check scan . --format json
npx next-secure-check scan . --format markdown --output report.md
npx next-secure-check scan . --format github
npx next-secure-check scan . --fail-on high
npx next-secure-check scan . --category secrets,auth,xss
```

## Monorepo Layout

```txt
packages/
  core/       scanner orchestration, shared types, score engine
  cli/        command line entrypoint
  rules/      built-in rule modules
  reporter/   terminal, JSON, markdown, GitHub report output
examples/
  vulnerable-next-app/
  secure-next-app/
docs/
  rules/
```

## Local Development

```bash
pnpm install
pnpm build
pnpm test
```

After building, the CLI can be run locally:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
```

## GitHub Actions

After the package is published, copy this workflow into `.github/workflows/security-check.yml` in your project:

```yaml
name: Security Check

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  next-secure-check:
    name: next-secure-check
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run security check
        shell: bash
        run: |
          set +e
          npx --yes next-secure-check@latest scan . --format github --fail-on high | tee next-secure-check-report.md
          status=${PIPESTATUS[0]}
          cat next-secure-check-report.md >> "$GITHUB_STEP_SUMMARY"
          exit "$status"
```

This fails the pull request when findings at `HIGH` or above are found. Change `--fail-on` to `medium`, `low`, or `info` if your team wants a stricter gate.

Findings are deterministic pattern matches, not proof of exploitation. Review the `confidence`, `evidence`, and `recommendation` fields before treating a finding as a confirmed vulnerability.

## Immediate Goal

```txt
Phase 2: prove the CLI inside GitHub Actions before moving to deeper rules or SaaS work.
```

## Release Gates

```txt
CLI works before web.
Tests pass before NPM release.
GitHub Action works before SaaS.
Real user feedback comes before payments.
```

## License

[MIT License](./LICENSE)
