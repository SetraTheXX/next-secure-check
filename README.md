# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

`next-secure-check` helps developers find common security mistakes before they reach production: leaked secrets, unsafe API routes, missing rate limits, weak configuration, XSS risks, raw SQL patterns, unsafe upload endpoints, and missing security headers.

> Current status: This project is in early development. The CLI MVP is functional, GitHub Actions integration has been proven, 20 deterministic rules are documented, and the Phase 4 web demo has started with an initial `apps/web` scaffold and GitHub repository URL validation.

Started on May 9, 2026.

## Current Status

Completed:

- CLI MVP
- 20 deterministic security rules
- 70 passing tests across packages and the web demo
- Terminal, JSON, Markdown, and GitHub report formats
- GitHub Actions proof with Step Summary output
- Rule documentation in `docs/rules`
- Initial `apps/web` scaffold for the future web demo
- GitHub repository URL validation for the web demo

Current focus:

```txt
Phase 4: safe public web demo
```

The web demo will scan public GitHub repositories using static analysis only. It will not run repository code, install dependencies, execute tests, or access private repositories.

## GitHub Actions Demo

The CLI is exercised in GitHub Actions as part of this repository's CI.

- The workflow runs the scanner with `--format github` and writes the markdown report to the job **Step Summary** via `$GITHUB_STEP_SUMMARY`.
- When `--fail-on high` is used, the job fails if any HIGH severity finding is reported.
- The step order is: build → typecheck → test → security check, ensuring workspace packages are compiled before typechecking.
- The findings are deterministic pattern matches; no proof-of-exploit is executed.

## Why This Exists

AI-assisted development makes it easy to ship fast and miss security basics. This project focuses on checks that are evidence-based, understandable, and useful for junior developers, freelancers, small SaaS teams, and agencies.

## Learning Project and Development Philosophy

This is a student-built learning project. I am developing it to improve my skills in TypeScript, Next.js security, static analysis, open-source project structure, testing, and product thinking.

The project is built with an AI-assisted development workflow, but the scanner itself is deterministic and does not require AI to run. Every rule is intended to be documented, tested, and designed to produce evidence-based findings rather than vague guesses.

AI helps with speed, structure, and iteration. Technical ownership, product direction, review, testing, and release decisions remain my responsibility.

## Current Rules

The scanner currently checks for 20 common security patterns. You can read more about each rule in the [docs/rules](./docs/rules) directory.

1. **[secrets/env-file-committed](./docs/rules/env-file-committed.md)**: Detects committed `.env` files.
2. **[secrets/hardcoded-secret](./docs/rules/hardcoded-secret.md)**: Detects hardcoded API keys and tokens.
3. **[secrets/weak-jwt-secret](./docs/rules/weak-jwt-secret.md)**: Detects weak or default `JWT_SECRET` values.
4. **[injection/no-eval](./docs/rules/no-eval.md)**: Detects `eval()` usage.
5. **[injection/no-new-function](./docs/rules/no-new-function.md)**: Detects `new Function()` usage.
6. **[injection/command-exec](./docs/rules/command-exec.md)**: Detects shell command execution.
7. **[xss/dangerously-set-inner-html](./docs/rules/dangerously-set-inner-html.md)**: Detects raw HTML rendering in React.
8. **[config/insecure-cors-wildcard](./docs/rules/insecure-cors-wildcard.md)**: Detects wildcard CORS origins.
9. **[auth/login-without-rate-limit](./docs/rules/login-without-rate-limit.md)**: Detects login endpoints missing rate limiting.
10. **[auth/register-without-rate-limit](./docs/rules/register-without-rate-limit.md)**: Detects registration endpoints missing rate limiting.
11. **[auth/password-without-hashing-library](./docs/rules/password-without-hashing-library.md)**: Detects password handling without bcrypt/argon2.
12. **[injection/raw-sql-concat](./docs/rules/raw-sql-concat.md)**: Detects raw SQL string interpolation.
13. **[headers/missing-security-headers](./docs/rules/missing-security-headers.md)**: Detects missing security headers in Next.js config.
14. **[secrets/next-public-secret](./docs/rules/next-public-secret.md)**: Detects `NEXT_PUBLIC_` secret-like variables.
15. **[upload/missing-file-type-validation](./docs/rules/missing-file-type-validation.md)**: Detects upload endpoints missing file type validation.
16. **[upload/missing-file-size-limit](./docs/rules/missing-file-size-limit.md)**: Detects upload endpoints missing file size limits.
17. **[validation/api-route-without-validation](./docs/rules/api-route-without-validation.md)**: Detects API routes that may be missing input validation.
18. **[auth/admin-route-without-auth](./docs/rules/admin-route-without-auth.md)**: Detects admin routes that may be missing authentication protection.
19. **[config/production-browser-source-maps](./docs/rules/production-browser-source-maps.md)**: Detects `productionBrowserSourceMaps: true` in Next.js config.
20. **[config/next-powered-by-header](./docs/rules/next-powered-by-header.md)**: Detects missing `poweredByHeader: false` in Next.js config.

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
apps/
  web/        Phase 4 web demo app

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
pnpm typecheck
pnpm test
```

The root test command currently runs both package tests and web demo tests.

Expected current test coverage:

```txt
packages: 60 tests
apps/web: 10 tests
total: 70 tests
```

After building, the CLI can be run locally:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format markdown --output report.md
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format github --fail-on high
```

## Web Demo Status

The Phase 4 web demo has started under `apps/web`.

Current web demo progress:

- Initial Next.js app scaffold is in place.
- Public GitHub repository URL validation has started.
- Web tests are included in the root test command.

The web demo is intentionally limited.

It will not:

- access private repositories
- require login
- include payment
- run repository code
- run `npm install`
- run project tests
- perform dynamic analysis

The goal is to scan public GitHub repositories using safe static analysis only.

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
Phase 4: build a safe public web demo for scanning public GitHub repositories without executing code.
```

Current Phase 4 focus:

- keep the web demo limited to public repositories
- validate GitHub repository URLs safely
- design secure static scan ingestion
- avoid code execution, dependency installation, and test execution
- keep private repositories, login, and payment out of scope

## Release Gates

```txt
CLI works before web.
Tests pass before NPM release.
GitHub Action works before SaaS.
Real user feedback comes before payments.
```

## License

[MIT License](./LICENSE)
