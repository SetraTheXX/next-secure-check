# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

`next-secure-check` helps developers find common security mistakes before they reach production: leaked secrets, unsafe API routes, missing rate limits, weak configuration, XSS risks, raw SQL patterns, unsafe upload endpoints, and missing security headers.

> Current status: MVP and Phase 4.5 hardening are complete. Phase 5 is focused on demo video, portfolio polish, UI polish, and feedback from real public repository scans.

Demo video coming soon.

Started on May 9, 2026.

## Current Status

Completed:

- CLI MVP
- 20 deterministic security rules
- 192 passing tests across packages and the web demo
- Terminal, JSON, Markdown, and GitHub report formats
- GitHub Actions proof with Step Summary output
- Rule documentation in `docs/rules`
- `apps/web` web demo for scanning public GitHub repositories
- GitHub repository URL validation, metadata check, tarball download, safe extraction, cleanup, API scan endpoint, report UI, exclude toggle, and JSON/Markdown export
- Phase 4.5 web demo hardening, including repo size checks, server-side redaction, scan abuse guard, hardened security headers, and orphan temp cleanup

Current focus:

```txt
Phase 5: demo, portfolio, UI polish, and public feedback
```

The web demo scans public GitHub repositories using static analysis only. It does not run repository code, install dependencies, execute tests, or access private repositories.

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
npx next-secure-check scan . --exclude "**/*.test.ts,examples/**"
node packages/cli/dist/index.js scan . --exclude "**/*.test.ts,examples/**"
```

## CLI Config

The CLI can read a local JSON config file named `.next-secure-check.json` from the scan target root.

Supported fields:

- `excludePaths`: relative path glob patterns to ignore
- `categories`: rule categories to run
- `failOn`: minimum severity that should make the command exit with code 1
- `format`: report output format

Example:

```json
{
  "excludePaths": ["**/*.test.ts", "**/*.spec.tsx", "examples/**"],
  "categories": ["secrets", "auth", "headers"],
  "failOn": "high",
  "format": "json"
}
```

CLI flags always take priority over config values:

```txt
CLI flag > config file > default
```

For example, if the config file sets `"format": "markdown"` but the command uses `--format json`, the CLI prints JSON.

You can also point to an explicit config file:

```bash
npx next-secure-check scan . --config path/to/config.json
```

The web demo does not read `.next-secure-check.json` files from scanned repositories. Hosted/public scans use the web demo's own server-side options instead.

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
packages: 79 tests
apps/web: 113 tests
total: 192 tests
```

After building, the CLI can be run locally:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format markdown --output report.md
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format github --fail-on high
node packages/cli/dist/index.js scan . --exclude "**/*.test.ts,examples/**"
```

## Web Demo Status

The web demo lives under `apps/web`. It is a local demo for scanning public GitHub repositories, not a production-ready hosted scanning service.

Current web demo flow:

```txt
Public GitHub repo URL
-> URL validation
-> public repository metadata check
-> tarball download
-> safe tarball extraction
-> core scanner
-> server-side evidence redaction
-> cleanup
-> report UI
-> optional test/example exclusion
-> JSON / Markdown export
```

The web demo includes:

- public GitHub repository URL validation
- public repository metadata checks
- tarball download from GitHub
- safe tarball extraction with archive limits and path checks
- cleanup guarantee for extracted temporary files
- core scanner integration
- server-side evidence redaction before results reach the browser
- `POST /api/scans` backend endpoint
- UI scan flow with loading, error, and result states
- **Exclude tests and examples** toggle for cleaner production-like scans
- JSON and Markdown export actions

The web demo is intentionally limited.

It will not:

- access private repositories
- require login
- include payment
- run repository code
- run `npm install`
- run build, test, or package scripts from the scanned repository
- perform dynamic analysis

The goal is to scan public GitHub repositories using safe static analysis only. Secret-related evidence is redacted server-side for web responses and exports.

By default, the web demo can exclude test/spec files and `examples/**`:

```txt
**/*.test.ts
**/*.test.tsx
**/*.spec.ts
**/*.spec.tsx
examples/**
```

Run the local web demo:

```bash
pnpm install
pnpm build
pnpm -C apps/web dev
```

Then open the local Next.js app and enter a public GitHub repository URL.

The scan API accepts:

```http
POST /api/scans
Content-Type: application/json

{
  "repoUrl": "https://github.com/owner/repo",
  "excludePaths": ["**/*.test.ts", "examples/**"]
}
```

A real local API smoke test passed with:

```txt
https://github.com/octocat/Hello-World
```

## Security Model / Hardening

The web demo is designed for public, static scans only:

- public repositories only
- no scanned repository scripts are executed
- no dependency installation inside scanned repositories
- GitHub repository metadata and size checks before download
- safe tarball extraction with archive limits
- path traversal protection
- symlink and hardlink rejection
- duplicate archive path rejection
- server-side secret evidence redaction
- in-memory IP rate limit and global concurrency guard
- orphan temp cleanup for old scanner extraction directories

The in-memory scan guard is intended for the local/demo stage. A public multi-instance deployment should use a distributed rate limit or platform-level protection.

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

## Validation Notes

Manual validation notes:

- [Phase 4 validation](./docs/validation/phase-4-validation.md)
- [Phase 4.5 validation](./docs/validation/phase-4-5-validation.md)

## Immediate Goal

```txt
Phase 5: prepare demo video, portfolio case study, README polish, UI polish, and public feedback.
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
