# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

`next-secure-check` helps developers find common security mistakes before they reach production: leaked secrets, unsafe API routes, missing rate limits, weak configuration, XSS risks, raw SQL patterns, unsafe upload endpoints, and missing security headers.

> Current status: v0.3.0 is published. MVP, hardening, context-aware scanning, presets, AST-assisted rule refinements, SARIF polish, and CLI helper commands are complete.

Demo video planned after the next analysis-quality milestones are stable.

See the public [roadmap](./ROADMAP.md) and the [v0.4 analysis-scope decision](./docs/decisions/0001-v0.4-analysis-scope.md) for the next development direction.

Started on May 9, 2026.

## Current Status

Completed:

- CLI MVP
- 20 deterministic security rules
- 445 passing tests across packages and the web demo
- Terminal, JSON, Markdown, GitHub, and SARIF report formats
- Context metadata on findings
- CLI preset system for app-focused, strict, CI, audit, library, and monorepo scans
- Context-aware severity/confidence tuning to reduce noisy findings in large repositories
- AST-assisted checks for command execution, raw SQL interpolation, dangerous HTML rendering, and password handling
- Bounded same-function command source-to-sink evidence paths for request-derived inputs
- Route-aware admin route detection and endpoint-aware upload validation
- Syntax-aware auth intent and API validation signals with conservative unknown-wrapper handling
- Shared `AnalysisFacts` parse cache for syntax analysis without changing finding behavior
- Middleware-aware auth/rate-limit signals for common Next.js middleware patterns
- Regression fixture suite for representative monorepo, registry, tooling, XSS, SQL, password, admin, upload, and config noise cases
- Reduced `unknown` context classifications for registry, story, demo, playground, fixture, and package UI paths
- XSS sanitizer/source refinement for `dangerouslySetInnerHTML`
- Rate-limit detection refinement for route-level and middleware-level signals
- SARIF metadata polish with help URIs, CWE/security tags, security severity, context properties, and deterministic fingerprints
- CLI `rules`, `explain`, and `init` helper commands
- GitHub Actions proof with Step Summary output
- Rule documentation in `docs/rules`
- `apps/web` web demo for scanning public GitHub repositories
- GitHub repository URL validation, metadata check, tarball download, safe extraction, cleanup, API scan endpoint, report UI, exclude toggle, and JSON/Markdown export
- Phase 4.5+ web demo hardening, including repo size checks, server-side redaction, scan abuse guard, hardened security headers, orphan temp cleanup, optional GitHub token support, and hardened client IP parsing
- Pre-publish rule coverage polish for committed `.env.*` variants and partial security header detection

Current release focus:

```txt
v0.4.x: bounded same-function source-to-sink analysis, rule-intent signals, and evidence-driven noise reduction.
```

The web demo scans public GitHub repositories using static analysis only. It does not run repository code, install dependencies, execute tests, or access private repositories.

## GitHub Actions Demo

The CLI is exercised in GitHub Actions as part of this repository's CI.

- The workflow runs the scanner with `--format github` and writes the markdown report to the job **Step Summary** via `$GITHUB_STEP_SUMMARY`.
- When `--fail-on high` is used, the job fails if any HIGH severity finding is reported.
- When `--fail-on critical` is used, the job fails only when the scan summary risk level is `critical`.
- The step order is: build -> typecheck -> test -> security check, ensuring workspace packages are compiled before typechecking.
- The findings are deterministic pattern matches; no proof-of-exploit is executed.

## Why This Exists

AI-assisted development makes it easy to ship fast and miss security basics. This project focuses on checks that are evidence-based, understandable, and useful for junior developers, freelancers, small SaaS teams, and agencies.

## Learning Project and Development Philosophy

This is a student-built learning project. I am developing it as a first-year computer programming student to improve my skills in TypeScript, Next.js security, static analysis, open-source project structure, testing, and product thinking.

The project was built with an AI-assisted workflow, including tools such as Codex, Claude, and ChatGPT for iteration, code review, testing strategy, and documentation support. The scanner itself does not use AI at runtime. It performs deterministic, rule-based static analysis.

AI helps with speed, structure, and feedback, but technical ownership, product direction, code review, testing, release decisions, and final responsibility remain mine.

I am still learning, so issues, feedback, and critical review are welcome. Findings should be treated as review signals rather than proof of exploitation, and false positives or false negatives are possible.

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

Recommended one-off usage:

```bash
npx --yes next-secure-check@latest scan . --preset app
```

For reproducible CI runs, pin the package version:

```bash
npx --yes next-secure-check@0.3.0 scan . --preset app
```

Install globally:

```bash
npm install -g next-secure-check
next-secure-check scan .
```

If an older global install is present, unversioned `npx next-secure-check` can sometimes reuse the old binary and fail on v0.3 options or helper commands such as `--preset`, `rules`, `explain`, or `init`. Check and remove the global install when needed:

```bash
next-secure-check --version
npm list -g next-secure-check
npm uninstall -g next-secure-check
npm cache verify
```

Or run without a global install:

```bash
npx --yes next-secure-check@latest scan .
npx --yes next-secure-check@latest scan . --format json
npx --yes next-secure-check@latest scan . --format markdown --output report.md
npx --yes next-secure-check@latest scan . --format github
npx --yes next-secure-check@latest scan . --format sarif --output report.sarif
npx --yes next-secure-check@latest scan . --fail-on high
npx --yes next-secure-check@latest scan . --fail-on critical
npx --yes next-secure-check@latest scan . --category secrets,auth,xss
npx --yes next-secure-check@latest scan . --exclude "**/*.test.ts,examples/**"
npx --yes next-secure-check@latest scan . --preset app
npx --yes next-secure-check@latest scan . --preset strict
npx --yes next-secure-check@latest scan . --preset ci
npx --yes next-secure-check@latest rules
npx --yes next-secure-check@latest explain xss/dangerously-set-inner-html
npx --yes next-secure-check@latest init
node packages/cli/dist/index.js scan . --exclude "**/*.test.ts,examples/**"
```

Prefer `npx --yes next-secure-check@latest` for local one-off scans, or pin `next-secure-check@0.3.0` in CI.

## CLI Helpers

List the built-in deterministic rules:

```bash
npx --yes next-secure-check@latest rules
```

Explain a single rule without opening the README:

```bash
npx --yes next-secure-check@latest explain xss/dangerously-set-inner-html
```

Create a starter config and GitHub Actions workflow:

```bash
npx --yes next-secure-check@latest init
```

`init` creates `.next-secure-check.json` and `.github/workflows/next-secure-check.yml`. Existing files are skipped by default. Use `--force` only when you intentionally want to overwrite those files:

```bash
npx --yes next-secure-check@latest init --force
```

`--fail-on critical` is a risk-level gate. It exits with code `1` only when `scan.summary.riskLevel` is `critical`. `--fail-on high`, `medium`, `low`, and `info` continue to work as severity thresholds.

## Presets

Presets adjust path coverage for common scan modes. They do not replace manual review; they help choose the right signal/noise tradeoff for the repository.

| Preset | Best for | Behavior |
| --- | --- | --- |
| `default` | General local scans | Broad baseline coverage with standard context tuning |
| `app` | Production app-code sanity checks | Excludes tests, examples, docs, generated output, and GitHub workflow/tooling paths |
| `strict` | Aggressive review | Keeps tuning off and scans broadly |
| `ci` | Pull request checks | Excludes tests and generated output while keeping CI-oriented behavior practical |
| `audit` | Broad manual review | Scans broadly with tuning off for conservative review |
| `library` | Component/library repositories | Reduces docs/examples/test/generated noise |
| `monorepo` | Multi-app workspaces | App-focused coverage for apps/packages style repositories |

## App-Focused Scans for Large Repositories

`next-secure-check` v0.3 is most useful as a quick review signal for application code. Large monorepos, template repositories, generator CLIs, release scripts, and demo/example-heavy repositories can still produce noise, but context metadata, presets, middleware signals, and AST-assisted rules make the default experience more practical.

For a production app-code-focused scan, you can start with:

```bash
npx --yes next-secure-check@latest scan . --preset app
```

Use `--preset strict` when you want the more aggressive review mode. You can still add `--exclude` patterns when a repository has project-specific generated, demo, or fixture paths. Findings are focused pre-release review signals for common mistakes.

## CLI Config

The CLI can read a local JSON config file named `.next-secure-check.json` from the scan target root.

Supported fields:

- `excludePaths`: relative path glob patterns to ignore
- `categories`: rule categories to run
- `failOn`: severity threshold, or `critical` to gate on scan summary risk level
- `format`: report output format
- `preset`: scan preset (`default`, `app`, `strict`, `ci`, `audit`, `library`, or `monorepo`)

Example:

```json
{
  "preset": "app",
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
npx --yes next-secure-check@latest scan . --config path/to/config.json
```

The web demo does not read `.next-secure-check.json` files from scanned repositories. Hosted/public scans use the web demo's own server-side options instead.

## SARIF Output

SARIF 2.1.0 output is available for tools such as GitHub Code Scanning:

```bash
npx --yes next-secure-check@latest scan . --format sarif --output report.sarif
```

The SARIF reporter includes:

- tool metadata with `informationUri`
- unique rule metadata with help URIs, tags, and selected CWE mappings
- result locations with file, line, and column when available
- `security-severity` and precision metadata
- deterministic `partialFingerprints` for more stable result tracking
- context and context reason properties for review triage
- optional bounded source-to-sink evidence paths when a command source is proven
- concise result messages built from the finding title, description, and recommendation

Raw secret evidence is not included in SARIF output.

## Monorepo Layout

```txt
apps/
  web/        local public-repository web demo app

packages/
  core/       scanner orchestration, shared types, score engine
  cli/        command line entrypoint
  rules/      built-in rule modules
  reporter/   terminal, JSON, markdown, GitHub, SARIF report output

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
packages: 302 tests
apps/web: 143 tests
total: 445 tests
```

After building, the CLI can be run locally:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format markdown --output report.md
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format github --fail-on high
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format sarif --output report.sarif
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
- tarball download from GitHub with `User-Agent: next-secure-check`
- optional `GITHUB_TOKEN` support for higher GitHub API rate limits
- safe tarball extraction with archive limits and path checks
- cleanup guarantee for extracted temporary files
- cleanup warning behavior when a scan succeeds but immediate cleanup fails
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
- optional `GITHUB_TOKEN` support for GitHub metadata and tarball requests
- `User-Agent: next-secure-check` on GitHub requests
- optional Upstash Redis REST distributed scan guard
- in-memory IP rate limit and global concurrency guard fallback
- hardened client IP resolver with platform header priority, IPv4/IPv6 validation, and oversized header fallback
- GitHub request and scan-stage timeouts with safe error responses
- orphan temp cleanup for old scanner extraction directories
- successful scan results are still returned if immediate cleanup fails, with a safe cleanup warning

The in-memory scan guard is intended for the local/single-instance demo stage. Public multi-instance or serverless deployments should configure the distributed guard or equivalent platform-level protection.

## Known Limitations

- Rules are deterministic and combine lightweight pattern matching, syntax-level AST checks, and path/context signals, so they can still produce false positives and false negatives.
- Findings are review signals, not proof of exploitation.
- Large monorepos, demo/example-heavy repositories, template repositories, and tooling-focused repositories can still produce noisy findings.
- CLI generators and release/tooling scripts may trigger command execution findings even when that behavior is intentional for the tool.
- Full type-aware analysis is intentionally deferred to a measured, opt-in spike before any default-mode adoption.
- The in-memory scan guard is only a local/single-instance fallback.
- Public deployments should use the optional Upstash/distributed guard or equivalent platform-level protection.
- IP-based limits depend on trusted proxy/platform forwarded headers.
- The web demo scans public repositories only and does not run repository code.

## GitHub Actions

Local terminal scans are manual: `next-secure-check` only runs when you execute the CLI. GitHub Actions scans are automatic after you add a workflow file to your repository; then GitHub runs the scan on the configured push or pull request events. The tool does not scan repositories on its own.

For a basic Step Summary workflow, copy this into `.github/workflows/next-secure-check.yml`:

```yaml
name: next-secure-check

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  security-check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run next-secure-check
        shell: bash
        run: |
          set -o pipefail
          npx --yes next-secure-check@0.3.0 scan . --preset app --format github --fail-on high | tee -a "$GITHUB_STEP_SUMMARY"
```

This fails the pull request when findings at `HIGH` or above are found. Change `--fail-on` to `medium`, `low`, or `info` if your team wants a stricter severity gate. Use `--fail-on critical` when you only want to fail on a `critical` scan summary risk level.

For GitHub Code Scanning, generate SARIF and upload it:

```yaml
name: next-secure-check SARIF

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run next-secure-check SARIF
        run: npx --yes next-secure-check@0.3.0 scan . --preset app --format sarif --output next-secure-check.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: next-secure-check.sarif
```

Findings are deterministic pattern matches, not proof of exploitation. Review the `confidence`, `evidence`, and `recommendation` fields before treating a finding as a confirmed vulnerability.

## Validation Notes

Manual validation notes:

- Current validation baseline: 302 package tests, 143 web tests, 445 total tests.
- [Phase 4 validation](./docs/validation/phase-4-validation.md)
- [Phase 4.5 validation](./docs/validation/phase-4-5-validation.md)
- [Phase 6 external review fixes](./docs/validation/phase-6-external-review-fixes.md)

## Future Roadmap

The detailed public plan now lives in [ROADMAP.md](./ROADMAP.md). The next release direction is deliberately narrow: improve explainable signal quality with bounded same-function analysis before considering type-aware or plugin-based expansion.

## Release Gates

```txt
CLI works before web.
Tests pass before NPM release.
GitHub Action works before SaaS.
Real user feedback comes before payments.
```

## License

[MIT License](./LICENSE)
