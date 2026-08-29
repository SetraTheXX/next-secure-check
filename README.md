# next-secure-check

Deterministic, Next.js-focused static security checks for pre-deploy review and CI.

next-secure-check scans a local project and reports common security mistakes before they become production surprises. It uses rule-based pattern matching, syntax-level AST analysis, and file context. It does not execute repository code and does not use AI at runtime.

> **Stable release:** `v0.4.1` is published on npm. The `v0.5.0` release candidate is prepared on `main`; its npm publication is a manual follow-up. v0.5 adds bounded source-to-sink evidence, structural auth intent, explainable reports, and a concise terminal summary.

[![npm](https://img.shields.io/npm/v/next-secure-check?logo=npm)](https://www.npmjs.com/package/next-secure-check)
[![CI](https://github.com/SetraTheXX/next-secure-check/actions/workflows/security-check.yml/badge.svg)](https://github.com/SetraTheXX/next-secure-check/actions/workflows/security-check.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

<p align="center">
  <img src="./docs/assets/next-secure-check-banner.svg" alt="next-secure-check — deterministic security checks for Next.js" width="100%">
</p>

## Why use it?

- Run a quick security sanity check with one `npx` command.
- Get deterministic findings with severity, confidence, location, context, bounded evidence paths, and recommendations.
- Use the same scanner locally, in GitHub Actions, or through SARIF-compatible Code Scanning workflows.

It is a lightweight pre-release review signal, not a penetration test or a replacement for a full security audit.

## See It in Action

<p align="center">
  <img src="./docs/assets/readme-security-demo.gif" alt="Terminal demo comparing vulnerable, secure, and self-scan fixture results" width="100%">
</p>

The demo is generated from the checked-in fixtures with [`docs/demo/next-secure-check.tape`](./docs/demo/next-secure-check.tape). It shows the prepared `v0.5.0` CLI and three concise `--summary` scans; the full finding report is intentionally omitted for readability. It shows a review signal, not proof of exploitability or a universal security score.

## Quick Start

Run the recommended application-focused scan without a global install:

~~~bash
npx --yes next-secure-check@latest scan . --preset app
~~~

For reproducible CI on the stable npm line, pin the CLI version:

~~~bash
npx --yes next-secure-check@0.4.1 scan . --preset app
~~~

After the manual v0.5.0 npm publication, the prepared release can be pinned
with:

~~~bash
npx --yes next-secure-check@0.5.0 scan . --preset app
~~~

The CLI requires Node.js 20 or newer.

### Global install

~~~bash
npm install -g next-secure-check
next-secure-check scan . --preset app
~~~

If an older global installation shadows the current CLI, check and remove it:

~~~bash
next-secure-check --version
npm list -g next-secure-check
npm uninstall -g next-secure-check
npm cache verify
~~~

Using a versioned `npx` command avoids that class of conflict.

## What It Checks

The scanner currently contains 20 built-in rules across secrets, injection, XSS, authentication, validation, uploads, headers, and Next.js configuration.

| Area | Checks |
| --- | --- |
| Secrets | [Committed `.env` files](./docs/rules/env-file-committed.md), [hardcoded secrets](./docs/rules/hardcoded-secret.md), [weak JWT secrets](./docs/rules/weak-jwt-secret.md), [public secret-like names](./docs/rules/next-public-secret.md) |
| Injection | [`eval`](./docs/rules/no-eval.md), [`new Function`](./docs/rules/no-new-function.md), [command execution](./docs/rules/command-exec.md), [raw SQL interpolation](./docs/rules/raw-sql-concat.md) |
| XSS | [`dangerouslySetInnerHTML`](./docs/rules/dangerously-set-inner-html.md) |
| Authentication | [Login rate limits](./docs/rules/login-without-rate-limit.md), [registration rate limits](./docs/rules/register-without-rate-limit.md), [password hashing](./docs/rules/password-without-hashing-library.md), [admin route protection](./docs/rules/admin-route-without-auth.md) |
| Validation and uploads | [API input validation](./docs/rules/api-route-without-validation.md), [file type validation](./docs/rules/missing-file-type-validation.md), [file size limits](./docs/rules/missing-file-size-limit.md) |
| Headers and configuration | [Missing security headers](./docs/rules/missing-security-headers.md), [wildcard CORS](./docs/rules/insecure-cors-wildcard.md), [Next.js powered-by header](./docs/rules/next-powered-by-header.md), [production browser source maps](./docs/rules/production-browser-source-maps.md) |

See [`docs/rules`](./docs/rules) for the complete rule documentation, examples, and known limitations.

The XSS rule documents its intentionally small sanitizer allowlist and bounded
request-source evidence in [`dangerously-set-inner-html.md`](./docs/rules/dangerously-set-inner-html.md).

Authentication and validation rules use structural route-handler signals. UI
pages, comments, strings, unused helpers, and unknown local auth/limiter
wrappers remain reviewable instead of being silently treated as protected.
See the [Phase 15 validation note](./docs/validation/phase-15-auth-middleware.md)
for the App Router, Pages Router, and same-app middleware contract.

## CLI Usage

### Scan and report formats

~~~bash
# Terminal output
npx --yes next-secure-check@latest scan .

# JSON report
npx --yes next-secure-check@latest scan . --format json

# Markdown report
npx --yes next-secure-check@latest scan . --format markdown --output report.md

# GitHub Actions Step Summary
npx --yes next-secure-check@latest scan . --format github

# SARIF for GitHub Code Scanning
npx --yes next-secure-check@latest scan . --format sarif --output report.sarif

# Concise terminal summary (v0.5.0 release candidate)
pnpm build
node packages/cli/dist/index.js scan . --preset app --summary

# Scan command help (v0.5.0 release candidate)
node packages/cli/dist/index.js scan --help
~~~

`--summary` is an opt-in terminal view for quick reviews and demos. It keeps the score, risk, finding counts, severity, confidence, context, and location visible while omitting the longer evidence and fix blocks. The default terminal report remains detailed, and `--summary` cannot be combined with JSON, Markdown, GitHub, or SARIF output. It is part of the prepared v0.5.0 release candidate; the published npm `latest` line remains `v0.4.1` until the manual v0.5 publication is complete.

### Failure gates

~~~bash
npx --yes next-secure-check@latest scan . --fail-on high
npx --yes next-secure-check@latest scan . --fail-on critical
~~~

`--fail-on high`, `medium`, `low`, and `info` act as severity thresholds. `--fail-on critical` is a risk-level gate: it exits with code `1` only when the scan summary risk level is `critical`.

### CLI helpers

List the built-in rules, explain a rule, or create starter project files:

~~~bash
npx --yes next-secure-check@latest rules
npx --yes next-secure-check@latest explain xss/dangerously-set-inner-html
npx --yes next-secure-check@latest init
~~~

`init` creates `.next-secure-check.json` and `.github/workflows/next-secure-check.yml`. Existing files are skipped by default; use `--force` only when you intentionally want to overwrite them.

`explain` also documents the review boundary for each built-in rule. Its output
includes false-positive notes and false-negative boundaries, including the
intentional limits of same-function bounded flow, short alias chains, dynamic
resolution, and external middleware or infrastructure controls.

## Presets

Presets choose a practical coverage and noise tradeoff. They do not replace manual review.

| Preset | Intended use | Behavior |
| --- | --- | --- |
| `default` | General local scans | Broad baseline coverage with standard context tuning |
| `app` | Production app-code checks | Excludes tests, examples, docs, generated output, and GitHub workflow/tooling paths |
| `strict` | Aggressive review | Scans broadly with tuning disabled |
| `ci` | Pull request checks | Excludes tests and generated output while keeping CI practical |
| `audit` | Broad manual review | Scans broadly with tuning disabled |
| `library` | Component/library repositories | Reduces docs, examples, test, and generated-output noise |
| `monorepo` | Multi-app workspaces | App-focused coverage for `apps/` and `packages/` layouts |

For most Next.js applications, start with `--preset app`. Use `--preset strict` when you want a broader review, including tooling and example paths.

### Large repositories and monorepos

Large monorepos, template repositories, generator CLIs, release scripts, and demo-heavy repositories can still produce noisy findings. Context metadata, presets, bounded source-to-sink evidence, and AST-assisted checks reduce that noise but do not eliminate it.

For a production app-focused scan:

~~~bash
npx --yes next-secure-check@latest scan . --preset app
~~~

Project-specific exclusions can be added when needed:

~~~bash
npx --yes next-secure-check@latest scan . \
  --exclude "**/*.test.ts,**/*.spec.ts,**/*.test.tsx,.github/**,examples/**"
~~~

## Configuration

The CLI reads `.next-secure-check.json` from the scan target root. Use `--config path/to/config.json` to provide an explicit file.

Supported fields in the current release:

- `excludePaths`: relative path glob patterns to ignore
- `categories`: rule categories to run
- `failOn`: `low`, `medium`, `high`, `critical`, or `info`
- `format`: `terminal`, `json`, `markdown`, or `github`
- `preset`: `default`, `app`, `strict`, `ci`, `audit`, `library`, or `monorepo`

`--summary` is a CLI-only display option. It is intentionally not read from the configuration file and applies only to terminal output. It is available in the prepared v0.5.0 release candidate and is not part of published npm `v0.4.1`.

Example:

~~~json
{
  "preset": "app",
  "excludePaths": ["**/*.test.ts", "**/*.spec.tsx", "examples/**"],
  "categories": ["secrets", "auth", "headers"],
  "failOn": "high",
  "format": "json"
}
~~~

Precedence is:

~~~txt
CLI flag > config file > default
~~~

The web demo does not read config files from scanned repositories. Its public-repository scan options are controlled server-side.

## Findings and SARIF

Findings include a rule ID, title, severity, confidence, file location, context,
an explanation of why the pattern was reported, and a recommendation. When the
syntax proves a bounded source-to-sink path, the finding also carries a concise
`evidencePath` such as `request.json() -> query`. That path is evidence of the
recognized syntax only; it is not proof that an exploit exists.

SARIF 2.1.0 output includes:

- tool metadata and `informationUri`
- rule help URIs, tags, and selected CWE mappings
- file, line, and column locations when available
- `security-severity` and precision metadata
- deterministic `partialFingerprints`
- context and context-reason properties
- `whyReported` and optional `evidencePath` result properties
- concise messages built from the title, description, and recommendation

Detailed terminal and Markdown reports show `Why`, `Context reason`, and an
optional `Evidence path`. GitHub keeps its findings table compact and places
the same explanation metadata in its recommendations details; it intentionally
omits raw evidence. The web Markdown export follows the same explanation
contract. Raw secret evidence is replaced with `[REDACTED]` in JSON, terminal,
and Markdown output and is not embedded in SARIF. Findings are review signals,
not proof that an exploit exists; review the confidence, evidence path, and
recommendation before treating one as a confirmed vulnerability.

## Reproducible Demo

The repository contains deliberately unsafe and mostly secure fixtures so the scanner can be checked without cloning an external project:

~~~bash
pnpm build

node packages/cli/dist/index.js scan examples/vulnerable-next-app --preset strict --summary
node packages/cli/dist/index.js scan examples/secure-next-app --preset app --summary
node packages/cli/dist/index.js scan . --preset app --summary
~~~

Expected fixture summaries:

| Target | Expected result |
| --- | --- |
| `vulnerable-next-app` with `strict` | `0/100`, `critical`, 26 findings (`12 HIGH`, `11 MEDIUM`, `2 LOW`, `1 INFO`) |
| `secure-next-app` with `app` | `99/100`, `excellent`, 1 LOW finding |
| repository self-scan with `app` | `100/100`, `excellent`, 0 findings |

These are regression-fixture expectations, not universal accuracy or risk guarantees.

Run the complete local v0.5 regression and performance gate after building:

~~~bash
pnpm release:gate
~~~

The gate checks fixture inventories, deterministic JSON/SARIF output, concise
summary length, public-output privacy, CLI packaging, and disposable 100/1,000
file benchmark corpora. See the [Phase 13 validation note](./docs/validation/phase-13-v05-release-gate.md)
for the protocol and the [Phase 17 release validation note](./docs/validation/phase-17-v05-release.md)
for the current release-candidate audit.

## GitHub Actions

Local scans are manual. After you add a workflow, GitHub runs it on the configured push or pull request events; `next-secure-check` does not scan repositories on its own.

### Step Summary

Copy this into `.github/workflows/next-secure-check.yml`:

~~~yaml
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
      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: 20

      - name: Run next-secure-check
        shell: bash
        run: |
          set -o pipefail
          npx --yes next-secure-check@0.4.1 scan . --preset app --format github --fail-on high | tee -a "$GITHUB_STEP_SUMMARY"
~~~

This fails the job when a `HIGH` or more severe finding is reported. Use `--fail-on critical` when the job should fail only for a `critical` scan risk level.

### Reusable GitHub Action

After the first `v1` Action release, projects can use the reusable composite Action as a single workflow step:

~~~yaml
- uses: SetraTheXX/next-secure-check@v1
  with:
    preset: app
    fail-on: high
    format: github
~~~

The published `v1` Action currently runs the stable `next-secure-check@0.4.1`
CLI against the checked-out workspace. It does not install or execute scripts
from the scanned repository. The default `github` format is written to the job
Step Summary; use `format: sarif` and `output: next-secure-check.sarif` when a
separate SARIF upload step is desired. A coordinated Action update to the
v0.5.0 CLI follows the manual npm publication so the existing `v1` tag never
points at an unavailable package.

The Action runs only when the consuming repository adds it to a workflow triggered by events such as `pull_request` or `push`. It does not monitor repositories on its own.

### SARIF and GitHub Code Scanning

~~~yaml
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
      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: 20

      - name: Run next-secure-check SARIF
        run: npx --yes next-secure-check@0.4.1 scan . --preset app --format sarif --output next-secure-check.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: next-secure-check.sarif
~~~

## Web Demo

The web demo under [`apps/web`](./apps/web) is a local public-repository scanning flow, not a hosted production service.

~~~txt
Public GitHub URL
-> URL and metadata validation
-> tarball download
-> safe extraction
-> static scan
-> server-side evidence redaction
-> cleanup
-> report UI and JSON/Markdown export
~~~

The demo:

- scans public GitHub repositories only
- does not run repository code, install dependencies, or execute scripts
- rejects unsafe archive paths and links
- applies repository size, request, concurrency, and timeout limits
- supports an optional `GITHUB_TOKEN` for GitHub requests
- supports optional Upstash Redis protection for multi-instance deployments
- redacts secret-related evidence server-side
- can exclude tests and examples for a production-like scan

Run it locally:

~~~bash
pnpm install
pnpm build
pnpm -C apps/web dev
~~~

The web demo is intentionally not presented as a public hosted scanning service. Its in-memory abuse guard is suitable for local or single-instance use; public multi-instance deployments need distributed protection or equivalent platform controls.

## Security Model and Limitations

The scanner is designed to provide fast, explainable review signals. It is not a full security audit, penetration test, exploit verifier, or cross-file/type-aware taint engine.

- Rules combine deterministic patterns, syntax-level AST checks, and path/context signals.
- False positives and false negatives are possible, especially around custom wrappers, dynamic code, and large tooling-heavy repositories.
- Command execution in a CLI or release tool may be intentional and still require manual review.
- Type-aware analysis, cross-file/interprocedural flow, and full route graphs are not part of the default scan path.
- The web demo scans public repositories only and never executes scanned code.
- Public hosted web deployments should use distributed abuse protection.
- IP-based limits require a trusted proxy or platform header configuration.

## Project Status and Roadmap

The current stable published line is `v0.4.1`; the `v0.5.0` release candidate
is prepared on `main` and awaits manual npm publication, an exact GitHub tag,
and post-release feedback. The detailed, checklist-based plan lives in
[`ROADMAP.md`](./ROADMAP.md).

The current direction is deliberately narrow: improve evidence quality and reduce guesses with bounded, explainable analysis before considering default type-aware analysis or an unrestricted plugin system.

For release history, see [`CHANGELOG.md`](./CHANGELOG.md). Historical validation notes remain under [`docs/validation`](./docs/validation).

## Local Development

~~~bash
pnpm install
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
~~~

The current validation baseline is:

~~~txt
packages: 366 tests
apps/web: 147 tests
total: 513 tests
~~~

Workspace layout:

~~~txt
apps/web/       local public-repository web demo
packages/core/  scanner orchestration, shared types, score engine
packages/cli/   command-line entrypoint
packages/rules/ built-in rule modules and AST utilities
packages/reporter terminal, JSON, Markdown, GitHub, and SARIF output
examples/       vulnerable and secure fixtures
docs/rules/     rule documentation
~~~

Useful validation references:

- [v0.4 analysis scope decision](./docs/decisions/0001-v0.4-analysis-scope.md)
- [bounded-flow validation](./docs/validation/phase-6-bounded-flow.md)
- [vulnerable/secure demo validation](./docs/validation/phase-8-demo.md)
- [concise terminal summary validation](./docs/validation/phase-9-summary-output.md)
- [v0.5 baseline and bounded-flow contract](./docs/decisions/0002-v0.5-bounded-flow-contract.md)
- [v0.5 baseline validation inventory](./docs/validation/phase-10-v0.5-baseline.md)
- [v0.5 shared AnalysisFacts validation](./docs/validation/phase-11-analysis-facts.md)
- [v0.5 XSS source and sanitizer refinement](./docs/validation/phase-14-xss-refinement.md)
- [v0.5 auth and middleware intent](./docs/validation/phase-15-auth-middleware.md)
- [v0.5 regression and performance release gate](./docs/validation/phase-13-v05-release-gate.md)
- [v0.5 release-candidate audit and manual publish handoff](./docs/validation/phase-17-v05-release.md)

## Learning Project and Development Philosophy

This is a student-built learning project focused on TypeScript, Next.js security, static analysis, testing, and open-source engineering.

The development process uses an AI-assisted workflow, including Codex, Claude, and ChatGPT for iteration, review, testing strategy, and documentation support. The scanner itself does not use AI at runtime: its checks are deterministic and rule-based.

Technical ownership, product direction, code review, testing, release decisions, and final responsibility remain with the developer. Feedback, issues, and critical review are welcome. Findings should be treated as review signals rather than proof of exploitation.

## Contributing and Security

- Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before opening an issue or pull request.
- Use the issue templates for bugs, false positives, false negatives, and feature requests.
- Never include real secrets, tokens, private repository contents, or customer data in public issues.
- See [`SECURITY.md`](./SECURITY.md) for responsible disclosure guidance.

## License

[MIT License](./LICENSE)
