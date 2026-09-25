# SecureCheck

**AI wrote your Next.js app. Who checks the AI?**

A deterministic security baseline for AI-generated and human-written Next.js code. No AI required at runtime.

`next-secure-check` remains the npm package and CLI name. This `v0.6.1` patch release carries forward the 25 built-in rules from `v0.6.0`. The reusable GitHub Action release is `v1.2.0`, available through `@v1`, and runs the published `v0.6.0` CLI. The CLI requires Node.js `20.9` or newer.

[![npm version](https://img.shields.io/npm/v/next-secure-check?logo=npm)](https://www.npmjs.com/package/next-secure-check)

## Quick start

```bash
npx --yes next-secure-check@0.6.1 scan . --preset app --summary
```

Findings are review signals. They do not prove that an issue is reachable or exploitable. Remove `--summary` for full finding details.

See [the main README](https://github.com/SetraTheXX/next-secure-check#how-it-fits-with-ai-assisted-code-review) for the product workflow and [the agent review example](https://github.com/SetraTheXX/next-secure-check/blob/main/docs/demo/agent-review.md) for JSON and SARIF usage.

## Presets

Use presets to choose a coverage and noise tradeoff:

```bash
npx --yes next-secure-check@0.6.1 scan . --preset app
npx --yes next-secure-check@0.6.1 scan . --preset strict
npx --yes next-secure-check@0.6.1 scan . --preset ci
```

- `app`: production app-code focused scan
- `strict`: broad aggressive review with context tuning off
- `ci`: practical pull request checks

Other presets are available for `default`, `audit`, `library`, and `monorepo` workflows.

Pin `next-secure-check@0.6.1` for reproducible runs. Use `@latest` only when
you intentionally want to try the newest published CLI line.

Global install is also supported:

```bash
npm install -g next-secure-check
next-secure-check scan . --preset app
```

If an older global install is present, unversioned `npx next-secure-check` can
sometimes reuse the old binary and fail on current options or helper commands
such as `--preset`, `rules`, `explain`, or `init`. Check it with:

```bash
next-secure-check --version
npm list -g next-secure-check
npm uninstall -g next-secure-check
npm cache verify
```

## CLI Helpers

List built-in rules:

```bash
npx --yes next-secure-check@0.6.1 rules
```

Explain one rule:

```bash
npx --yes next-secure-check@0.6.1 explain xss/dangerously-set-inner-html
```

Create a starter config and GitHub Actions workflow:

```bash
npx --yes next-secure-check@0.6.1 init
```

`init` creates:

```txt
.next-secure-check.json
.github/workflows/next-secure-check.yml
```

Existing files are skipped by default. Use `--force` only when you intentionally want to overwrite those files:

```bash
npx --yes next-secure-check@0.6.1 init --force
```

## Output Formats

```bash
npx --yes next-secure-check@0.6.1 scan .
npx --yes next-secure-check@0.6.1 scan . --summary
npx --yes next-secure-check@0.6.1 scan . --format json
npx --yes next-secure-check@0.6.1 scan . --format markdown --output report.md
npx --yes next-secure-check@0.6.1 scan . --format github
npx --yes next-secure-check@0.6.1 scan . --format sarif --output report.sarif
```

`github` output is designed for GitHub Actions Step Summary usage. SARIF output can be uploaded to GitHub Code Scanning.

Use JSON when an approved local AI agent will review findings with the checked-out source. The report includes rule IDs, severity, confidence, locations, and evidence fields where available. SARIF is the interchange format for Code Scanning. See the [agent review example](https://github.com/SetraTheXX/next-secure-check/blob/main/docs/demo/agent-review.md) for the workflow and privacy limits.

`--summary` is a terminal-only compact view for demos and quick reviews. It
keeps score, risk, counts, confidence, context, and representative locations;
the default terminal report remains detailed. The flag cannot be combined
with JSON, Markdown, GitHub, or SARIF output.

## GitHub Actions

Local terminal scans are manual. GitHub Actions scans are automatic after you add a workflow file to your repository; then GitHub runs the scan on the configured push or pull request events. `next-secure-check` does not scan repositories on its own.

Basic Step Summary workflow:

```yaml
name: next-secure-check

on:
  pull_request:
  push:
    branches: [main]

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
          npx --yes next-secure-check@0.6.1 scan . --preset app --format github --fail-on high | tee -a "$GITHUB_STEP_SUMMARY"
```

SARIF / GitHub Code Scanning workflow:

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
      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: 20

      - name: Run next-secure-check SARIF
        run: npx --yes next-secure-check@0.6.1 scan . --preset app --format sarif --output next-secure-check.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: next-secure-check.sarif
```

## Failure Gates

```bash
npx --yes next-secure-check@0.6.1 scan . --fail-on high
npx --yes next-secure-check@0.6.1 scan . --fail-on critical
```

`--fail-on critical` is a scan risk-level gate. It exits with code `1` only when the scan summary risk level is `critical`. Other values, such as `high`, `medium`, `low`, and `info`, work as severity thresholds.

## v0.6.0 Highlights

- Five bounded request-boundary and configuration signals for Server Actions, redirects, SSRF, session cookies, and broad image-host configuration
- Same-function source-to-sink evidence with visible guard and stop conditions
- Next.js 16 `proxy.ts`, dynamic request parameters, Pages Router, JavaScript, TypeScript, and CommonJS config coverage
- Deterministic JSON/SARIF output, privacy-safe evidence, and the v0.6 release quality gate

## v0.5.0 Highlights

- Bounded same-function source-to-sink evidence for command execution and raw SQL
- Structural auth, route-handler, validation, and middleware intent signals
- Explainable findings with context reason and optional proven evidence paths
- Concise terminal summaries for readable reviews and demos
- Context-aware scanning with finding context metadata
- Preset system for app, strict, CI, audit, library, and monorepo scans
- AST-assisted checks for command execution, raw SQL, dangerous HTML rendering, and password handling
- Regression fixture suite for real-world-style noise cases
- Reduced unknown context classifications for registry, demo, playground, story, fixture, and package UI paths
- XSS sanitizer/source refinement
- Middleware auth/rate-limit signals and refined rate-limit detection
- SARIF metadata polish for GitHub Code Scanning
- CLI `rules`, `explain`, and `init` commands

## Release Status

The `v0.6.1` patch keeps the scanner behavior and 25 built-in rules from
`v0.6.0`. It updates npm package presentation only, with no rule ID or scan
behavior changes. The reusable Action remains at `v1.2.0` through `@v1` and
runs the published `v0.6.0` CLI. The earlier `v0.5.0` line remains available
for reproducibility and historical compatibility checks.

To try the local build from a clone:

```bash
pnpm install
pnpm build
node packages/cli/dist/index.js scan . --preset app
```

## Honest Note

Findings are review signals, not proof of exploitation or a full security audit. False positives and false negatives are possible, especially in large monorepos, generators, templates, and tooling-heavy repositories.

See the main repository for rule documentation, web demo notes, and validation details:

https://github.com/SetraTheXX/next-secure-check
