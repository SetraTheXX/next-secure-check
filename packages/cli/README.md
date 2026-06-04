# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

Run a quick static security sanity check before deploying a Next.js app.

## Usage

Recommended one-off usage:

```bash
npx --yes next-secure-check@latest scan . --preset app
```

For reproducible CI runs, pin the version:

```bash
npx --yes next-secure-check@0.3.0 scan . --preset app
```

Or run without installing:

```bash
npx --yes next-secure-check@latest scan .
```

Global install is also supported:

```bash
npm install -g next-secure-check
next-secure-check scan .
```

If an older global install is present, unversioned `npx next-secure-check` can sometimes reuse the old binary and fail on v0.2 options such as `--preset`. Check and remove the global install when needed:

```bash
next-secure-check --version
npm list -g next-secure-check
npm uninstall -g next-secure-check
npm cache verify
```

## Presets

Use presets to choose the right signal/noise tradeoff:

```bash
npx --yes next-secure-check@latest scan . --preset app
npx --yes next-secure-check@latest scan . --preset strict
npx --yes next-secure-check@latest scan . --preset ci
```

- `app`: production app-code focused scan
- `strict`: broad aggressive review with context tuning off
- `ci`: practical pull request checks

Other presets are available for `default`, `audit`, `library`, and `monorepo` workflows.

Prefer `npx --yes next-secure-check@latest` for local one-off scans, or pin `next-secure-check@0.3.0` in CI.

## CLI Helpers

List built-in rules:

```bash
npx --yes next-secure-check@latest rules
```

Explain one rule:

```bash
npx --yes next-secure-check@latest explain xss/dangerously-set-inner-html
```

Create a starter config and GitHub Actions workflow:

```bash
npx --yes next-secure-check@latest init
```

`init` creates:

```txt
.next-secure-check.json
.github/workflows/next-secure-check.yml
```

Existing files are skipped by default. Use `--force` only when you intentionally want to overwrite those files:

```bash
npx --yes next-secure-check@latest init --force
```

## Output Formats

```bash
npx --yes next-secure-check@latest scan .
npx --yes next-secure-check@latest scan . --format json
npx --yes next-secure-check@latest scan . --format markdown --output report.md
npx --yes next-secure-check@latest scan . --format github
npx --yes next-secure-check@latest scan . --format sarif --output report.sarif
```

`github` output is designed for GitHub Actions Step Summary usage. SARIF output can be uploaded to GitHub Code Scanning.

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

## Failure Gates

```bash
npx --yes next-secure-check@latest scan . --fail-on high
npx --yes next-secure-check@latest scan . --fail-on critical
```

`--fail-on critical` is a scan risk-level gate. It exits with code `1` only when the scan summary risk level is `critical`. Other values, such as `high`, `medium`, `low`, and `info`, work as severity thresholds.

## v0.3.0 Highlights

- Context-aware scanning with finding context metadata
- Preset system for app, strict, CI, audit, library, and monorepo scans
- AST-assisted checks for command execution, raw SQL, dangerous HTML rendering, and password handling
- Regression fixture suite for real-world-style noise cases
- Reduced unknown context classifications for registry, demo, playground, story, fixture, and package UI paths
- XSS sanitizer/source refinement
- Middleware auth/rate-limit signals and refined rate-limit detection
- SARIF metadata polish for GitHub Code Scanning
- CLI `rules`, `explain`, and `init` commands

## Honest Note

Findings are review signals, not proof of exploitation or a full security audit. False positives and false negatives are possible, especially in large monorepos, generators, templates, and tooling-heavy repositories.

See the main repository for rule documentation, web demo notes, and validation details:

https://github.com/SetraTheXX/next-secure-check
