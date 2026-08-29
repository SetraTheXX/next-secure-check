# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

Run a quick static security sanity check before deploying a Next.js app.

Requires Node.js 20 or newer.

The stable npm line is `v0.4.1`. The `v0.5.0` release candidate is prepared
in the repository with aligned CLI and internal package versions; manual npm
publication is still pending.

## Usage

Recommended one-off usage:

```bash
npx --yes next-secure-check@latest scan . --preset app
```

For reproducible CI runs on the stable npm line, pin the release version:

```bash
npx --yes next-secure-check@0.4.1 scan . --preset app
```

After the manual v0.5.0 npm publication, the candidate can be pinned with:

```bash
npx --yes next-secure-check@0.5.0 scan . --preset app
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

If an older global install is present, unversioned `npx next-secure-check` can sometimes reuse the old binary and fail on current options or helper commands such as `--preset`, `rules`, `explain`, or `init`. Check and remove the global install when needed:

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

Prefer `npx --yes next-secure-check@latest` for local one-off scans, or pin
`next-secure-check@0.4.1` in CI until the manual v0.5.0 publication is done.

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
npx --yes next-secure-check@latest scan . --summary
npx --yes next-secure-check@latest scan . --format json
npx --yes next-secure-check@latest scan . --format markdown --output report.md
npx --yes next-secure-check@latest scan . --format github
npx --yes next-secure-check@latest scan . --format sarif --output report.sarif
```

`github` output is designed for GitHub Actions Step Summary usage. SARIF output can be uploaded to GitHub Code Scanning.

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
          npx --yes next-secure-check@0.4.1 scan . --preset app --format github --fail-on high | tee -a "$GITHUB_STEP_SUMMARY"
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
        run: npx --yes next-secure-check@0.4.1 scan . --preset app --format sarif --output next-secure-check.sarif

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

## v0.5.0 Release-Candidate Highlights

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

The v0.5.0 release candidate contains the bounded-analysis, intent, reporter,
and summary changes described above. The CLI, core, rules, and reporter
candidate manifests are all aligned at `0.5.0`; npm publication and the exact
GitHub tag remain manual release steps. The published stable line remains
`0.4.1` until then.

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
