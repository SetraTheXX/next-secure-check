# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

Run a quick static security sanity check before deploying a Next.js app.

## Usage

Install globally:

```bash
npm install -g next-secure-check
next-secure-check scan .
```

Or run without installing:

```bash
npx next-secure-check scan .
```

## Presets

Use presets to choose the right signal/noise tradeoff:

```bash
npx next-secure-check scan . --preset app
npx next-secure-check scan . --preset strict
npx next-secure-check scan . --preset ci
```

- `app`: production app-code focused scan
- `strict`: broad aggressive review with context tuning off
- `ci`: practical pull request checks

Other presets are available for `default`, `audit`, `library`, and `monorepo` workflows.

## Output Formats

```bash
npx next-secure-check scan .
npx next-secure-check scan . --format json
npx next-secure-check scan . --format markdown --output report.md
npx next-secure-check scan . --format github
npx next-secure-check scan . --format sarif --output report.sarif
```

`github` output is designed for GitHub Actions Step Summary usage. SARIF output can be uploaded to GitHub Code Scanning.

## Failure Gates

```bash
npx next-secure-check scan . --fail-on high
npx next-secure-check scan . --fail-on critical
```

`--fail-on critical` is a scan risk-level gate. It exits with code `1` only when the scan summary risk level is `critical`. Other values, such as `high`, `medium`, `low`, and `info`, work as severity thresholds.

## v0.2.0 Highlights

- Context-aware scanning with finding context metadata
- Preset system for app, strict, CI, audit, library, and monorepo scans
- AST-assisted checks for command execution, raw SQL, dangerous HTML rendering, and password handling
- Reduced noisy findings in large monorepos and tooling-heavy repositories
- GitHub Actions and SARIF support

## Honest Note

Findings are review signals, not proof of exploitation or a full security audit. False positives and false negatives are possible, especially in large monorepos, generators, templates, and tooling-heavy repositories.

See the main repository for rule documentation, web demo notes, and validation details:

https://github.com/SetraTheXX/next-secure-check
