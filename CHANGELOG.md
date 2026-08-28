# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added a root composite GitHub Action wrapper for `next-secure-check@0.4.1` with preset, fail-on, format, exclude, and output inputs.
- Added a CI smoke step that exercises the local Action against the secure fixture.
- Added an opt-in terminal-only `--summary` view for concise score, risk, finding-count, severity, confidence, context, and location output.
- Added shared syntax-only bounded-flow facts for direct sources, command sinks, guards, short aliases, invalidations, function boundaries, and proven evidence paths.

### Documentation
- Added the reproducible VHS README demo, simplified SVG wordmark, and v0.5 summary-output validation note.
- Added the v0.5 baseline/finding-identity inventory and bounded-flow contract decision note for issue #13.
- Added the shared `AnalysisFacts` foundation validation note for issue #14.

### Tests
- Current validation baseline: 326 package tests, 146 web tests, 472 total tests.

## [0.4.1] - 2026-08-24

### Documentation
- Clarified that v0.4.0 is published and removed stale release-candidate wording from the CLI package documentation.
- Updated npm-facing usage guidance for reproducible v0.4 scans and the v0.4.1 CLI documentation patch.

## [0.4.0] - 2026-08-24

### Changed
- Prepared a reproducible fixture-first demo flow for v0.4 release review; external repositories remain optional smoke-test inputs rather than accuracy claims.
- Clarified `secrets/next-public-secret` wording as a review signal based on a secret-like name, not proof that the assigned value is a credential.
- Added guidance for intentionally public client identifiers and more descriptive `NEXT_PUBLIC_*` names.
- Refined auth and API validation intent detection to ignore comments and keyword-only identifiers while recognizing common auth and validation calls.
- Added shared `AnalysisFacts` syntax parsing with a per-scan source-file cache.
- Added a bounded same-function command source-to-sink pilot with optional JSON/SARIF `evidencePath` metadata.
- Raised the supported Node.js baseline to Node 20 and aligned CLI metadata with `commander@14`.
- Upgraded the web demo and secure fixture to Next.js 16.3.2 and added a warning-free ESLint gate.
- Made workspace tests resolve package source instead of potentially stale `dist` output.
- Added the lint gate to CI and included the MIT license text in every published package tarball.
- Updated generated and documented GitHub workflows to current Node 24-based action majors while keeping scanned projects on Node.js 20.

### Fixed
- Kept password findings active when a hashing dependency is installed but not actually used.
- Corrected monorepo Next.js project/router detection and avoided treating generic `src/api` directories as Next.js.
- Scoped nested app middleware signals so they protect only routes in the same app.
- Aggregated SARIF rule metadata using the strongest effective severity and confidence for each rule.
- Mapped GitHub API rate limits safely and prevented rejected distributed-concurrency requests from consuming IP rate quota.
- Removed duplicated hardcoded CLI version literals by reading the package manifest at runtime.

### Tests
- v0.4.0 release validation snapshot: 320 package tests, 146 web tests, 466 total tests.

## [0.3.0] - 2026-06-04

### Added
- Benchmark/regression fixture suite for representative monorepo, registry, tooling, XSS, SQL, password, admin, upload, and config cases.
- Middleware auth and rate-limit signals from `middleware.ts` and `src/middleware.ts`.
- CLI `rules` command for listing built-in deterministic rules.
- CLI `explain <rule-id>` command for terminal rule explanations.
- CLI `init` command for generating a starter `.next-secure-check.json` and GitHub Actions workflow.

### Changed
- Reduced `unknown` context classifications for registry, story, demo, playground, fixture, and package UI paths.
- Refined `xss/dangerously-set-inner-html` sanitizer and source signals.
- Refined login/register rate-limit detection for route-level and middleware-level limiter signals.
- Improved SARIF rule metadata with help URIs, tags, selected CWE mappings, security severity, and deterministic fingerprints.

### Fixed/Improved
- Preserved vulnerable fixture coverage while reducing false-positive/noise cases in synthetic real-world-style fixtures.
- Kept app/default/ci preset behavior stable while improving context classification.
- Kept SARIF secret/evidence redaction behavior intact.
- Raised the validation baseline to 429 passing tests.

### Notes
- v0.3.0 keeps the same core CLI scan surface while improving analysis quality and CLI usability.
- Findings remain deterministic review signals, not proof of exploitation.
- Full type-aware analysis and a larger route graph remain future work beyond the v0.3 release.

## [0.2.1] - 2026-05-24

### Documentation
- Clarified recommended `npx --yes next-secure-check@latest` usage for local scans.
- Added reproducible `next-secure-check@0.2.0` examples for CI workflows.
- Documented how to diagnose and remove stale global installs that can shadow v0.2 CLI options.
- Added copy-paste GitHub Actions examples for Step Summary and SARIF / GitHub Code Scanning.

## [0.2.0] - 2026-05-24

### Added
- Context metadata and context reasons on findings.
- `--preset` CLI option for `default`, `app`, `strict`, `ci`, `audit`, `library`, and `monorepo` scan modes.
- `preset` config option in `.next-secure-check.json`.
- Context-aware severity and confidence tuning.
- AST-assisted `injection/command-exec` detection.
- AST-assisted `injection/raw-sql-concat` detection.
- AST-assisted `xss/dangerously-set-inner-html` detection.
- AST-assisted `auth/password-without-hashing-library` detection.
- Route-aware `auth/admin-route-without-auth` detection.
- Endpoint-aware upload validation checks.
- Context-aware `config/next-powered-by-header` refinement.

### Changed
- Reduced noisy findings in large monorepos, template-heavy repositories, and tooling-heavy repositories.
- Improved shadcn/ui benchmark from roughly 166+ noisy findings to 55 default / 47 app findings.
- Improved create-t3-app app preset benchmark from 13 findings to 8 findings.
- Reporter output now includes finding context in user-facing formats.
- JSON and SARIF outputs now include context metadata.
- Added app-focused scan guidance for large repositories and monorepos.
- Clarified that findings are review signals, not proof of exploitation.

### Notes
- Findings are review signals, not a full security audit.
- False positives and false negatives are still possible.
- Full type-aware analysis was intentionally deferred beyond the v0.2 release.

## [0.1.0] - 2026-05-20

### Added
- CLI scanner for local Next.js project scans.
- 20 deterministic security rules across secrets, injection, XSS, auth, config, headers, upload, and validation categories.
- Terminal, JSON, Markdown, GitHub Actions Summary, and SARIF 2.1.0 report formats.
- SARIF metadata, deterministic partial fingerprints, and concise result messages for GitHub Code Scanning usage.
- `.next-secure-check.json` config support for `excludePaths`, `categories`, `failOn`, and `format`.
- CLI flags for `--exclude`, `--category`, `--fail-on`, `--format`, `--output`, and `--config`.
- Public GitHub repository web demo with JSON and Markdown export.
- Safe tarball extraction with path traversal, symlink, hardlink, duplicate path, size, and file count protections.
- Server-side secret evidence redaction for web scan responses.
- Optional `GITHUB_TOKEN` support for GitHub metadata and tarball requests.
- Optional Upstash Redis REST distributed scan abuse guard.
- GitHub request and scan-stage timeout handling.
- Safe minimal logging and error responses for public scan operations.
- Package README files for npm tarball presentation.
- NPM publish readiness metadata for the CLI, core, rules, and reporter packages.

### Fixed
- `--fail-on critical` now gates on critical scan summary risk level.
- Command execution matching no longer ignores real bare calls after safe method calls on the same line.
- Low-signal hardcoded secret sample values produce fewer false positives.
- Raw SQL logging/error-message contexts produce fewer false positives.
- `dangerouslySetInnerHTML` severity is context-aware for static literals versus user-controlled-looking values.
- Committed environment file detection now covers common `.env.*` variants.
- Missing security header detection now reports partial header configurations.
- Successful web scans are preserved when immediate cleanup fails, with a safe cleanup warning.

### Security
- Web demo avoids executing scanned repository scripts.
- Web responses and safe logs avoid raw secrets, tokens, local paths, and stack traces.
- Client IP resolution validates IPv4/IPv6 values and handles oversized headers safely.
