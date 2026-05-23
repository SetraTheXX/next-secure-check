# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Full AST/type-aware analysis remains a v0.3 roadmap item.

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
