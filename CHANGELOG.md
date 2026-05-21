# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- Added app-focused scan guidance for large repositories and monorepos.
- Documented known v0.1 noise sources around CI/release scripts, demo/example paths, and CLI tooling repositories.
- Clarified that findings are review signals, not proof of exploitation.

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
