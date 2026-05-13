# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial CLI MVP implementation.
- Core scanner engine with file collection and project detection.
- 10 deterministic security rules for Next.js projects:
  - `secrets/env-file-committed`
  - `secrets/hardcoded-secret`
  - `secrets/weak-jwt-secret`
  - `injection/no-eval`
  - `xss/dangerously-set-inner-html`
  - `config/insecure-cors-wildcard`
  - `auth/login-without-rate-limit`
  - `auth/password-without-hashing-library`
  - `injection/raw-sql-concat`
  - `headers/missing-security-headers`
- Multiple reporter formats: Terminal, JSON, Markdown, and GitHub Actions Summary.
- `--fail-on` flag to exit with a non-zero code based on severity.
- `--category` flag to filter rules by category.
- Vulnerable and secure example Next.js apps for testing.
- Comprehensive unit test suite (40 tests).