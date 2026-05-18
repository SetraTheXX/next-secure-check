# Phase 6 External Review Fixes

Date: 2026-05-19

## Scope

This note records the Claude/Codex external review bugfix sweep after SARIF and CLI config support were added. The pass focused on confirmed bugs and small hardening improvements without changing the scanner's deterministic static-analysis model.

## Completed Fixes

- `--fail-on critical` now gates on `scan.summary.riskLevel === "critical"` instead of trying to match a non-existent CRITICAL severity.
- `commandExecRule` method-call ignore logic is column-aware, so `regex.exec(input)` is ignored while bare `exec("ls")` on the same line is still detected.
- `hardcodedSecretRule` ignores low-signal sample values such as `test1234`, `12345678`, `password`, `changeme`, `example`, `demo`, `dummy`, and `placeholder`, while preserving known provider token patterns and high-signal secret-like values.
- Successful web scans still return their scan result if immediate temp cleanup fails; the response includes a safe cleanup warning instead of leaking internal paths or stack traces.
- GitHub metadata and tarball requests support optional `GITHUB_TOKEN` and always send `User-Agent: next-secure-check`.
- Scan client IP resolution is hardened with platform header priority, IPv4/IPv6 validation, comma-separated header handling, whitespace trimming, invalid-value fallback, and oversized-header fallback.
- SARIF output includes `tool.driver.informationUri` and deterministic `results[].partialFingerprints`.
- SARIF output continues to omit raw secret evidence.

## Validation Commands

```powershell
pnpm build
pnpm typecheck
pnpm test
pnpm -C apps/web test
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format sarif --output report.sarif
node -e "JSON.parse(require('fs').readFileSync('report.sarif','utf8')); console.log('valid json')"
Remove-Item report.sarif -ErrorAction SilentlyContinue
```

## Test Baseline

- Packages: 105 tests.
- Web app: 128 tests.
- Total: 233 tests.
- Build, typecheck, package tests, web tests, and SARIF smoke passed.

## CLI Smoke Notes

- `examples/vulnerable-next-app` currently returns 26 findings.
- The vulnerable app remains rated `critical`.
- `--fail-on critical` exits with code `1` for a critical scan summary.
- `--fail-on critical` exits with code `0` for non-critical scan summaries.
- SARIF smoke output is valid JSON.

## Remaining Risks

- The in-memory scan guard is still local/single-instance only. Public multi-instance or serverless deployments need a distributed rate limit or platform-level protection.
- Client IP resolution still depends on trusted platform/proxy behavior. Deployment configuration must ensure forwarded headers are controlled by the platform.
- AST-based rule analysis remains future work.
- `originalUriBaseIds` was not added to SARIF because the reporter does not currently receive a reliable repository root/base URI.

## Final Status

Phase 6 external review bugfix pass passed.
