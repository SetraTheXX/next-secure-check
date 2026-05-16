# Phase 4 Validation Note

Date: 2026-05-17

## Scope

This note records the manual validation results for the Phase 4 web demo and the existing CLI flow.

Phase 4 covers the public-repository web demo path:

- public GitHub repository URL validation
- public repository metadata check
- tarball download
- safe extraction and cleanup
- core scanner integration
- server-side evidence redaction
- scan result UI
- JSON and Markdown export

The web demo remains an early-development demo. It is public-repository-only and static-analysis-only.

## Commands Run

- `pnpm build`
- `pnpm typecheck`
- `pnpm test`
- `pnpm -C apps/web test`
- CLI scans against local example apps
- Local web demo checks in development mode
- Local web demo checks in production mode

Automated test baseline:

```txt
packages: 66 tests
apps/web: 82 tests
total: 148 tests
```

## Web Demo Checks

Manual web demo checks passed in both development mode and production mode.

Validated scenarios:

- `octocat/Hello-World` scan completed successfully.
- `SetraTheXX/next-secure-check` scan completed successfully.
- Invalid GitHub URL validation worked.
- Not-found repository error handling worked.
- JSON export worked.
- Markdown export worked.
- Secret evidence was shown as `[REDACTED]` in the web UI and exports.

## API Checks

The scan API path was validated through the web demo flow.

Validated behavior:

- Public repository scan requests complete successfully for reachable public repositories.
- Invalid repository input returns a safe validation error.
- Not-found repositories return a safe error response.
- Raw secret evidence is not sent to the browser for secret findings.
- Cleanup behavior remained part of the scan pipeline.

## CLI Checks

Manual CLI checks passed.

Validated scenarios:

- `examples/vulnerable-next-app` scan returned 27 findings.
- `examples/vulnerable-next-app` was rated `critical`.
- `--fail-on high` returned exit code `1` for the vulnerable app.
- `examples/secure-next-app` scan returned score `99`.
- `examples/secure-next-app` was rated `excellent`.
- `examples/secure-next-app` returned 1 LOW finding.
- Category filtering worked.

## Results Summary

Phase 4 manual validation passed.

Summary:

- Build passed.
- Typecheck passed.
- Package tests passed.
- Web tests passed.
- Web demo development mode passed manual checks.
- Web demo production mode passed manual checks.
- CLI manual checks passed.
- Git working tree remained clean after validation.

## Known Notes

- UI polish can happen later.
- Scanning `SetraTheXX/next-secure-check` is expected to be critical because the repository contains vulnerable examples and test fixtures.
- The web demo remains early-development, public-repository-only, and static-analysis-only.
- The web demo does not run repository code, install dependencies, or execute scanned repository scripts.

## Final Status

Phase 4 manual validation passed.
