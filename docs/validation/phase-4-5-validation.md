# Phase 4.5 Validation

Date: 2026-05-18

## Scope

Phase 4.5 focused on hardening the Phase 4 web demo and reducing scanner noise before moving toward Phase 5. The work stayed within the existing static-analysis model: no scanned repository code execution, no dependency installation inside scanned repositories, and no private repository support.

## Commits / Completed Work

- Repo size check before tarball download.
- Cleanup error masking fix for safe extraction failures.
- Basic scan abuse guard for the web scan API:
  - IP-based in-memory rate limiting.
  - Global in-memory concurrent scan limiting.
- Core and CLI `excludePaths` support.
- Web app security headers hardening.
- Rule false positive hardening for noisy text-based checks.
- Final self-scan cleanup for remaining false positives.

## Validation Commands

```powershell
pnpm build
pnpm typecheck
pnpm test
pnpm -C apps/web test
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/secure-next-app --format json
node packages/cli/dist/index.js scan apps/web --category headers,config
node packages/cli/dist/index.js scan . --exclude "**/*.test.ts,examples/**"
```

## Test Baseline

- Packages: 79 tests.
- Web app: 92 tests.
- Total: 171 tests.
- Build, typecheck, package tests, and web tests passed.

## CLI Smoke Results

### vulnerable-next-app

- Command: `node packages/cli/dist/index.js scan examples/vulnerable-next-app`
- Result: 27 findings.
- Score: 0.
- Risk: critical.
- Expected vulnerable findings were preserved.

### secure-next-app

- Command: `node packages/cli/dist/index.js scan examples/secure-next-app --format json`
- Result: 1 LOW finding.
- Score: 99.
- Risk: excellent.

### apps/web headers/config

- Command: `node packages/cli/dist/index.js scan apps/web --category headers,config`
- Result: 0 findings.
- Score: 100.
- Risk: excellent.

### self-scan with exclude

- Command: `node packages/cli/dist/index.js scan . --exclude "**/*.test.ts,examples/**"`
- Result: 0 findings.
- Score: 100.
- Risk: excellent.

## Remaining Risks

- The in-memory rate limit is not distributed. A public multi-instance or serverless deployment still needs deploy-specific rate limiting, such as Redis or a platform-level control.
- AST migration remains future work. The scanner still uses lightweight rule heuristics for several checks.
- A public hosted demo still needs deploy-specific hardening before being treated as internet-facing.

## Final Status

Phase 4.5 hardening passed.

Phase 5 can start after this documentation is committed.
