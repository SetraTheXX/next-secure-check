# Phase 6: Bounded Command Flow Validation

Date: 2026-08-23

## Scope

This validation note covers the v0.4 bounded, syntax-only `injection/command-exec` source-to-sink pilot. It does not claim cross-function, cross-file, type-aware, or full control-flow analysis.

## Regression Matrix

- 30 scanner-level synthetic fixtures pass.
- 22 fixtures produce a deterministic `evidencePath` for a request-derived command value.
- Coverage includes `request.json()`, `request.formData()`, `req.body`, `req.query`, `searchParams.get(...)`, route parameters, imported/namespace/require sinks, and one- to two-alias chains.
- The matrix covers JavaScript, JSX, TypeScript, TSX, App Router-style paths, and Pages Router-style paths.
- Reassignment, mutation, callback/closure escape, and cross-function flow stop tracking as intended.
- Literal commands, argument-array commands, and unrelated object methods do not receive a source path; the existing imported sink review signal remains intact.

## Performance Measurement

The local Vitest measurement used a 100-file syntax-only fixture project:

```txt
cold: 82.5ms
warm: 77.4ms
```

These numbers are directional local measurements, not a universal benchmark. The test uses an 8-second ceiling to catch pathological regressions while leaving room for slower CI machines.

## Format Compatibility Smoke

After `pnpm build`, the following commands were run against the vulnerable fixture:

```powershell
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format github
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format sarif --output report.sarif
```

- Terminal and GitHub output completed with the expected 26 findings.
- JSON parsed successfully and preserved the expected 26 findings.
- SARIF parsed as `2.1.0` with 26 results, 19 unique rules, `informationUri`, deterministic `partialFingerprints`, result context properties, and rule-level `security-severity` metadata.
- `evidencePath` appeared only for findings with a proven bounded source path; temporary reports were deleted after the smoke run.

## Validation Snapshot

- Package tests: 304 passed.
- Web tests: 143 passed.
- Total: 447 passed.
- Self-scan with `--preset app`: `100/100`, `excellent`, 0 findings.
- Vulnerable fixture with `--preset strict`: `0/100`, `critical`, 26 findings.

## Intentional Limitations

The pilot deliberately records no source path for values that cross a function boundary, escape through a callback, or are reassigned/mutated. It also does not resolve wrappers, module aliases, or values flowing across files. These are intentional false negatives for this phase and are not evidence that a command is safe.

## Gate Status

The 30-case matrix, deterministic output checks, and local performance measurement are complete with no critical regression in the vulnerable or self-scan fixtures. The broader acceptance criterion of five measured false-positive reductions or five additional findings is not claimed yet because this pilot adds explainable flow metadata while preserving sink-only detection. Phase 6 remains open for a measured noise/coverage comparison before the v0.4 release decision.
