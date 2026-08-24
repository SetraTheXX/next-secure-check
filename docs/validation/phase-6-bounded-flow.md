# Phase 6: Bounded Command Flow Validation

Date: 2026-08-23

## Scope

This validation note covers the v0.4 bounded, syntax-only `injection/command-exec` source-to-sink pilot and its narrow non-shell spawn noise reduction. It does not claim cross-function, cross-file, type-aware, or full control-flow analysis.

## Regression Matrix

- 30 scanner-level synthetic fixtures pass.
- 22 fixtures produce a deterministic `evidencePath` for a request-derived command value.
- Coverage includes `request.json()`, `request.formData()`, `req.body`, `req.query`, `searchParams.get(...)`, route parameters, imported/namespace/require sinks, and one- to two-alias chains.
- The matrix covers JavaScript, JSX, TypeScript, TSX, App Router-style paths, and Pages Router-style paths.
- Reassignment, mutation, callback/closure escape, and cross-function flow stop tracking as intended.
- Literal commands, argument-array commands, and unrelated object methods do not receive a source path; the existing imported sink review signal remains intact.
- Five static non-shell `spawn`/`spawnSync` tooling patterns are suppressed, while dynamic executable values and `shell: true` remain findings.
- Explicit same-function `includes`/`has` allowlist guards suppress a request-derived command sink; a `spawn` call still remains detectable when later arguments carry request data.

## Performance Measurement

The local Vitest measurement used a 100-file syntax-only fixture project:

```txt
cold: 124.9ms
warm: 115.2ms
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

- Package tests: 306 passed.
- Web tests: 143 passed.
- Total: 449 passed.
- Self-scan with `--preset app`: `100/100`, `excellent`, 0 findings.
- Vulnerable fixture with `--preset strict`: `0/100`, `critical`, 26 findings.

## Intentional Limitations

The pilot deliberately records no source path for values that cross a function boundary, escape through a callback, or are reassigned/mutated. It also does not resolve wrappers, module aliases, or values flowing across files. These are intentional false negatives for this phase and are not evidence that a command is safe.

## Gate Status

The 30-case matrix, deterministic output checks, local performance measurement, and five-case static non-shell spawn comparison are complete with no critical regression in the vulnerable or self-scan fixtures. The five confirmed noise reductions come from static executable-plus-argument-array `spawn`/`spawnSync` tooling patterns that the previous broad sink matcher reported. Dynamic executable values and `shell: true` remain findings. Phase 6 acceptance is complete; TypeChecker and broader source-to-sink coverage remain later work.
