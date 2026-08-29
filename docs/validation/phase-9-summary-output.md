# Phase 9: Concise Terminal Summary

Date: 2026-08-29

Status: Implemented and included in the published `v0.5.0` release; the
stable npm line is `v0.5.0`.

## Purpose

Provide a readable terminal view for quick reviews, README recordings, and short CI logs without changing the existing detailed terminal report or machine-readable formats.

## Contract

The opt-in command is:

```bash
node packages/cli/dist/index.js scan . --preset app --summary
```

`--summary` is terminal-only. It prints the project/framework, score, risk level, finding counts, and up to three deterministic representative findings. Each representative row keeps severity, confidence, context, and location. Evidence and fix paragraphs are intentionally omitted from this view.

The default terminal report remains the detailed report with evidence and recommendations. JSON, Markdown, GitHub, and SARIF output are unchanged; combining `--summary` with a non-terminal format is rejected instead of silently changing the requested format. The flag is CLI-only and is not a configuration-file field.

## Fixture checks

After `pnpm build`, run:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app --preset strict --summary
node packages/cli/dist/index.js scan examples/secure-next-app --preset app --summary
node packages/cli/dist/index.js scan . --preset app --summary
```

The expected score/risk/finding values remain the established fixture baseline:

| Scan | Expected result |
| --- | --- |
| `vulnerable-next-app` with `strict` | `0/100`, `critical`, 26 findings |
| `secure-next-app` with `app` | `99/100`, `excellent`, 1 LOW finding |
| repository self-scan with `app` | `100/100`, `excellent`, 0 findings |

## Recorded verification

- `pnpm build`, `pnpm typecheck`, `pnpm lint`, and `pnpm test` pass.
- Package tests: `323`; web tests: `146`; total: `469`.
- CLI summary smoke, `scan --help`, non-terminal format rejection, JSON parsing, and SARIF parsing pass.
- The prepared v0.5.0 README GIF is `1280x640`, `18.44` seconds, approximately `776 KB`, and contains no checked-out local paths or secret/token patterns.

The README VHS recording uses the same summary commands, labels each fixture, and clears the terminal between scans. This keeps the comparison legible without exposing local checkout paths or raw secret evidence.

## Boundaries

This is a presentation and reporter-UX change, not a new analysis engine. It does not prove exploitability, alter rule IDs, alter finding counts, or add cross-file/interprocedural flow.
