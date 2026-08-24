# Phase 8: Reproducible Vulnerable/Secure Demo

Date: 2026-08-24

Recording status: screen capture completed; edit, Turkish voice-over, English subtitles, and final privacy review are supplementary release material.

## Purpose

This note defines a short, reproducible terminal flow for showing what `next-secure-check` catches and what its results do not claim. It uses the repository's checked-in fixtures rather than an external project, so the expected output remains stable and reviewable.

## Demo Commands

Build the workspace first:

```bash
pnpm build
```

Run the three comparison scans:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app --preset strict
node packages/cli/dist/index.js scan examples/secure-next-app --preset app
node packages/cli/dist/index.js scan . --preset app
```

Expected summary values:

| Scan | Score | Risk | Findings |
| --- | ---: | --- | ---: |
| `examples/vulnerable-next-app` with `strict` | `0/100` | `critical` | 26 (`12 HIGH`, `11 MEDIUM`, `2 LOW`, `1 INFO`) |
| `examples/secure-next-app` with `app` | `99/100` | `excellent` | 1 LOW |
| repository self-scan with `app` | `100/100` | `excellent` | 0 |

These values are fixture regression expectations. They demonstrate a deliberately unsafe project, a mostly clean project with one review signal, and a repository self-scan with app-focused exclusions; they are not universal accuracy or risk guarantees.

## Before/After Signal Examples

- **Command execution:** the AST-assisted matcher distinguishes imported `child_process` sinks from unrelated methods such as `regex.exec(input)`. Same-function request-derived input can produce an optional `evidencePath`; reassignment, closures, cross-function flow, and type-aware resolution remain out of scope.
- **Raw SQL:** direct interpolation passed to a recognized query sink remains visible. A plain SQL-like template assigned to a variable without a direct sink is intentionally not reported by the current bounded rule.
- **Dangerous HTML:** JSX `dangerouslySetInnerHTML` values supplied by variables or member expressions remain review signals. Normal JSX text, unrelated props, and static literal HTML are not treated as equivalent input.
- **Admin and upload checks:** route-aware and endpoint-aware signals focus on API handlers rather than treating every admin dashboard, file picker, or upload button component as an endpoint.
- **Context and presets:** `app` favors production application paths; `strict` keeps broad coverage and tuning off. Context metadata explains why a file was classified, but it does not prove reachability or exploitability.

## Suggested 35-Second Recording Flow

1. Show the command and the vulnerable fixture result (`0/100`, `critical`, 26 findings).
2. Scroll to two API findings and show their rule IDs, locations, confidence, and recommendation.
3. Run the secure fixture and show `99/100`, `excellent`, with one LOW review signal.
4. Run the self-scan with `--preset app` and show `100/100` with zero findings.
5. Optionally show `explain injection/command-exec` or the SARIF command.

## Honest Boundary

The scanner is a deterministic pre-release review signal. It is not a penetration test, exploit verifier, full security audit, cross-file taint engine, or type-aware proof system. False positives and false negatives remain possible, especially in custom wrappers and large tooling-heavy repositories.
