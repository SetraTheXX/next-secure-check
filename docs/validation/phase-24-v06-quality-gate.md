# Phase 24 — v0.6 Quality Gate and Release Feedback (#35)

Date: 2026-08-31

Issue: [#35](https://github.com/SetraTheXX/next-secure-check/issues/35)

Status: Complete for the v0.6 release-quality candidate and candidate-package
preparation. npm publication and the v0.6 GitHub tag/release remain a separate
maintainer release decision.

## Purpose

This phase turns the v0.6 request-boundary work into reproducible release
evidence without expanding analyzer scope. It protects the published v0.5
contract, exercises the five development-line signals, records safe and
unsafe minimized cases, and defines how real-world feedback becomes a small
regression fixture or an explicitly non-actionable observation.

The scanner reads repository files as input. It does not execute code from a
scanned repository, install its dependencies, or make network requests on its
behalf.

## Public version contract

| Surface | Version/status | Meaning |
| --- | --- | --- |
| Stable npm CLI and internal packages | `0.5.0`, published | Stable public line with 20 built-in rules |
| v0.6 candidate CLI and internal packages | `0.6.0`, local candidate only | 25 built-in rules; not published or tagged |
| Reusable GitHub Action | `v1.1.0`, `@v1` | Runs the published `next-secure-check@0.5.0` line |
| README demo | Published `v0.5.0` build | Stable three-fixture `--summary` demo; intentionally not a v0.6 claim |

The four publishable working-tree manifests are now aligned at candidate
version `0.6.0`. This is release preparation only: it does not publish npm
artifacts, create a tag, update the Action pin, or change the demo. Until the
candidate is deliberately published, stable users should keep using the
published `0.5.0` CLI and `v1.1.0`/`@v1` Action.

The CLI `init` template follows the checked-in CLI version, so a locally built
candidate writes `next-secure-check@0.6.0` for a future published workflow. The
stable README and Action remain pinned to `0.5.0` while that package is not yet
available on npm.

## Runnable quality gate

The public command is:

```bash
pnpm release:gate
```

It runs [`scripts/v06-quality-gate.mjs`](../../scripts/v06-quality-gate.mjs),
which first runs the frozen v0.5 compatibility gate and then checks:

- a positive/safe minimized matrix for all five v0.6 rule IDs;
- repeated local JSON determinism and bounded evidence presence;
- CLI version/help/rule-list/explanation/unknown-rule and `--fail-on` smoke;
- aligned package versions, Node engine metadata, license/dist packaging,
  Action pin, and README version messaging;
- the existing SARIF, public-output privacy, summary, pack, and 100/1,000-file
  cold/warm benchmark checks from the v0.5 gate.

The legacy gate remains directly runnable as `pnpm release:gate:v05` for
historical v0.5 compatibility checks. External repositories are intentionally
not a CI dependency.

## Local audit result

The final local validation sequence produced:

```text
pnpm install --frozen-lockfile  PASS
pnpm build                    PASS
pnpm typecheck                PASS
pnpm lint                     PASS
pnpm test                     PASS — 453 package tests, 147 web tests, 600 total
pnpm audit --prod --audit-level high  PASS — no known vulnerabilities
```

The compatibility stage and benchmark samples passed with these local values:

```text
100 files:  cold scanner 134.6/140.8 ms median/p95; cold process 532.9/570.6 ms; warm 86.0/128.0 ms; overhead 1.18x
1,000 files: cold scanner 911.8/997.1 ms median/p95; cold process 1331.9/1432.7 ms; warm 788.9/851.1 ms; overhead 1.14x
warm corpus scaling ratio: 9.18x
```

The published-package smoke reported `next-secure-check@0.5.0`, and its secure
fixture scan remained `99/100`, `excellent`, with one LOW finding. The four
publishable package tarballs were independently checked with `npm pack
--dry-run --ignore-scripts`; the candidate publish dry-run recognized all four
`0.6.0` packages without publishing them. The previously published `0.5.0`
smoke remains the stable consumer check.

The checked-in demo asset remains `1280x640`, `18.44` seconds, and `461`
frames. Its tape uses only the three fixture scans with `--summary`; no
summary flag is combined with JSON/SARIF or another machine-readable format.

## v0.6 development matrix

The minimized positive fixture exercised each development-line rule once;
the safe fixture exercised its corresponding visible guard or safe form and
reported none of those five IDs.

| Rule | Positive result | Safe result | Observed inventory |
| --- | ---: | ---: | --- |
| `auth/server-action-without-guards` | 1 | 0 | `app-code / MEDIUM / MEDIUM` |
| `auth/session-cookie-without-security-flags` | 1 | 0 | `api-code / MEDIUM / MEDIUM` |
| `config/next-image-domains` | 1 | 0 | `unknown / MEDIUM / HIGH` |
| `redirect/unvalidated-target` | 1 | 0 | `app-code / MEDIUM / MEDIUM` |
| `ssrf/unvalidated-outbound-url` | 1 | 0 | `api-code / HIGH / MEDIUM` |

Repeated JSON reports matched after removing only volatile scan metadata.
Evidence remained present for every exercised positive signal and no absolute
local path was emitted by the matrix output.

## Real-world smoke and feedback disposition

Two public repositories were downloaded as source archives and scanned with
the published `0.5.0` CLI and the local 25-rule development line. No scanned
repository code was executed, and raw reports or repository contents were not
stored.

| Input | Published `0.5.0` | Local development line | Difference observed |
| --- | --- | --- | --- |
| `shadcn-ui/ui` | 42 findings, 10 rule/context kinds, `0/100` observed score | 44 findings, 12 kinds, `0/100` observed score | Two new `auth/server-action-without-guards` signals: one LOW and one MEDIUM |
| `vercel/nextjs-postgres-auth-starter` | 1 LOW header signal, `99/100` observed score | 3 findings, `89/100` observed score | Two new MEDIUM `auth/server-action-without-guards` signals |

These deltas are expected coverage from the new development-line rule, not a
confirmed false positive or an accuracy claim. They remain review-only until
the repository owner confirms whether the action inputs have equivalent
authentication and validation controls that are outside the syntax boundary.
No external false-positive or false-negative was confirmed, so no raw
external output was converted into a regression fixture. The minimized matrix
above is the reproducible regression surface for this phase.

An attempted smoke archive for `t3-oss/create-t3-app` could not be extracted
on Windows because the archive contained a path exceeding the local tar
tool's path limit. It was excluded from the evidence and is a tooling
limitation, not a scanner result.

## Independent review handoff

Use this checklist for a fresh review or a future user report:

1. Record the exact CLI/Action version and whether the input was the published
   line or the v0.6 working tree.
2. Provide a public repository and commit, or a small redacted fixture; never
   include real secrets, tokens, private files, or customer data.
3. Classify the observation as crash, false positive, false negative, output
   compatibility, privacy, performance, packaging, or documentation.
4. Compare rule ID, context, severity, confidence, evidence path, and the
   visible guard/stop condition before proposing a code change.
5. Reduce a confirmed behavior change to one positive and one safe example,
   add the expected report contract, then rerun `pnpm release:gate`.
6. Do not use score, finding count, or a single public repository as a general
   accuracy percentage or proof of exploitability.

## Acceptance record

- [x] Final fixture and report compatibility are protected by the v0.5 gate
  and the v0.6 minimized matrix.
- [x] Real-world observations are either minimized or explicitly recorded as
  review-only/non-actionable; no unreviewed accuracy claim is made.
- [x] Determinism, privacy, and performance budgets pass locally and in CI.
- [x] `npm pack --dry-run`, package metadata, and Action compatibility checks
  pass; the Action remains correctly pinned to the published v0.5 line.
- [x] Release documentation states the exact published versions and v0.6
  limitations.
- [x] The v0.6 npm publication/tag decision is intentionally handed off as a
  separate release step; it is not implied by this validation note.

## Boundaries

This phase does not add a full taint engine, cross-file or cross-function
flow, route graph, TypeChecker default path, unrestricted plugins, hosted
service behavior, or external accuracy claims. Every finding remains an
explainable review signal, not proof of exploitation.
