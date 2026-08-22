# Roadmap

Public progress board for `next-secure-check`. This file tracks the current release direction and actionable work. Historical decisions stay in git history, `CHANGELOG.md`, and `docs/validation`; private working notes do not belong here.

| Field | Value |
| --- | --- |
| Last reviewed | 2026-08-22 |
| Current release | v0.3.0 published |
| Current next task | v0.4 Phase 2 - clarify `NEXT_PUBLIC_*` review-signal messaging |

## Progress Legend

- `[x]` completed and validated
- `[ ]` planned or not started
- `[~]` in progress

## Release Status

### v0.3.0 - Published

- [x] 20 deterministic security rules
- [x] Syntax-level AST checks for command execution, raw SQL, dangerous HTML, and password handling
- [x] Context metadata and seven scan presets
- [x] Route-aware admin and endpoint-aware upload checks
- [x] CLI `rules`, `explain`, and `init` commands
- [x] Terminal, JSON, Markdown, GitHub, and SARIF output
- [x] GitHub Actions and public repository web-demo flow
- [x] 429 passing tests: 286 package tests and 143 web tests
- [x] NPM and GitHub release completed

## v0.4.0 - Bounded Analysis Quality

### Product Goal

Reduce high-value false positives and recover a small number of missed source-to-sink risks without turning the scanner into a slow, opaque, full taint-analysis engine.

### Compatibility Rules

- Default scans should remain syntax-first and fast.
- Existing rule IDs, report formats, SARIF fingerprints, and CLI flags should remain compatible.
- `--preset app` remains the recommended production-app sanity check.
- `strict` and `audit` remain broad review modes; they should not silently become permissive.
- No scanned repository code is executed.
- No unrestricted JavaScript/TypeScript plugin loading is introduced.

## Phase 0 - Repository Hygiene

**Status:** `[x] Complete`

**Goal:** Make the project easy for a future contributor to understand and safe to publish.

- [x] Add a public root roadmap.
- [x] Keep README, CHANGELOG, CONTRIBUTING, SECURITY, and LICENSE at the root.
- [x] Add issue templates for bugs, false positives, and feature requests.
- [x] Add a pull request checklist.
- [x] Ignore private plans, local reports, and runtime evidence.
- [x] Mark historical validation numbers as historical instead of deleting them.
- [x] Record the v0.4 analysis boundary in `docs/decisions/0001-v0.4-analysis-scope.md`.

**Done when:** A new contributor can find the current status, contribution rules, security policy, and next task without seeing private working notes.

## Phase 1 - Scope and Measurement

**Status:** `[~] Decision recorded; issue execution pending`

**Goal:** Define what the v0.4 analysis layer is allowed to claim before writing scanner code.

- [x] Write the bounded-analysis decision note.
- [ ] Review and close or rewrite issue `#10` around explicit source/sink scope.
- [ ] Create a 30-case fixture matrix covering safe, unsafe, alias, reassignment, malformed, JS, JSX, TS, TSX, App Router, and Pages Router cases.
- [ ] Record a syntax-scan performance baseline on a small fixture project and a medium monorepo.
- [ ] Define the finding and SARIF compatibility checks before implementation.

**Exit criteria:** The fixture categories, non-goals, performance baseline, and compatibility checks are written down and reviewable.

**Depends on:** Phase 0.

**Unblocks:** Phases 2-5.

## Phase 2 - Review-Signal Messaging

**Status:** `[ ] Next`

**Goal:** Make security language precise before expanding detection depth.

- [ ] Update `secrets/next-public-secret` wording so it signals exposure risk without claiming every match is a confirmed leak.
- [ ] Add safe examples for public configuration versus actual secret material.
- [ ] Add negative tests for public client configuration and documentation/example values.
- [ ] Verify terminal, JSON, Markdown, GitHub, and SARIF messages remain consistent.
- [ ] Add or update the rule documentation and changelog entry.

**Exit criteria:** A user can distinguish “review this exposure” from “this is definitely a leaked credential,” and all formats preserve the same rule ID and safe explanation.

**Depends on:** Phase 1.

**Expected size:** Small, low-risk rule/docs change.

## Phase 3 - Auth Intent and Validation Signals

**Status:** `[ ] Planned`

**Goal:** Reduce keyword-only findings around authentication and API validation.

### Issue `#7` - Auth Intent

- [ ] Define a small allowlist of recognizable auth wrappers and session checks.
- [ ] Distinguish route-handler checks from UI words, comments, and unrelated identifiers.
- [ ] Add positive and negative fixtures for `getServerSession`, `auth`, `requireAuth`, `isAdmin`, middleware, and custom unknown wrappers.
- [ ] Keep unknown wrappers conservative instead of assuming they are safe.

### Issue `#8` - Validation Wrapper

- [ ] Define a small allowlist of recognizable validation calls.
- [ ] Cover direct body parsing and common schema validation patterns.
- [ ] Add negative fixtures for labels, types, comments, and UI-only `validate` names.
- [ ] Document unsupported custom wrappers as intentional limitations.

**Exit criteria:** Auth and validation findings use structural intent signals with fixture-backed negative coverage; no broad keyword expansion is accepted without a noise measurement.

**Depends on:** Phase 1.

**Expected size:** Medium, rule-focused changes.

## Phase 4 - AnalysisFacts and Parse Cache

**Status:** `[ ] Planned`

**Goal:** Create a shared, single-parse foundation without changing findings by itself.

- [ ] Add a parse cache keyed to the existing source-file lifecycle.
- [ ] Define a small `AnalysisFacts` structure for sources, sinks, guards, imports, and route signals.
- [ ] Keep the helper in the rules/core boundary that already owns syntax analysis.
- [ ] Add a cache-hit and cache-miss test without relying on timing alone.
- [ ] Confirm a baseline scan produces the same finding IDs, counts, severities, and reports.

**Exit criteria:** Files are parsed at most once per scan path, tests prove the cache behavior, and the behavior-only diff is empty for existing fixtures.

**Depends on:** Phase 1.

**Unblocks:** Phase 5 and later SQL/XSS pilots.

## Phase 5 - Bounded Command Source-to-Sink Pilot

**Status:** `[ ] Planned`

**Goal:** Improve `injection/command-exec` with explainable same-function flow.

- [ ] Recognize sources: `request.json()`, `request.formData()`, `req.body`, `req.query`, `searchParams.get(...)`, and route parameters.
- [ ] Recognize sinks: `exec`, `execSync`, `spawn`, and `spawnSync` with explicit shell risk.
- [ ] Support direct expressions, direct assignments, and a short identifier alias chain.
- [ ] Stop tracking on reassignment, mutation, closure/callback escape, and function boundary.
- [ ] Add optional evidence-path metadata without changing the rule ID.
- [ ] Keep imported sink detection working when no source can be proven.
- [ ] Add safe command allowlist and early-return guard fixtures where they are syntax-visible.

**Exit criteria:** The pilot reduces measured false positives or adds measured true positives without changing safe fixture behavior, report formats, or default scan startup expectations.

**Depends on:** Phases 1 and 4.

**Expected size:** Medium/high; implement as small vertical PRs.

## Phase 6 - Regression and Performance Gate

**Status:** `[ ] Planned`

**Goal:** Turn the v0.4 quality claim into repeatable evidence.

- [ ] Finish the 30-case synthetic fixture matrix.
- [ ] Add direct/aliased source-to-sink, safe literal, parameterized input, reassignment stop, and function-boundary cases.
- [ ] Cover JS/JSX/TS/TSX and App/Pages Router patterns.
- [ ] Run CLI terminal/JSON/GitHub/SARIF compatibility checks.
- [ ] Measure cold and warm scans on small and medium fixtures.
- [ ] Add a documented real-world smoke command, without making large external repositories a required CI dependency.
- [ ] Record remaining false positives and false negatives as issues or backlog notes.

**Exit criteria:** At least five confirmed noise reductions or five correct additional findings, no critical regression, deterministic outputs, and performance within the decision-note budget.

**Depends on:** Phase 5.

**Unblocks:** v0.4 release decision.

## Phase 7 - Opt-in TypeChecker Spike

**Status:** `[ ] Deferred research`

**Goal:** Measure whether project-aware symbols justify their operational cost.

- [ ] Add an isolated opt-in experiment; do not make it the default scan path.
- [ ] Measure small project and medium monorepo startup/warm costs.
- [ ] Test missing, malformed, and multi-project `tsconfig` behavior.
- [ ] Compare import alias and symbol-resolution accuracy against the syntax baseline.
- [ ] Require syntax fallback when project loading is unsafe or unavailable.
- [ ] Decide whether TypeChecker belongs in v0.5, remains opt-in, or is rejected.

**Exit criteria:** A measured decision exists. No TypeChecker productization happens based only on intuition.

**Depends on:** Phase 6.

**Expected size:** Research spike; no default runtime change.

## Phase 8 - Release and Demo

**Status:** `[ ] Planned after quality gate`

**Goal:** Explain the improved behavior with evidence instead of a feature list.

- [ ] Update rule docs and README examples with before/after signal explanations.
- [ ] Add a short vulnerable-versus-secure terminal demo.
- [ ] Record a 30-45 second demo only after findings and output are stable.
- [ ] Run full validation, pack smoke, and publish dry-run.
- [ ] Prepare concise v0.4 release notes with known limitations.

**Exit criteria:** The release can show what the tool catches, what it intentionally does not claim, and how to report a false positive.

**Depends on:** Phase 6; Phase 7 is informative, not a v0.4 blocker.

## Deferred to v0.5+

- [ ] Productized or default type-aware analysis.
- [ ] Cross-file/interprocedural taint flow and call graphs.
- [ ] Full middleware/auth route graph.
- [ ] Custom rule/plugin loading. Any future plugin model must preserve the no-repo-code-execution boundary.
- [ ] Hosted web demo expansion.
- [ ] VS Code extension or ESLint integration.

## How to Update This File

Only mark a task `[x]` after its implementation or documentation change, focused tests, and relevant validation have passed. Add a short link to the commit, issue, or validation note when a phase is completed. Keep private experiments, credentials, raw external reports, and temporary benchmark output outside this file and outside the repository.
