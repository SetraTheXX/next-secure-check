# Roadmap

Public progress board for `next-secure-check`. It records completed release work, the active release direction, and the next implementable tasks. Historical decisions stay in git history, `CHANGELOG.md`, and `docs/validation`; private working notes do not belong here.

| Field | Value |
| --- | --- |
| Last reviewed | 2026-08-31 |
| Current release | `v0.5.0` stable on npm and GitHub; reusable Action `v1.1.0` is available through `@v1` |
| Next release focus | `v0.6.0` - Next.js request-boundary coverage with bounded, explainable flows |
| Current next task | [Issue #33](https://github.com/SetraTheXX/next-secure-check/issues/33) - add a bounded SSRF source-to-sink review flow |
| Release blocker | No v0.5 release blocker; #33 is the next bounded v0.6 implementation slice |

## Progress Legend

- [x] Completed and validated
- [ ] Planned or not started
- [ ] In progress (labelled explicitly in the phase status)

A checked item means the implementation or documentation exists and the relevant validation was run. A completed phase can still have optional follow-up work listed separately.

## Release Status

- [x] `v0.3.0` published with the context, preset, AST-assisted rule, CLI helper, web demo, and SARIF baseline.
- [x] `v0.4.0` published as the bounded-analysis feature release.
- [x] `v0.4.1` published as the CLI documentation-only patch.
- [x] npm package, workspace package metadata, GitHub Actions validation, pack smoke, and release documentation completed.
- [x] v0.5.0 release validation baseline: 366 package tests, 147 web tests, 513 total tests.
- [x] Current main validation after #32: 401 package tests, 147 web tests, 548 total tests.
- [x] `v0.5.0` package metadata, documentation, demo, npm publication, and exact GitHub release/tag completed.
- [x] Reusable GitHub Action `v1.1.0` released and floating `@v1` tag coordinated with the published `0.5.0` CLI.
- [x] Repository self-scan with `--preset app`: 100/100, `excellent`, 0 findings.
- [x] Vulnerable fixture with `--preset strict`: 0/100, `critical`, 26 findings.
- [x] Secure fixture with `--preset app`: 99/100, `excellent`, 1 LOW finding.
- [x] v0.6 development line: 22 built-in rules; published v0.5.0 baseline remains 20 rules.

### Post-release follow-up (not v0.5 release blockers)

- [x] Publish the aligned `v0.5.0` packages and update the reusable Action after npm availability was verified.
- [ ] [Issue #12](https://github.com/SetraTheXX/next-secure-check/issues/12) - optional demo/video enhancement; separate from the completed v0.5 release gate.
- [ ] Collect feedback from real Next.js users before committing to additional rule surface.
- [ ] Record confirmed false-positive reductions and false-negative recoveries as evidence, not as marketing claims.

### Public evidence

- [x] [v0.4 analysis scope decision](./docs/decisions/0001-v0.4-analysis-scope.md)
- [x] [bounded-flow validation](./docs/validation/phase-6-bounded-flow.md)
- [x] [TypeChecker spike decision](./docs/validation/phase-7-typechecker-spike.md)
- [x] [vulnerable/secure demo validation](./docs/validation/phase-8-demo.md)
- [x] [v0.5 concise terminal summary validation](./docs/validation/phase-9-summary-output.md)
- [x] [v0.5 baseline and bounded-flow contract](./docs/decisions/0002-v0.5-bounded-flow-contract.md)
- [x] [v0.5 baseline validation inventory](./docs/validation/phase-10-v0.5-baseline.md)
- [x] [v0.5 shared AnalysisFacts validation](./docs/validation/phase-11-analysis-facts.md)
- [x] [v0.5 raw SQL bounded-flow validation](./docs/validation/phase-12-raw-sql-bounded-flow.md)
- [x] [v0.5 regression and performance release gate](./docs/validation/phase-13-v05-release-gate.md)
- [x] [v0.5 auth and middleware intent](./docs/validation/phase-15-auth-middleware.md)
- [x] [v0.5 evidence and reporter explanations](./docs/validation/phase-16-evidence-reporter.md)
- [x] [v0.5 release, npm, and Action audit](./docs/validation/phase-17-v05-release.md)
- [x] [v0.6 request-boundary contract](./docs/decisions/0003-v0.6-request-boundary-contract.md)
- [x] [v0.6 request-boundary validation](./docs/validation/phase-18-v06-request-boundary-contract.md)
- [x] [v0.6 Proxy and dynamic route validation](./docs/validation/phase-19-v06-proxy-dynamic-routes.md)
- [x] [v0.6 Server Action guard validation](./docs/validation/phase-20-v06-server-actions.md)
- [x] [v0.6 Server Action guard decision](./docs/decisions/0004-v0.6-server-action-guard-signal.md)
- [x] [v0.6 unvalidated redirect validation](./docs/validation/phase-21-v06-unvalidated-redirects.md)
- [x] [v0.6 unvalidated redirect decision](./docs/decisions/0005-v0.6-unvalidated-redirect-signal.md)
- [x] [v0.4.1 GitHub release](https://github.com/SetraTheXX/next-secure-check/releases/tag/v0.4.1)
- [x] [v0.5.0 GitHub release](https://github.com/SetraTheXX/next-secure-check/releases/tag/v0.5.0)
- [x] [release history](./CHANGELOG.md)

## v0.4.0 - Bounded Analysis Quality

The v0.4 feature release focused on reducing high-value false positives and recovering a small number of missed source-to-sink risks without turning the scanner into a slow, opaque full taint-analysis engine.

### Compatibility rules

- [x] Default scans remain syntax-first and fast.
- [x] Existing rule IDs, report formats, SARIF fingerprints, and CLI flags remain compatible.
- [x] `--preset app` remains the recommended production-app sanity check.
- [x] `strict` and `audit` remain broad review modes with tuning disabled.
- [x] No scanned repository code is executed.
- [x] No unrestricted JavaScript or TypeScript plugin loading was introduced.

### Phase 0 - Repository hygiene

- [x] Add a public root roadmap.
- [x] Keep `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `LICENSE` at the root.
- [x] Add issue templates for bugs, false positives, false negatives, and feature requests.
- [x] Add a pull request checklist.
- [x] Ignore private plans, local reports, credentials, and runtime evidence.
- [x] Mark historical validation numbers as historical instead of deleting them.
- [x] Record the v0.4 analysis boundary in `docs/decisions/0001-v0.4-analysis-scope.md`.

### Phase 1 - Scope and measurement

- [x] Write the bounded-analysis decision note.
- [x] Review and close or rewrite issue #10 around explicit source and sink scope.
- [x] Create a 30-case fixture matrix covering safe, unsafe, alias, reassignment, malformed, JS, JSX, TS, TSX, App Router, and Pages Router cases.
- [x] Record syntax-scan performance on a small fixture project and a medium monorepo.
- [x] Define finding and SARIF compatibility checks before implementation.

### Phase 2 - Review-signal messaging

- [x] Refine `secrets/next-public-secret` so it signals exposure risk without claiming every match is a confirmed leak.
- [x] Add safe examples for public configuration versus actual secret material.
- [x] Add negative tests for public client configuration and documentation/example values.
- [x] Verify terminal, JSON, Markdown, GitHub, and SARIF messages remain consistent.
- [x] Update rule documentation and changelog entries.

### Phase 3 - Auth intent and validation signals

- [x] Define a small allowlist of recognizable auth wrappers and session checks.
- [x] Distinguish route-handler checks from UI words, comments, and unrelated identifiers.
- [x] Add positive and negative fixtures for `getServerSession`, `auth`, `requireAuth`, `isAdmin`, middleware, and unknown wrappers.
- [x] Define a small allowlist of recognizable validation calls.
- [x] Cover direct body parsing and common schema validation patterns.
- [x] Document unsupported custom wrappers as intentional limitations.
- [x] Close issues #7 and #8 with fixture-backed validation.

### Phase 4 - AnalysisFacts and parse cache

- [x] Add a parse cache keyed to the existing source-file lifecycle.
- [x] Define `AnalysisFacts` for sources, sinks, guards, imports, and route signals.
- [x] Keep the helper at the existing rules/core boundary.
- [x] Add cache-hit and cache-miss tests without relying on timing alone.
- [x] Confirm baseline finding IDs, counts, severities, and reports remain stable.

### Phase 5 - Bounded command source-to-sink pilot

- [x] Recognize request-derived sources such as `request.json()`, `request.formData()`, `req.body`, `req.query`, `searchParams.get(...)`, and route parameters.
- [x] Recognize `exec`, `execSync`, `spawn`, and `spawnSync` sinks with existing import and namespace detection.
- [x] Support direct expressions, direct assignments, and a short identifier alias chain.
- [x] Stop tracking on reassignment, mutation, closure/callback escape, and function boundary.
- [x] Add optional evidence-path metadata without changing the rule ID.
- [x] Keep imported sink detection working when no source can be proven.
- [x] Add safe command allowlist and early-return guard fixtures where syntax makes them visible.

### Phase 6 - Regression and performance gate

- [x] Finish the 30-case synthetic fixture matrix.
- [x] Cover direct/aliased source-to-sink, safe literal, parameterized input, reassignment stop, and function-boundary cases.
- [x] Cover JS/JSX/TS/TSX and App/Pages Router patterns.
- [x] Run CLI terminal, JSON, GitHub, and SARIF compatibility checks.
- [x] Measure cold and warm scans on small and medium fixtures.
- [x] Document real-world smoke commands without making large external repositories a CI dependency.
- [x] Record remaining false positives and false negatives as validation notes.
- [x] Document five confirmed noise reductions or five correct additional findings with no critical regression.

### Phase 7 - Opt-in TypeChecker spike

- [x] Add an isolated opt-in experiment; do not make it the default scan path.
- [x] Measure small-project and medium-fixture startup costs.
- [x] Test missing, malformed, and multi-project `tsconfig` behavior.
- [x] Compare import alias and symbol-resolution accuracy against the syntax baseline.
- [x] Require syntax fallback when project loading is unsafe or unavailable.
- [x] Keep TypeChecker isolated until a broader productization study.
- [x] Close issue #11 with the measured decision and validation note.

### Phase 8 - Release and demo

- [x] Update rule docs and README examples with before/after signal explanations.
- [x] Record the vulnerable-versus-secure terminal demo.
- [x] Complete correctness, dependency, CI, and package-metadata audits.
- [x] Run full validation, pack smoke, publish dry-run, and the v0.4.1 CLI patch.
- [x] Prepare concise v0.4 release notes with known limitations.
- [ ] Complete optional post-release media editing and privacy review under issue #12.

## v0.5.0 - Explainable Bounded Analysis

### Product goal

Improve the quality of evidence without turning the product into a default full taint-analysis engine.

The working theme is:

> Better evidence, fewer guesses.

The first production slice should be a bounded `injection/raw-sql-concat` flow built on the existing `AnalysisFacts` and AST utilities. It should be small enough to measure, explain, and roll back without changing the scanner's public contract.

### v0.5 issue map

- [x] [#13 Baseline and bounded-flow contract](https://github.com/SetraTheXX/next-secure-check/issues/13)
- [x] [#14 Shared `AnalysisFacts` foundation](https://github.com/SetraTheXX/next-secure-check/issues/14)
- [x] [#15 Raw SQL bounded source-to-sink pilot](https://github.com/SetraTheXX/next-secure-check/issues/15)
- [x] [#16 XSS source and sanitizer refinement](https://github.com/SetraTheXX/next-secure-check/issues/16)
- [x] [#17 Auth and middleware intent signals](https://github.com/SetraTheXX/next-secure-check/issues/17)
- [x] [#18 Evidence and reporter explanations](https://github.com/SetraTheXX/next-secure-check/issues/18)
- [x] [#19 Regression and performance release gate](https://github.com/SetraTheXX/next-secure-check/issues/19)
- [x] [#20 v0.5 release and feedback loop](https://github.com/SetraTheXX/next-secure-check/issues/20)

### v0.5 compatibility rules

- [x] Keep `default` syntax-first and fast.
- [x] Keep `--preset app` as the recommended application-focused scan.
- [x] Keep `strict` and `audit` broad, with tuning disabled.
- [x] Preserve rule IDs, CLI flags, report formats, SARIF locations, and deterministic fingerprints unless a change is explicitly reviewed.
- [x] Do not execute scanned repository code.
- [x] Do not add unrestricted JS/TS plugin loading.
- [x] Do not make TypeChecker or project graph loading the default path.
- [x] Treat exact fixture counts as regression alarms, not immutable product requirements. Any changed result must be intentional, reviewed, and documented.

### Metrics for v0.5

- [ ] Measure confirmed false-positive reductions and confirmed additional findings separately on a reviewed real-world corpus after release.
- [x] Track fixture matrix coverage, safe-case preservation, determinism, and report compatibility.
- [x] Record Node version, OS, CPU, repository size, cold/warm state, median, p95, and analysis-overhead ratio for performance measurements.
- [x] Keep test count as a health signal, not as the primary release KPI.
- [x] Require a validation note for behavior changes that affect vulnerable or secure fixture output.

## v0.5 Phase 0 - Baseline and analysis contract (#13)

- [x] **Phase status:** Complete; baseline and contract recorded locally on 2026-08-29

**Purpose:** Freeze the current behavior and define the narrow flow model before writing new rule logic.

- [x] Capture current self-scan, vulnerable-fixture, and secure-fixture summaries.
- [x] Capture finding IDs, severity/confidence, score, risk, and report output for the baseline.
- [x] Define the `AnalysisFacts` contract for source, sink, guard, alias, reassignment, and evidence-path facts.
- [x] Define the supported flow boundary: same function, local scope, direct assignment, and at most a short identifier alias chain.
- [x] Define stop conditions: reassignment, mutation, closure/callback escape, function boundary, dynamic property flow, and cross-file flow.
- [x] Record non-goals: call graphs, heap/property aliasing, full CFG, dynamic resolution, and default TypeChecker analysis.
- [x] Write a short v0.5 decision note before implementation.

**Exit criteria:** A reviewer can tell which flows are supported, which are intentional false negatives, and how a changed fixture result will be judged.

**Expected size:** Small, documentation and test design.

## v0.5 Phase 1 - Shared bounded-flow foundation (#14)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-11-analysis-facts.md](./docs/validation/phase-11-analysis-facts.md)

**Purpose:** Extend the existing parse-cache and `AnalysisFacts` layer without duplicating rule-specific AST walks.

- [x] Reuse the existing one-parse-per-source-file lifecycle.
- [x] Add source, sink, guard, alias, and evidence facts only where they have rule-specific meaning.
- [x] Avoid a universal `sanitized` or `safe` flag; SQL, HTML, and command guards must remain separate.
- [x] Add explicit facts for alias creation, reassignment, and function-boundary stop.
- [x] Add unit tests for direct expressions, one-to-two aliases, reassignment, mutation, closure, and malformed TS/TSX.
- [x] Keep the existing direct pattern matchers as a fallback when no source can be proven.

**Exit criteria:** The foundation is reusable, deterministic, and produces no behavior change until a rule opts into it.

**Expected size:** Medium.

## v0.5 Phase 2 - Raw SQL bounded flow pilot (#15)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-12-raw-sql-bounded-flow.md](./docs/validation/phase-12-raw-sql-bounded-flow.md)

**Purpose:** Distinguish a value that reaches a recognized SQL sink from a SQL-looking string that never reaches one.

- [x] Recognize direct request-derived sources: `request.json()`, `request.formData()`, `req.body`, `req.query`, and `searchParams.get(...)`.
- [x] Recognize direct sinks: `db.query`, `connection.query`, `connection.execute`, `pool.query`, `client.query`, `$queryRaw`, and `$executeRaw`.
- [x] Track direct expressions and a short same-function alias chain into a query sink.
- [x] Do not report a plain SQL-like template assigned to a variable when no direct sink is visible.
- [x] Do not report clearly parameterized query calls with placeholder parameters.
- [x] Stop tracking on reassignment, mutation, function boundary, and cross-file flow.
- [x] Preserve app/api severity and context tuning; strict/audit must keep their current behavior.
- [x] Add a concise evidence path when a source-to-sink path is proven.

**Exit criteria:** The pilot demonstrates measured noise reduction or measured additional true findings, preserves safe parameterized-query fixtures, keeps report formats compatible, and documents intentional false negatives such as variable flow across functions.

**Expected size:** Medium/high, split into small PRs.

## v0.5 Phase 3 - XSS source and sanitizer refinement (#16)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-14-xss-refinement.md](./docs/validation/phase-14-xss-refinement.md)

**Purpose:** Improve the distinction between static HTML, sanitized content, and values that may carry untrusted input into `dangerouslySetInnerHTML`.

- [x] Keep JSX attribute syntax as the first boundary.
- [x] Recognize direct variable and member-expression values as review signals.
- [x] Recognize a small, documented sanitizer allowlist such as `DOMPurify.sanitize`, `sanitizeHtml`, and `sanitizeMarkdown`.
- [x] Do not assume an unknown custom wrapper is safe.
- [x] Keep static literal HTML out of the default finding path.
- [x] Add negative fixtures for normal JSX text, unrelated props, static literals, and sanitized values.
- [x] Add positive fixtures for request-derived, member-expression, and unsanitized values.
- [x] Keep context tuning and strict/audit behavior explicit in tests.

**Exit criteria:** XSS findings explain whether the value is literal, sanitized, or variable-based without claiming source reachability that the analyzer cannot prove.

**Expected size:** Medium.

## v0.5 Phase 4 - Auth and middleware intent (#17)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-15-auth-middleware.md](./docs/validation/phase-15-auth-middleware.md)

**Purpose:** Reduce keyword-only assumptions around authentication, authorization, route protection, and rate limiting.

- [x] Keep route-handler detection separate from UI/component names.
- [x] Track only a small allowlist of recognizable session/auth wrappers and role checks.
- [x] Model same-app middleware signals conservatively; do not build a full route graph in this phase.
- [x] Distinguish a route-local auth check from a generic identifier such as `role`, `admin`, or `permission`.
- [x] Add positive and negative fixtures for App Router, Pages Router, middleware, wrappers, and unknown custom helpers.
- [x] Preserve unknown-wrapper findings as review signals instead of assuming safety.
- [x] Measure false-positive changes on admin, login, register, and validation rules separately.

**Exit criteria:** Admin/auth findings use structural intent evidence and do not treat component/sidebar/demo paths as protected API routes or unprotected API routes without route evidence.

**Expected size:** Medium/high.

## v0.5 Phase 5 - Evidence and reporter UX (#18)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-16-evidence-reporter.md](./docs/validation/phase-16-evidence-reporter.md)

**Purpose:** Make a finding easier to review without changing its rule identity or report contract.

- [x] Show a concise source-to-sink evidence path when one is proven.
- [x] Keep context and context reason visible in JSON, terminal, Markdown, GitHub, and SARIF outputs.
- [x] Keep raw secrets, tokens, local paths, and stack traces out of user-facing output.
- [x] Improve `explain` guidance for common false-positive and false-negative boundaries.
- [x] Provide an opt-in concise terminal summary for quick reviews and README demos while preserving the detailed default report.
- [x] Add deterministic reporter tests for evidence paths, empty findings, SARIF fingerprints, and secret redaction.
- [x] Avoid adding a new output format when existing formats can carry the information.

**Exit criteria:** A reviewer can answer “why was this reported?” from the result itself without mistaking the evidence for proof of exploitation.

**Expected size:** Small/medium.

## v0.5 Phase 6 - Regression, benchmark, and release gate (#19)

- [x] **Phase status:** Complete; implementation and validation recorded in [phase-13-v05-release-gate.md](./docs/validation/phase-13-v05-release-gate.md)

**Purpose:** Turn the quality claim into repeatable evidence before publishing.

- [x] Expand and freeze the synthetic/regression fixture coverage for SQL, XSS, auth, middleware, safe wrappers, aliases, reassignment, and malformed input.
- [x] Keep external repositories as opt-in smoke tests, not required CI dependencies.
- [x] Add and document a benchmark command for small fixtures and a medium monorepo corpus.
- [x] Record cold/warm median and p95 measurements with environment details.
- [x] Compare fixture results by rule, context, severity, confidence, and reviewed signal inventory.
- [x] Run build, typecheck, lint, package/web tests, CLI smoke, JSON/SARIF parse, and pack dry-run.
- [x] Include concise-summary CLI smoke, determinism, line-count, and public-output privacy checks in the release gate.
- [x] Require a release note when fixture counts change intentionally.
- [x] Update README, CHANGELOG, and validation notes; GitHub release-page notes remain part of the v0.5 publication in #20.

**Exit criteria:** No critical regression, deterministic outputs, reviewed fixture changes, compatible reports, and performance within the documented budget.

**Expected size:** Medium.

## v0.5 Phase 7 - Release and feedback loop (#20)

- [x] **Phase status:** Complete; v0.5.0 npm/GitHub publication and Action coordination were verified on 2026-08-29. Real-user feedback remains post-release follow-up.

- [x] Review open feedback; no repeated new report was present, and #12 remains an optional media follow-up.
- [x] Confirm the v0.5 release gate passes before the manual publication handoff.
- [x] Keep npm package versions and internal workspace dependency versions consistent.
- [x] Run npm pack and recursive publish dry-run before any real publish.
- [x] Publish all four `0.5.0` packages and verify npm `latest`.
- [x] Update the reusable Action to `next-secure-check@0.5.0`, release `v1.1.0`, and coordinate the floating `@v1` tag.
- [x] Record the release commit `051c3d8db65722b266ff864906a5e863fa4abe7c` and [GitHub tag/release `v0.5.0`](https://github.com/SetraTheXX/next-secure-check/releases/tag/v0.5.0).
- [x] Publish a short demo/validation note with honest boundaries in the repository.
- [ ] Re-measure user-facing noise on a small, reviewed corpus after release.

The phase is complete. Real-user feedback and the optional demo/video follow-up
remain separate post-release work and must be recorded as reproducible issues.

**Exit criteria:** v0.5 can be installed, reproduced, reviewed, and rolled back without changing the no-repo-code-execution boundary.

**Expected size:** Small/medium release work.

## v0.6.0 - Next.js Request-Boundary Coverage

The v0.6 line extends the same syntax-first, bounded-analysis model to request
boundaries that are important in current Next.js applications. It is a quality
release, not a pivot to full taint analysis: every new signal must have a
documented source/sink/guard boundary, honest evidence, deterministic output,
and a reviewed fixture contract.

### Phase 0 - Baseline and request-boundary contract (#29)

- [x] Phase status: Complete; the v0.5 baseline and v0.6 contract are recorded in the decision and validation notes.
- [x] Link issues #30–#35 to their source/sink/guard/stop boundaries.
- [x] Preserve existing rule IDs, report identity, output formats, determinism, privacy, and performance rules.
- [x] Confirm no v0.6 runtime rule behavior was introduced before the contract.
- [x] Run the existing build, typecheck, lint, test, and release-gate checks.

**Exit criteria:** A reviewer can implement the next slice without guessing
which request boundary is supported, what evidence is allowed, or where the
analysis must stop.

### Implementation order

1. [x] [Issue #29](https://github.com/SetraTheXX/next-secure-check/issues/29) - freeze the v0.5 baseline and v0.6 request-boundary contract.
2. [x] [Issue #30](https://github.com/SetraTheXX/next-secure-check/issues/30) - support Next.js 16 Proxy and dynamic route parameter intent.
3. [x] [Issue #31](https://github.com/SetraTheXX/next-secure-check/issues/31) - add bounded Server Action and Server Function auth/validation signals.
4. [x] [Issue #32](https://github.com/SetraTheXX/next-secure-check/issues/32) - add bounded unvalidated redirect source-to-sink flow.
5. [ ] [Issue #33](https://github.com/SetraTheXX/next-secure-check/issues/33) - add bounded SSRF source-to-sink review flow.
6. [ ] [Issue #34](https://github.com/SetraTheXX/next-secure-check/issues/34) - refine session-cookie and Next.js config hardening signals.
7. [ ] [Issue #35](https://github.com/SetraTheXX/next-secure-check/issues/35) - run the real-world quality gate and release feedback loop.

### v0.6 Phase 1 - Proxy and dynamic route boundaries (#30)

- [x] Phase status: Complete; implementation and validation are recorded in [phase-19-v06-proxy-dynamic-routes.md](./docs/validation/phase-19-v06-proxy-dynamic-routes.md).
- [x] Recognize root and app/package-scoped `proxy.ts`/`proxy.js` entry points alongside legacy middleware files.
- [x] Preserve same-app auth and rate-limit matcher behavior without building a route graph.
- [x] Recognize static matcher strings, arrays, and simple matcher-object sources while ignoring dynamic values.
- [x] Add bounded API request-source evidence for route params and search/request values without changing the existing rule ID.
- [x] Add validation, allowlist, normalization-guard, App Router, Pages Router, JavaScript, TypeScript, malformed-input, and safe-negative regression coverage.

**Exit criteria:** Proxy and dynamic route signals are visible only at recognized
boundaries, evidence remains bounded and deterministic, existing middleware
behavior stays compatible, and the full release gate passes.

### v0.6 Phase 2 - Server Action and Server Function guards (#31)

- [x] Phase status: Complete; implementation and validation are recorded in [phase-20-v06-server-actions.md](./docs/validation/phase-20-v06-server-actions.md).
- [x] Add one separately documented `auth/server-action-without-guards` signal without changing the existing v0.5 rule identities.
- [x] Recognize file-level and inline `use server` boundaries, including nested inline Server Functions with direct action/request input.
- [x] Reuse same-function auth and validation intent with bounded input aliases, static guards, reassignment stops, and unknown-wrapper negatives.
- [x] Add dedicated rule explanation, rule documentation, compatibility decision, and malformed syntax coverage.

**Exit criteria:** Server Action signals are explicit, bounded, explainable, and
privacy-safe; partial controls lower deterministically; existing v0.5 fixture
and report contracts remain unchanged; and the full release gate passes.

### v0.6 Phase 3 - Unvalidated redirect source-to-sink flow (#32)

- [x] Phase status: Complete; implementation and validation are recorded in [phase-21-v06-unvalidated-redirects.md](./docs/validation/phase-21-v06-unvalidated-redirects.md).
- [x] Add one separately documented `redirect/unvalidated-target` signal without changing the published v0.5 rule identities.
- [x] Recognize bounded request/query/route/form/body sources and imported App Router, `NextResponse.redirect`, and Pages Router redirect sinks.
- [x] Recognize static destination equality, allowlists, safe internal-path checks, and same-origin/host guard forms without trusting normalization alone.
- [x] Stop at cross-file/cross-function flow, dynamic properties, unknown wrappers, reassignment/mutation, unsupported sinks, client components, and aliases beyond two hops.
- [x] Add App Router, Pages Router, JavaScript/TypeScript, malformed-input, privacy, deterministic-output, and CLI explanation coverage.

**Exit criteria:** Redirect signals are bounded, explainable, privacy-safe, and
deterministic; recognized guards suppress only when their syntax proves the
relevant relationship; the historical v0.5 baseline remains unchanged; and
the full release gate passes.

### v0.6 compatibility guardrails

- [x] Preserve existing rule IDs, CLI flags, output formats, and deterministic SARIF fingerprints; the separately documented #31 rule addition does not repurpose an existing identity.
- [ ] Keep the default path syntax-first, bounded, and fast; TypeChecker remains opt-in research rather than the default engine.
- [ ] Keep cross-file/cross-function taint, full CFG, heap aliasing, dynamic resolution, full route graphs, and unrestricted plugins out of scope.
- [ ] Never execute code from a scanned repository.
- [ ] Treat each finding as an explainable review signal, not proof of exploitability.

**v0.6 success metric:** better request-boundary evidence and fewer unsupported
guesses, measured by reviewed fixture changes, noise/false-positive notes,
determinism, privacy, and performance—not by rule count alone.

## Deferred beyond the first v0.6 slices

These are valuable, but should not block the v0.5 bounded-analysis quality work:

- [ ] Productized or default TypeChecker/type-aware analysis after a measured opt-in study.
- [ ] Cross-file/interprocedural taint flow, call graphs, heap/property aliasing, and full CFG analysis.
- [ ] Full middleware/auth route graph and framework-wide reachability.
- [ ] Unrestricted custom JavaScript/TypeScript plugin loading.
- [ ] A custom rule system with a reviewed security model and no repository-code execution.
- [ ] Hosted web demo expansion and distributed public-service operations.
- [ ] VS Code extension or ESLint integration.
- [ ] Broad framework support outside the Next.js-focused scope.

## Recommended implementation order

1. [x] v0.5 Phase 0 - baseline and analysis contract.
2. [x] v0.5 Phase 1 - shared bounded-flow foundation.
3. [x] v0.5 Phase 2 - raw SQL bounded flow pilot.
4. [x] v0.5 Phase 6 - regression and performance gate for the SQL pilot.
5. [x] v0.5 Phase 3 - XSS source/sanitizer refinement.
6. [x] v0.5 Phase 4 - auth and middleware intent.
7. [x] v0.5 Phase 5 - evidence/reporting polish.
8. [x] v0.5 Phase 7 - release and feedback loop (npm/GitHub/Action publication complete; feedback remains follow-up).

This order deliberately puts measurement before deeper analysis. It also keeps TypeChecker and plugins out of the default path until real corpus evidence shows that their accuracy value justifies their cost.

## How to update this file

Only mark a task [x] after the implementation or documentation change, focused tests, and relevant validation have passed. Add a short link to the commit, issue, or validation note when a phase is completed. Keep private experiments, credentials, raw external reports, and temporary benchmark output outside this file and outside the repository.
