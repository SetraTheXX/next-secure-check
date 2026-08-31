# Validation Notes

This folder contains manual validation notes for project phases and milestone checks.

Frozen #13 pre-implementation validation baseline:

```txt
packages: 323 tests
apps/web: 146 tests
total: 469 tests
```

The 323-package-test count above is the frozen #13 pre-implementation
baseline. The post-#14 validation count was 326 package tests, 146 web tests,
and 472 total tests; see [phase-11-analysis-facts.md](./phase-11-analysis-facts.md).
The #15 raw-SQL pilot recorded 337 package tests, 146 web tests, and 483 total
tests; subsequent review hardening, the #19 reporter gate, and the #16 XSS
refinement bring the count to 342 package tests, 146 web tests, and 488 total
 tests. The #17 auth/middleware intent work adds the current 20 regression
 checks, bringing the working-line count to 362 package tests, 146 web tests,
 and 508 total tests. Issue #18 reporter and web-export coverage brings the
 current count to 366 package tests, 147 web tests, and 513 total tests. See
[phase-12-raw-sql-bounded-flow.md](./phase-12-raw-sql-bounded-flow.md) and
[phase-13-v05-release-gate.md](./phase-13-v05-release-gate.md) and
[phase-15-auth-middleware.md](./phase-15-auth-middleware.md).

The #18 evidence/reporter explanation contract, privacy behavior, bounded-path
presentation, and CLI false-negative guidance are documented in
[phase-16-evidence-reporter.md](./phase-16-evidence-reporter.md).

The #20 v0.5 release audit, package publication, coordinated Action release,
demo contract, and feedback review are documented in
[phase-17-v05-release.md](./phase-17-v05-release.md).

The #29 v0.6 request-boundary baseline, compatibility contract, slice
boundaries, and performance/privacy budget are documented in
[phase-18-v06-request-boundary-contract.md](./phase-18-v06-request-boundary-contract.md)
and
[0003-v0.6-request-boundary-contract.md](../decisions/0003-v0.6-request-boundary-contract.md).

The #30 Proxy/dynamic-route slice, static matcher handling, bounded request
source evidence, and validation/allowlist guard coverage are documented in
[phase-19-v06-proxy-dynamic-routes.md](./phase-19-v06-proxy-dynamic-routes.md).

The #31 Server Action and Server Function boundary, same-function auth and
validation intent, bounded aliases, and malformed-input coverage are documented
in [phase-20-v06-server-actions.md](./phase-20-v06-server-actions.md).

The #32 bounded unvalidated redirect source-to-sink flow, recognized Next.js
redirect sinks, destination guards, stop conditions, and validation coverage
are documented in
[phase-21-v06-unvalidated-redirects.md](./phase-21-v06-unvalidated-redirects.md).

The #33 bounded SSRF source-to-sink flow, recognized outbound HTTP sinks,
URL-like request sources, destination guards, stop conditions, and shared-flow
validation are documented in
[phase-22-v06-ssrf-flow.md](./phase-22-v06-ssrf-flow.md).

The post-#33 working line contained 426 package tests, 147 web tests, and 573
total tests. After #34, the current working line contains 453 package tests,
147 web tests, and 600 total tests. The published v0.5.0 baseline remains
separately frozen at 20 rules; the five v0.6 rules are available only from the
unreleased `v0.6.0` candidate line.

The #34 session-cookie, security-header, and broad image-domain signals,
including privacy-safe evidence, App/Pages Router coverage, JavaScript and
TypeScript parsing, CommonJS config discovery, and the release-gate result are
documented in
[phase-23-v06-config-hardening.md](./phase-23-v06-config-hardening.md) and
[0007-v0.6-config-hardening-signals.md](../decisions/0007-v0.6-config-hardening-signals.md).

The #35 v0.6 quality gate, minimized development-rule matrix, opt-in
real-world smoke observations, package/Action contract, and independent
review handoff are documented in
[phase-24-v06-quality-gate.md](./phase-24-v06-quality-gate.md).

Historical v0.1 baseline:

```txt
packages: 118 tests
apps/web: 143 tests
total: 261 tests
```

Phase 0-3 do not have separate manual validation reports in this folder. Those phases were validated through automated tests, CI checks, README/CHANGELOG updates, and commit history.

Phase 4 has a separate manual validation note because the web demo required additional end-to-end checks across the UI, API, public GitHub repository scanning flow, exports, and CLI smoke behavior.

Phase 6 external review fixes are documented separately because they were a focused bugfix and hardening pass after Claude/Codex review, covering CLI behavior, rule false positives, web hardening, and SARIF output quality.

The current v0.4 bounded command-flow matrix and performance gate are documented in [phase-6-bounded-flow.md](./phase-6-bounded-flow.md).

The isolated TypeChecker measurement and syntax fallback decision are documented in [phase-7-typechecker-spike.md](./phase-7-typechecker-spike.md).

The reproducible vulnerable-versus-secure terminal demo and current rule-level signal notes are documented in [phase-8-demo.md](./phase-8-demo.md).

The v0.5 concise terminal summary contract and README demo validation are documented in [phase-9-summary-output.md](./phase-9-summary-output.md).

The v0.5 baseline, finding identity inventory, report compatibility contract,
and bounded-flow boundaries are documented in
[phase-10-v0.5-baseline.md](./phase-10-v0.5-baseline.md). The decision record is
[0002-v0.5-bounded-flow-contract.md](../decisions/0002-v0.5-bounded-flow-contract.md).

The shared `AnalysisFacts` foundation, bounded-flow fact vocabulary, and #14
validation results are documented in
[phase-11-analysis-facts.md](./phase-11-analysis-facts.md).

The #15 raw-SQL bounded source-to-sink pilot, route-parameter fact fix,
fixture stability, and directional performance sample are documented in
[phase-12-raw-sql-bounded-flow.md](./phase-12-raw-sql-bounded-flow.md).

The #19 regression, benchmark, deterministic-output, public-privacy, and pack
release gate are documented in
[phase-13-v05-release-gate.md](./phase-13-v05-release-gate.md).

The #16 XSS source/sanitizer refinement, documented sanitizer allowlist,
bounded request-source evidence, and unknown-wrapper regression cases are
documented in [phase-14-xss-refinement.md](./phase-14-xss-refinement.md).

The #17 auth/middleware intent refinement, route-handler gating, structural
rate-limit signals, known-provider imports, unknown-wrapper behavior, and
same-app middleware scope are documented in
[phase-15-auth-middleware.md](./phase-15-auth-middleware.md).

## Post-release Real-world Smoke Note

After v0.1.0 was published, `shadcn-ui/ui` and `t3-oss/create-t3-app` were scanned as real-world smoke tests. The scanner did not crash, but the results showed that v0.1 can be noisy on large monorepos, template repositories, generator CLIs, demo/example-heavy paths, and tooling/release scripts.

Those results should be treated as validation and learning notes, not launch claims. They informed the v0.2 context/preset work, the v0.3 regression fixtures, and the v0.4 bounded source-to-sink analysis backlog.
