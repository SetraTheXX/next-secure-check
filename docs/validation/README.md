# Validation Notes

This folder contains manual validation notes for project phases and milestone checks.

Current validation baseline:

```txt
packages: 323 tests
apps/web: 146 tests
total: 469 tests
```

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

## Post-release Real-world Smoke Note

After v0.1.0 was published, `shadcn-ui/ui` and `t3-oss/create-t3-app` were scanned as real-world smoke tests. The scanner did not crash, but the results showed that v0.1 can be noisy on large monorepos, template repositories, generator CLIs, demo/example-heavy paths, and tooling/release scripts.

Those results should be treated as validation and learning notes, not launch claims. They informed the v0.2 context/preset work, the v0.3 regression fixtures, and the v0.4 bounded source-to-sink analysis backlog.
