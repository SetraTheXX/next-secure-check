# Phase 7: Opt-in TypeChecker Spike

Date: 2026-08-24

## Scope

This was an isolated TypeScript `Program`/`TypeChecker` measurement spike. It does not change the default scanner path, CLI behavior, reporter output, or package runtime API. No dependency or lockfile change was required; `typescript` was already a runtime dependency of `@next-secure-check/rules`.

## Accuracy Probe

- A valid temporary `tsconfig.json` was loaded into a `Program`.
- TypeChecker resolved an aliased `child_process` import in `src/api.ts`.
- TypeChecker rejected a shadowed `run(...)` parameter in `src/shadow.ts`.
- The syntax baseline saw two command call sites; symbol resolution accepted only the imported sink call.
- This demonstrates useful syntax-level precision for import aliases and local shadowing without introducing cross-file taint flow.

## Fallback Probe

The spike falls back to the existing syntax scan when:

- `tsconfig.json` is missing.
- The config is malformed or cannot be read safely.
- The root config contains multiple project references.

Each fallback case completed without throwing and returned the expected clean syntax result for its fixture.

## Performance Measurement

Local `Program` startup measurements:

```txt
small fixture: 12 files, 927.1ms
medium fixture: 120 files, 912.6ms
```

Both measurements stayed below the decision-note budgets of 2 seconds for a small project and 8 seconds for a medium project. These are directional local measurements; they include project creation and should be repeated on representative monorepos before productization.

## Validation Snapshot

- Package tests: 309 passed.
- Web tests: 143 passed.
- Total: 452 passed.

## Decision

TypeChecker provides real accuracy value for symbol alias and shadowing questions, but it introduces project configuration and startup-cost risk. Keep it isolated and opt-in for now. It should not become the default v0.4 scan path. A future productized mode needs broader repository measurements, project-reference handling, cache strategy, and a safe syntax fallback before release.

## Intentional Non-goals

This spike does not implement cross-file taint flow, call graphs, full type-aware rules, CLI flags, or a TypeChecker-backed finding model. Those remain future design work rather than implicit behavior.
