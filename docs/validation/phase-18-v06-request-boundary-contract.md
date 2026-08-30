# Phase 18: v0.6 Request-Boundary Baseline and Contract

Date: 2026-08-31

Issue: [#29](https://github.com/SetraTheXX/next-secure-check/issues/29)

Status: Complete for the documentation and contract phase; no v0.6 runtime
rule behavior is included.

## Evidence source

The frozen behavioral source is the validated v0.5.0 release tag at
051c3d8db65722b266ff864906a5e863fa4abe7c. The normative boundaries are in
[0003-v0.6-request-boundary-contract.md](../decisions/0003-v0.6-request-boundary-contract.md).

The frozen fixture expectations are:

| Target | Preset | Expected result |
| --- | --- | --- |
| examples/vulnerable-next-app | strict | 0/100, critical, 26 findings |
| examples/secure-next-app | app | 99/100, excellent, 1 LOW finding |
| repository self-scan | app | 100/100, excellent, 0 findings |

The public identity contract remains ruleId:filePath:line:column, with
scannedAt and durationMs excluded from exact-output comparisons. Existing 20
rule identities, CLI flags, terminal/JSON/Markdown/GitHub/SARIF formats, and
deterministic SARIF fingerprints remain protected.

## Contract anchors

The following v0.6 issues are now required to link back to the decision note:

- #30 Proxy and dynamic route parameter intent;
- #31 Server Action and Server Function auth/validation signals;
- #32 bounded unvalidated redirect flow;
- #33 bounded SSRF review flow;
- #34 session-cookie and Next.js configuration signals;
- #35 real-world quality and release feedback gate.

Each slice must add positive, negative, alias, reassignment, malformed, and
framework/language-specific fixtures where its syntax requires them. Each
slice must stop at the documented boundary instead of inferring reachability,
exploitability, or safety.

## Runnable verification

The existing release checks remain the executable contract:

~~~text
pnpm build        -> pass
pnpm typecheck    -> pass
pnpm lint         -> pass
pnpm test         -> 366 package tests + 147 web tests = 513 total
pnpm release:gate -> fixture, summary, help, determinism, SARIF, privacy, pack, and 100/1,000-file benchmark checks pass
~~~

No source, rule, CLI, reporter, package, or Action behavior changed in this
phase. The next implementation slice is #30.

## Acceptance mapping

- Decision and validation notes record the v0.5 baseline and v0.6 contract.
- Following v0.6 issues are anchored to the decision note.
- Existing finding identity and report compatibility are explicit.
- Determinism, privacy, and performance checks remain runnable through the
  existing release gate.
- No v0.6 rule behavior is introduced before the contract phase.
