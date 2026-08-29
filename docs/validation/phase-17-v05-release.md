# Phase 17: v0.5 Release Audit and Feedback Handoff

Date: 2026-08-29

Issue: [#20](https://github.com/SetraTheXX/next-secure-check/issues/20)

Status: Complete. The `v0.5.0` packages are published on npm, the GitHub
release and tag are recorded on the validated release commit, and the
reusable Action is coordinated through `v1.1.0` and the floating `v1` tag.
Post-release feedback remains an intentionally separate follow-up.

## Scope

This phase turns the completed v0.5 implementation work into a reviewable
published release. It covers version alignment, public documentation, the
reproducible terminal demo, packaging checks, npm registry verification, the
coordinated Action release, and a final local audit. It does not make a
real-world accuracy claim or treat the release as a replacement for manual
security review.

The GitHub [`v0.5.0` release](https://github.com/SetraTheXX/next-secure-check/releases/tag/v0.5.0)
and tag target commit `051c3d8db65722b266ff864906a5e863fa4abe7c`, the commit
validated by the release gate and CI run `33258034052`.

The scanner continues to read repository files as input and never executes
code from the scanned repository.

## Published package matrix

| Package | Release version | Publication status |
| --- | ---: | --- |
| `next-secure-check` | `0.5.0` | Published on npm; `latest` points to `0.5.0` |
| `@next-secure-check/core` | `0.5.0` | Published on npm |
| `@next-secure-check/rules` | `0.5.0` | Published on npm |
| `@next-secure-check/reporter` | `0.5.0` | Published on npm |

The private workspace and local web application remain `0.0.0`; they are not
published npm packages. Internal package references remain `workspace:*` and
are resolved by the workspace publish flow.

The reusable `v1` GitHub Action is now released as `v1.1.0` and runs the
available npm `next-secure-check@0.5.0` package. The floating `@v1` consumer
tag was updated only after the npm registry and Action smoke checks passed.

## Feedback review

The issue review found:

- #20, this release and feedback handoff, now complete;
- #12, the optional demo/video editing follow-up.

No repeated new user report was available to convert into a separate issue.
The post-release feedback loop remains open and should use reviewed real
repositories, not unverified benchmark or accuracy claims.

## Verification protocol

The release audit runs:

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm release:gate
pnpm audit --prod --audit-level high
pnpm -r publish --dry-run --no-git-checks
```

Additional smoke coverage includes:

- CLI version, root help, scan help, rule listing, rule explanation, unknown
  rule handling, and invalid `--summary`/JSON combinations;
- `--fail-on high` and `--fail-on critical` on vulnerable and secure fixtures;
- JSON, Markdown, GitHub, and SARIF output generation and JSON parsing;
- repeated fixture output and SARIF determinism;
- package tarball contents and an isolated local-install/CLI-help simulation;
- public-output checks for absolute paths, credential-shaped values, raw secret
  evidence, and the privacy-fixture marker;
- GIF dimensions, duration, frame count, and visual readability after VHS
  regeneration.

The fixture contract remains:

| Target | Preset | Expected result |
| --- | --- | --- |
| `examples/vulnerable-next-app` | `strict` | `0/100`, `critical`, 26 findings |
| `examples/secure-next-app` | `app` | `99/100`, `excellent`, 1 LOW finding |
| repository self-scan | `app` | `100/100`, `excellent`, 0 findings |

These are deterministic regression expectations, not universal accuracy or
exploitability guarantees.

## Audit evidence

The final local release run passed:

```text
pnpm build       PASS
pnpm typecheck   PASS
pnpm lint        PASS
pnpm test        PASS — 366 package tests, 147 web tests, 513 total
pnpm audit       PASS — no known vulnerabilities found
```

The release gate passed the frozen inventories, report compatibility,
deterministic JSON/SARIF, public-output privacy, concise-summary, and pack
checks. Its current machine snapshot was:

```text
100 files: cold scanner 108.7/134.6 ms median/p95; cold process 471.6/562.7 ms; warm 71.7/140.1 ms; overhead 1.11x
1,000 files: cold scanner 744.2/777.3 ms median/p95; cold process 1072.1/1121.5 ms; warm 674.4/703.0 ms; overhead 1.08x
warm scaling ratio: 9.41x
```

`pnpm -r publish --dry-run --no-git-checks` recognized all four `0.5.0`
publishable packages. Four local tarballs were then installed together in a
disposable directory; `npm ls` resolved the CLI, core, rules, and reporter at
`0.5.0`. The installed CLI reported `0.5.0`, exposed `scan --help`, and
reproduced the secure fixture result of `99/100`, `excellent`, and one LOW
finding.

The live npm registry check on 2026-08-29 reported `0.5.0` for all four
published packages, with `next-secure-check` dist-tag `latest` also at
`0.5.0`. `npx --yes next-secure-check@0.5.0 --version` reported `0.5.0`.
The GitHub Action release `v1.1.0` and the floating `v1` tag were verified to
resolve to the commit containing the `0.5.0` Action pin, and the reusable
Action smoke workflow passed.

The bug audit found and corrected three release-quality issues: a stale README
validation count (`362/146/508` instead of the current `366/147/513`), release
line package version drift (`0.4.1` CLI versus `0.4.0` internal packages), and
a Windows `shell: true` invocation in the release gate that emitted Node's
shell-spawn deprecation warning. The Action pin was then updated from
`0.4.1` to the published `0.5.0` line and released through `v1.1.0`.

## Demo contract

The checked-in [`next-secure-check.tape`](../demo/next-secure-check.tape)
records the published `v0.5.0` CLI version and three labeled concise
`--summary` scans: vulnerable/strict, secure/app, and self-scan/app. The
summary keeps score, risk, severity counts, confidence, context, and a small
representative finding set visible while omitting long evidence and fix
blocks. The detailed reporter and `explain <rule-id>` command remain available
outside the compact recording.

The GIF is a deterministic documentation asset, not an accuracy claim. It
must not contain the local checkout path, raw secret evidence, or a credential
token. The regenerated asset was visually sampled at the intro and each final
scan state and measured at `1280x640`, `461` frames, `18.44` seconds, and
approximately `776 KB`.

## Post-release follow-up

The v0.5.0 release is complete and can be installed from npm or consumed
through the reusable `@v1` Action. The remaining follow-up is to record
real-user feedback as small, reproducible issues before expanding the rule
surface. The optional demo/video work remains tracked in #12.

The next planned release line is v0.6. Its scope and implementation order are
tracked in `ROADMAP.md` and the linked GitHub issues.

## Boundaries

This release does not add a full taint engine, cross-file or cross-function
flow, call graph, heap aliasing, dynamic resolution, TypeChecker-backed default
analysis, unrestricted plugins, hosted-service operations, or external
accuracy claims. Findings remain explainable review signals, not proof of
exploitation.
