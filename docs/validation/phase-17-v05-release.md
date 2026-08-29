# Phase 17: v0.5 Release-Candidate Audit and Feedback Handoff

Date: 2026-08-29

Issue: [#20](https://github.com/SetraTheXX/next-secure-check/issues/20)

Status: The `v0.5.0` GitHub release and tag are recorded on the validated
release commit. The package publication, coordinated Action update, and
post-release feedback remain manual follow-up steps.

## Scope

This phase turns the completed v0.5 implementation work into a reviewable
release. It covers version alignment, public documentation, the reproducible
terminal demo, packaging checks, and a final local audit. It does not publish
to npm or claim that the stable npm `latest` channel has moved.

The GitHub [`v0.5.0` release](https://github.com/SetraTheXX/next-secure-check/releases/tag/v0.5.0)
and tag target commit `051c3d8db65722b266ff864906a5e863fa4abe7c`, the commit
validated by the release gate and CI run `33258034052`.

The scanner continues to read repository files as input and never executes
code from the scanned repository.

## Release-candidate package matrix

| Package | Candidate version | Publication status |
| --- | ---: | --- |
| `next-secure-check` | `0.5.0` | Manual npm publication pending |
| `@next-secure-check/core` | `0.5.0` | Manual npm publication pending |
| `@next-secure-check/rules` | `0.5.0` | Manual npm publication pending |
| `@next-secure-check/reporter` | `0.5.0` | Manual npm publication pending |

The private workspace and local web application remain `0.0.0`; they are not
published npm packages. Internal package references remain `workspace:*` and
are resolved by the workspace publish flow.

The published `v1` GitHub Action remains pinned to the available npm
`next-secure-check@0.4.1` package. It is deliberately not changed to an
unpublished `0.5.0` version. A coordinated Action release can follow after
the manual npm publication.

## Feedback review

The open issue review found:

- #20, this release and feedback handoff;
- #12, the optional demo/video editing follow-up.

No repeated new user report was available to convert into a separate issue.
The post-release feedback loop remains open and should use reviewed real
repositories, not unverified benchmark or accuracy claims.

## Verification protocol

The release-candidate audit runs:

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

The final local candidate run passed:

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

The bug audit found and corrected three release-quality issues: a stale README
validation count (`362/146/508` instead of the current `366/147/513`), release
line package version drift (`0.4.1` CLI versus `0.4.0` internal packages), and
a Windows `shell: true` invocation in the release gate that emitted Node's
shell-spawn deprecation warning. The existing Action pin was intentionally
retained at published `0.4.1` and documented as a post-publication coordination
step.

## Demo contract

The checked-in [`next-secure-check.tape`](../demo/next-secure-check.tape)
records the prepared `v0.5.0` CLI version and three labeled concise
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

## Manual handoff after the GitHub release

The maintainer can now publish the aligned packages through the authenticated
workspace release process. Once npm availability is confirmed, the Action can
be updated and released separately. Finally, record real-user feedback as
small, reproducible issues before expanding the rule surface.

Until those steps are complete, documentation must continue to describe
`v0.4.1` as the stable npm line and `v0.5.0` as the GitHub release whose npm
publication is pending.

## Boundaries

This release does not add a full taint engine, cross-file or cross-function
flow, call graph, heap aliasing, dynamic resolution, TypeChecker-backed default
analysis, unrestricted plugins, hosted-service operations, or external
accuracy claims. Findings remain explainable review signals, not proof of
exploitation.
