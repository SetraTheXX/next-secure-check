# Phase 16: Evidence and Reporter Explanations

Date: 2026-08-29

Issue: [#18](https://github.com/SetraTheXX/next-secure-check/issues/18)

Status: Implemented on the v0.5 development line; the published npm line
remains v0.4.1 until issue #20 is completed.

## Purpose

Make a finding easier to review without presenting bounded syntax evidence as
proof of exploitability. The reporter keeps the existing rule IDs, CLI flags,
output formats, SARIF locations, and deterministic fingerprint inputs.

## Reporter contract

- Detailed terminal and Markdown reports show `Why`, `Context reason`, and an
  optional `Evidence path` when the analyzer proves a bounded source-to-sink
  path.
- The concise terminal `--summary` view remains intentionally short. It keeps
  score, risk, counts, severity, confidence, context, and location, while
  omitting evidence, explanation, and fix blocks.
- JSON preserves `description`, context metadata, and optional `evidencePath`;
  secret evidence remains `[REDACTED]`.
- GitHub keeps the findings table compact and places explanation metadata in
  the existing recommendations details. It does not add raw evidence to the
  Step Summary; only a proven bounded path may be shown.
- SARIF keeps `2.1.0`, existing locations, and deterministic fingerprints. Its
  result message contains the title, description, and recommendation, while
  result properties expose context, context reason, `whyReported`, redaction
  state, and optional `evidencePath`.
- The web JSON/Markdown export DTO and Markdown output carry the same context,
  explanation, and bounded-path fields.

## Explain guidance

`next-secure-check explain <rule-id>` now includes both the existing false
positive note and a false-negative boundary. Common guidance calls out:

- same-function and short-alias limits for command and raw SQL flow;
- cross-file, cross-function, dynamic-resolution, and custom-wrapper limits;
- external middleware, WAF, hosting, and infrastructure controls that may not
  be visible to a source scan; and
- pattern-based secret detection that is not a complete credential inventory.

## Privacy and determinism

Raw secret evidence is redacted in JSON, terminal, Markdown, and web exports;
SARIF does not embed raw evidence, and GitHub does not emit raw evidence. New
explanation fields normalize line breaks for readable single-line metadata.
`evidencePath` is emitted only from the existing bounded syntax facts and does
not change finding IDs or SARIF fingerprint inputs.

## Verification

Focused reporter, CLI-helper, and web-export tests pass. The current full
workspace test snapshot is:

```text
packages: 366 tests
apps/web: 147 tests
total: 513 tests
```

The established fixture expectations remain unchanged:

| Scan | Expected result |
| --- | --- |
| `examples/vulnerable-next-app` with `--preset strict` | `0/100`, `critical`, 26 findings |
| `examples/secure-next-app` with `--preset app` | `99/100`, `excellent`, 1 LOW finding |
| repository self-scan with `--preset app` | `100/100`, `excellent`, 0 findings |

The local v0.5 release gate passed after the reporter changes. Its repeatable
benchmark snapshot was:

```text
100 files: cold scanner 117.6/119.8 ms median/p95; cold process 513.7/584.3 ms; warm 78/111.1 ms; overhead 1.12x
1,000 files: cold scanner 832/843.7 ms median/p95; cold process 1221.5/1260.7 ms; warm 741.4/802.7 ms; overhead 1.09x
warm scaling ratio: 9.50x
```

The release gate also passed fixture inventories, public-output privacy, SARIF
determinism, CLI packaging dry-run, and concise-summary checks. Release
publication/tagging and final GitHub CI validation remain part of issue #20.
The README demo GIF remains the v0.5 development baseline and will be
re-recorded after the final release feature set is frozen.

## Intentional boundaries

An evidence path describes recognized syntax, not runtime reachability or
exploitability. Cross-file/interprocedural flow, full call graphs, dynamic
resolution, heap aliasing, TypeChecker-backed analysis, and external controls
remain outside this phase. A finding without `evidencePath` is still a review
signal when a recognized sink or pattern was found; its absence is not a claim
that the code is safe.
