# Real-user feedback and pilot measurement template

**Status:** Reusable plan only. No participants have been contacted, and no
interviews or pilots have been run.

## Purpose and scope

Use this worksheet to test whether SecureCheck's existing Next.js CLI and
GitHub Action give small teams useful, understandable review signals. The
initial sample is **five short interviews** and **three opt-in project
pilots**. An interview participant may also join a pilot, but count the two
activities separately.

Use the published v0.6.0 CLI/Action line and `--preset app`; write down only
the exact product version and whether the CLI or Action was used. Run scans in
the participant's own environment. This is a feedback exercise, not a security
audit, release, or claim about general scanner accuracy.

## Privacy boundary

- Get explicit opt-in before a pilot. Do not begin a scan for someone who has
  not opted in. This template does not authorize or initiate outreach.
- Do not collect, copy, upload, or retain source code, repository names or
  URLs, raw reports, JSON/SARIF, logs, screenshots, recordings, file paths,
  code snippets, secrets, tokens, or customer data.
- Ask participants to inspect findings locally and provide only aggregate
  counts and coarse review-time measurements below. Optional notes may use a
  public rule ID or broad category only when it reveals no project detail.
- Do not record interview audio/video. Keep participant contact details, if
  needed for scheduling, outside this worksheet and delete them when no longer
  needed. Use only the pseudonymous codes below here.
- If private material is shared accidentally, do not copy it into notes or
  issue trackers; remove the accidental copy and continue only with aggregate
  measurements.
- Do not publish quotes, participant-level results, or marketing claims from
  this small sample. Obtain separate permission before any future external use.

## Interview plan

Target five 20–30 minute conversations with people who work on Next.js apps.
Ask about their current CI/security review workflow before showing SecureCheck
to avoid leading the answers. Do not ask them to send a repository or scan
report.

Suggested prompts:

1. What security checks do you run before merging Next.js changes, and where
   do they slow you down?
2. When a static check reports a possible issue, what makes the result clear
   and actionable for your team?
3. Which findings or review steps most often create noise? Ask for a general
   example without collecting code, paths, or report output.
4. Would a local/CI Next.js-specific check fit your workflow? What would have
   to be true for your team to use it repeatedly?
5. What would make you trust or reject a finding, and how much review time is
   acceptable?

| Code | Opt-in confirmed | Broad role/team size | Current workflow pain | Repeated-use signal | Sanitized note |
| --- | --- | --- | --- | --- | --- |
| I01 |  |  |  |  |  |
| I02 |  |  |  |  |  |
| I03 |  |  |  |  |  |
| I04 |  |  |  |  |  |
| I05 |  |  |  |  |  |

Keep notes short and paraphrased. Do not enter employer, project, customer, or
personal identifiers.

## Pilot procedure and measures

For each of the three separately opted-in projects, let the participant run
the existing CLI or Action in their own environment. They review findings
locally and report only the counts and time below. If they cannot review all
findings, record unreviewed items separately; do not classify them as correct
or false positives.

Use these definitions consistently:

- **Confirmed actionable:** a reviewed finding that the participant or an
  independent reviewer confirms is a relevant risk signal within the stated
  rule scope. This does not prove exploitability.
- **Confirmed false positive:** a reviewed finding shown to be safe or outside
  the rule's stated scope. “Not fixed” or “not prioritized” alone is not a
  false-positive confirmation.
- **Uncertain/unreviewed:** no reliable classification yet. Keep this count
  separate from both actionable and false-positive counts.
- **Confirmed false negative:** a relevant issue in the scanned scope that was
  independently identified and verified, but not reported by SecureCheck.
  Do not infer a miss from an empty report; unverified candidate misses remain
  unknown. Record only a count and, if safe, a broad category.
- **Review time:** active minutes spent triaging findings, rounded to the
  nearest five minutes. Exclude setup, unrelated work, and time spent fixing
  issues. Record total time, not a per-finding timeline.
- **Action taken:** the participant says they changed code, added a guard, or
  created a tracked follow-up because of a confirmed actionable finding.

| Pilot | Opt-in | Version + CLI/Action | Findings reviewed | Actionable | Confirmed FP | Uncertain/unreviewed | Confirmed FN count | Action taken | Review minutes (nearest 5) | Optional broad category only |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| P01 |  |  |  |  |  |  |  |  |  |  |
| P02 |  |  |  |  |  |  |  |  |  |  |
| P03 |  |  |  |  |  |  |  |  |  |  |

### Calculations

- **Classified findings** = confirmed actionable + confirmed false positive.
- **Observed FP rate** = confirmed false positives ÷ classified findings.
  Exclude uncertain/unreviewed findings; show the denominator. If it is zero,
  report “not measurable.”
- **Action rate** = actionable findings with an action taken ÷ confirmed
  actionable findings. If the denominator is zero, report “not measurable.”
- **Review time** = report the median total active review minutes per pilot;
  show the number of pilots included.
- **FN measure** = report only the count of independently confirmed misses.
  This small, non-exhaustive sample cannot establish recall or an accuracy
  percentage.

Before applying quality thresholds, require at least 20 classified findings
across at least two pilots. If the sample is smaller, report descriptive
observations only and keep the result inconclusive.

## Decision thresholds

At the 30/60/90-day review, record evidence and choose one next step:

- If the observed FP rate is **over 30%** after meeting the minimum sample,
  pause new rules and tune the noisy signals first.
- If **under 20%** of confirmed actionable findings lead to an action, revisit
  the problem framing and finding presentation before building more features.
- At day 90, continue productization only if there are **at least two paying
  teams**, or strong written purchase intent together with repeat use. Treat
  interview interest alone as insufficient.
- Otherwise, keep the project in maintenance/feedback mode and do not start a
  larger hosted-service or analysis-engine investment based on this sample.
- A low sample, conflicting results, or unresolved classifications means
  “inconclusive”; do not round it into a pass.

| Review date | Interviews completed / 5 | Pilots completed / 3 | Classified findings / 20 | FP rate | Action rate | Median review minutes | Confirmed FN count | Repeat use / paid intent (aggregate only) | Decision + evidence |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 30-day |  |  |  |  |  |  |  |  |  |
| 60-day |  |  |  |  |  |  |  |  |  |
| 90-day |  |  |  |  |  |  |  |  |  |

## Retention and closeout

- Delete paraphrased interview notes within **30 days** of each interview.
- Delete pseudonymous pilot-level rows and consent yes/no records within
  **90 days after the final 90-day decision**. Do not keep a code-to-identity
  key in this worksheet.
- Keep only non-identifying aggregate totals for up to **12 months** after the
  final decision, then delete them or document a fresh review. With a sample
  this small, suppress combinations that could identify a participant or
  project.
- Before closeout, confirm that no source, raw report, identifier, or accidental
  private material remains in notes, issue trackers, or exports.

| Data category | Collection allowed | Delete by | Deletion verified |
| --- | --- | --- | --- |
| Contact/scheduling details (kept separately) | Only if needed | When scheduling/follow-up ends |  |
| Paraphrased interview notes | Minimal, pseudonymous | 30 days after interview |  |
| Pseudonymous pilot counts and consent status | Aggregate fields above only | 90 days after 90-day decision |  |
| Non-identifying aggregate summary | Counts/medians only | 12 months after final decision |  |
| Source, raw scan output, logs, paths, snippets, secrets | Never | Not applicable |  |

## Current record

This file is an empty template. No interview, pilot, participant contact, or
measurement has been recorded here.
