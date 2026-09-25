# Contributing

Thanks for taking an interest in SecureCheck, published as `next-secure-check`.

SecureCheck is a deterministic static checker for Next.js projects. It is also a student-built project, so thoughtful feedback, issue reports, and critical review are welcome.

Contributions are most helpful when they keep the scanner understandable, testable, and honest about false positives and false negatives.

## Start With the Roadmap and Issues

Before starting work, read [ROADMAP.md](./ROADMAP.md) and check the open GitHub issues. The published CLI line is `v0.6.0` with 25 built-in rules, and the reusable GitHub Action release is `v1.2.0` on `@v1`. CLI checks use bounded, syntax-first analysis. Prefer a focused issue or a short proposal before beginning a new rule, analyzer, or public API change. Full type-aware analysis, cross-file taint flow, and unrestricted plugin loading are outside the current default scope.

## Before Opening an Issue

Please include:

- What you expected to happen.
- What actually happened.
- The command or web demo flow you used.
- A small, redacted code sample or public repository link when possible.
- Whether the result is a false positive, false negative, crash, documentation issue, or feature request.
- For a false positive or false negative, choose the matching [false-positive](./.github/ISSUE_TEMPLATE/false_positive.md) or [false-negative](./.github/ISSUE_TEMPLATE/false_negative.md) issue template. Describe the rule behavior without attaching a private repository report.

Do not include real secrets, tokens, private repository contents, raw reports from private projects, or customer data in public issues.

## Rule Suggestions

For new rule ideas, please include:

- Rule name and category.
- The risky pattern it should detect.
- One vulnerable example.
- One safe example that should not be flagged.
- Expected severity and confidence.
- Known false positive risks.

Good rules should be deterministic, explainable, and covered by tests.

## Bug Reports

For bugs, please include:

- Package or area affected: CLI, core, rules, reporter, web demo, docs.
- OS and Node.js version.
- Command used.
- Minimal reproduction steps.
- Actual output and expected output.

## Development Setup

Use Node.js 20.9 or newer for the workspace.

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```

The root test command runs both package tests and web demo tests.

## Adding or Changing Rules

When adding or changing a rule, please update:

- The rule implementation.
- Unit tests for vulnerable and safe examples.
- Documentation under `docs/rules`.
- Example or fixture behavior when the rule intentionally changes scanner output.

Think through false positives before raising severity. Predictable and explainable behavior is more important than matching every possible edge case. Do not treat a pattern match as a confirmed vulnerability without checking its context and the rule's documented scope. False positives and false negatives are possible.

## Pull Requests

Please keep pull requests focused. A good PR usually changes one behavior, one rule, or one documentation area at a time.

Please include a short problem statement, the intended behavior, and any known false-positive or false-negative tradeoffs. For scanner changes, include vulnerable and safe examples whenever possible.

Link the related issue when one exists. Keep the pull request focused and do not mix a rule behavior change with an unrelated refactor, release, or generated artifact update.

Before opening a PR, run:

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```

Before requesting review, check that:

- [ ] The change is covered by focused tests or documentation validation.
- [ ] Rule changes include safe and unsafe examples.
- [ ] User-facing behavior and report formats remain compatible unless the PR explains the change.
- [ ] No secrets, private repository contents, generated artifacts, or local planning notes are included.

## Repository Hygiene

Do not commit private plans, raw benchmark reports, terminal recordings, credentials, generated build output, or repository contents from private projects. Keep local demo exports outside the repository unless they have been intentionally reviewed as public assets. Historical decisions belong in public validation notes or the changelog, not in private working files.

## Security Issues

If you believe you found a security vulnerability in the scanner or web demo, please follow [SECURITY.md](./SECURITY.md) instead of opening a public issue with sensitive details.
