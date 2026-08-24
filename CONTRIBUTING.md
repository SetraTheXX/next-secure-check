# Contributing

Thanks for taking an interest in `next-secure-check`.

This project is a deterministic static security scanner for Next.js projects. It is also a student-built learning project, so thoughtful feedback, issue reports, and critical review are very welcome.

Contributions are most helpful when they keep the scanner understandable, testable, and honest about false positives and false negatives.

## Before Opening an Issue

Please include:

- What you expected to happen.
- What actually happened.
- The command or web demo flow you used.
- A small code sample or public repository link when possible.
- Whether the result is a false positive, false negative, crash, documentation issue, or feature request.

Do not include real secrets, tokens, private repository contents, or customer data in public issues.

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
pnpm test
```

The root test command runs both package tests and web demo tests.

## Adding or Changing Rules

When adding or changing a rule, please update:

- The rule implementation.
- Unit tests for vulnerable and safe examples.
- Documentation under `docs/rules`.
- Example or fixture behavior when the rule intentionally changes scanner output.

Think through false positives before raising severity. For the current v0.3 line and the planned v0.4 work, predictable and explainable behavior is more important than catching every possible edge case.

## Pull Requests

Please keep pull requests focused. A good PR usually changes one behavior, one rule, or one documentation area at a time.

Please include a short problem statement, the intended behavior, and any known false-positive or false-negative tradeoffs. For scanner changes, include vulnerable and safe examples whenever possible.

Before opening a PR, run:

```bash
pnpm build
pnpm typecheck
pnpm test
```

Before requesting review, check that:

- [ ] The change is covered by focused tests or documentation validation.
- [ ] Rule changes include safe and unsafe examples.
- [ ] User-facing behavior and report formats remain compatible unless the PR explains the change.
- [ ] No secrets, private repository contents, generated artifacts, or local planning notes are included.

## Security Issues

If you believe you found a security vulnerability in the scanner or web demo, please follow [SECURITY.md](./SECURITY.md) instead of opening a public issue with sensitive details.
