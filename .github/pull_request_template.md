## Summary

Describe the user-facing problem and the smallest change that solves it.

## Related issue

Link the issue or explain why this is a small documentation, maintenance, or release-hygiene change.

## Scope

- [ ] Runtime or rule behavior
- [ ] Tests or fixtures
- [ ] Documentation or release hygiene
- [ ] No unrelated refactor included

## Validation

- [ ] `pnpm build`
- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] Relevant smoke test or documentation check

## Rule and finding impact

For scanner changes, describe expected finding-count, severity, confidence, context, exit-code, and report-format impact. Include safe and unsafe examples when applicable.

## Checklist

- [ ] No secrets, private repository contents, generated artifacts, or local planning notes are included.
- [ ] False-positive and false-negative tradeoffs are documented.
- [ ] User-facing docs and rule docs are updated when needed.
- [ ] Security-sensitive changes follow `SECURITY.md`.
- [ ] I checked the roadmap and kept the change within the stated v0.4 scope.

Do not include private plans, raw benchmark reports, terminal recordings, credentials, generated build output, or private repository contents.
