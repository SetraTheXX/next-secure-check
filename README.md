# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

`next-secure-check` helps developers find common security mistakes before they reach production: leaked secrets, unsafe API routes, missing rate limits, weak configuration, XSS risks, raw SQL patterns, and missing security headers.

> Current status: This project is still in early development. The CLI shape exists; real scanning rules are being implemented next.

Started on May 9, 2026.

## Why This Exists

AI-assisted development makes it easy to ship fast and miss security basics. This project focuses on checks that are evidence-based, understandable, and useful for junior developers, freelancers, small SaaS teams, and agencies.

## Learning Project and Development Philosophy

This is a student-built learning project. I am developing it to improve my skills in TypeScript, Next.js security, static analysis, open-source project structure, testing, and product thinking.

The project is built with an AI-assisted development workflow, but the scanner itself is deterministic and does not require AI to run. Every rule is intended to be documented, tested, and designed to produce evidence-based findings rather than vague guesses.

AI helps with speed, structure, and iteration. Technical ownership, product direction, review, testing, and release decisions remain my responsibility.

## Target CLI

```bash
npx next-secure-check scan .
npx next-secure-check scan . --format json
npx next-secure-check scan . --format markdown --output report.md
npx next-secure-check scan . --fail-on high
```

## Monorepo Layout

```txt
packages/
  core/       scanner orchestration, shared types, score engine
  cli/        command line entrypoint
  rules/      built-in rule modules
  reporter/   terminal, JSON, markdown, GitHub report output
examples/
  vulnerable-next-app/
  secure-next-app/
docs/
  rules/
```

## Local Development

```bash
pnpm install
pnpm build
pnpm test
```

After building, the current scaffold CLI can be run from the package:

```bash
node packages/cli/dist/index.js scan examples/vulnerable-next-app
node packages/cli/dist/index.js scan examples/vulnerable-next-app --format json
```

## Immediate Goal

```txt
Phase 1: make next-secure-check scan . produce real findings.
```

## Release Gates

```txt
CLI works before web.
Tests pass before NPM release.
GitHub Action works before SaaS.
Real user feedback comes before payments.
```

## License

License decision is pending before the first public release.
