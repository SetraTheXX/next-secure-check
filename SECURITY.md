# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.6.x | Yes |
| 0.5.x | Maintenance only |
| 0.4.x | Maintenance only |
| 0.3.x | No |
| 0.2.x | No |
| 0.1.x | No |

## Reporting a Security Issue

Please do not post real secrets, tokens, private repository contents, exploit payloads, or sensitive infrastructure details in public issues.

If GitHub security advisories are available for this repository, open a private security advisory. If that is not available, contact the maintainer through the repository owner's public GitHub profile and keep details minimal until a private channel is agreed.

Helpful reports include:

- A short description of the issue.
- A minimal reproduction.
- Affected package or area.
- Expected impact.
- Whether the issue affects the CLI, packages, reporter output, or web demo.

## Scanner Findings

`next-secure-check` findings are review signals, not proof of exploitation. The scanner uses deterministic static analysis and lightweight context, so findings can be false positives or false negatives.

Do not paste live secrets into issues to prove a finding. Use redacted samples instead.

## Web Demo Security Model

The web demo is designed for public repository scans only.

- It does not access private repositories.
- It does not execute scanned repository code.
- It does not run dependency installation, builds, tests, or package scripts from scanned repositories.
- Secret-related evidence is redacted server-side before web responses.

Public hosted deployments should use distributed abuse protection, such as the optional Upstash Redis REST guard or equivalent platform controls. The in-memory guard is only a local/single-instance fallback.

## Responsible Disclosure

Please give the maintainer reasonable time to investigate and fix security issues before public disclosure. Reports that avoid sensitive data and include clear reproduction steps are much easier to handle safely.
