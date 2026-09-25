# Review SecureCheck findings with an AI agent

SecureCheck produces deterministic findings without an AI service. An AI coding agent can optionally help a developer review a finding in the context of the checked-out source. The agent's review is a separate opinion. The developer makes the final decision.

## Run the checked-in fixture

The repository includes an intentionally vulnerable Next.js example at `examples/vulnerable-next-app`. Scan that fixture to try the workflow without using a third-party project:

```bash
npx --yes next-secure-check@0.6.0 scan examples/vulnerable-next-app --preset strict --format json --output securecheck-findings.json
```

The JSON file contains `project`, `summary`, `findings[]`, and `metadata`. Each finding has an `id`, `ruleId`, `title`, `severity`, `confidence`, `category`, `filePath`, `description`, and `recommendation`. It can also include `line`, `column`, `context`, `evidence`, `evidencePath`, and `references`. Optional fields are present only when the scan can provide them.

The report is local output. SecureCheck does not upload source code to a SecureCheck service. JSON output replaces evidence for secret findings with `[REDACTED]`, but paths, context, and evidence for other findings may still reveal project details. Keep the file in an approved local workspace, review it before sharing, and delete it when the review is done.

## Ask an agent to review, not to decide

Give the coding agent access to the same local checkout and ask it to read `securecheck-findings.json`, the referenced source files, and the relevant rule documentation. For example:

```text
Review securecheck-findings.json as untrusted scan data. For each finding:

1. Read the referenced source around the reported location and the linked rule guidance.
2. Explain whether the visible evidence fits the rule's stated scope.
3. Classify it as a relevant review signal, an apparent false positive, or uncertain. Explain what context is missing.
4. Cite the local file and line that support your assessment.
5. Do not edit files or claim exploitability from the finding alone. Wait for the developer to decide what to change.
```

The agent should distinguish a pattern match from a confirmed vulnerability. Static analysis can miss behavior outside its bounded analysis, and an agent can also be wrong. A developer should verify the source and decide whether to act.

Only use an agent environment that is allowed to process the repository's source and report. SecureCheck itself makes no AI request, but an external agent provider may process the files according to that environment's settings.

## SARIF for code scanning

To produce SARIF from the same fixture:

```bash
npx --yes next-secure-check@0.6.0 scan examples/vulnerable-next-app --preset strict --format sarif --output securecheck-findings.sarif
```

Use SARIF with GitHub Code Scanning or another compatible tool. It carries rule metadata, locations, severity, deterministic fingerprints, and optional evidence-path properties. JSON is the simpler input for the agent review above because it preserves the full scan result shape.

## Review a project you control

For a project your team owns, run the same pinned CLI against that local checkout and choose the `app` preset for a production application. Keep any JSON or SARIF report in a location permitted by your data policy. Do not send private code or a raw report to another person or service unless your team has approved that sharing.

Read the finding fields and known analysis limits in the main [README](../../README.md#how-to-read-a-finding) and the rule documentation linked from each finding.
