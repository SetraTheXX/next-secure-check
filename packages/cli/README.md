# next-secure-check

Deterministic security checks for Next.js projects. No AI required.

## Usage

```bash
npx next-secure-check scan .
npx next-secure-check scan . --format json
npx next-secure-check scan . --format sarif --output report.sarif
npx next-secure-check scan . --fail-on high
npx next-secure-check scan . --fail-on critical
npx next-secure-check scan . --exclude "**/*.test.ts,examples/**"
```

`--fail-on critical` is a scan risk-level gate. It exits with code `1` only when the scan summary risk level is `critical`. Other values, such as `high`, `medium`, `low`, and `info`, work as severity thresholds.

See the main repository for rule documentation, web demo notes, and validation details:

https://github.com/SetraTheXX/next-secure-check
