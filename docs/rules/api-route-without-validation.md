# validation/api-route-without-validation

## Severity: MEDIUM

## Confidence: MEDIUM

## Category: validation

## Description

API routes that consume user input should validate the input before using it.

## Why This Matters

Without input validation, malicious or malformed data can reach your business logic, database queries, or downstream services. This can lead to injection attacks, crashes, data corruption, or unexpected behavior.

## Detection Logic

The rule looks for API routes (files in `app/api` or `pages/api`) that contain evidence of reading user input (`req.body`, `searchParams`, etc.) but do not contain any schema validation library or custom validation patterns.

## Common False Positives

- Routes that only perform authentication checks without needing body/query validation
- Routes that use framework-level validation (e.g., Next.js built-in validation or middleware)
- Internal APIs with trusted consumers and documented contracts

## Recommendation

Add input validation with a schema library such as Zod, Yup, Joi, or a clear custom validation layer.

## References

- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Zod](https://zod.dev)