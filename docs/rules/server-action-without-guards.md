# auth/server-action-without-guards

## Severity: MEDIUM

## Confidence: MEDIUM

## Category: auth

## Description

Flags a recognized Next.js Server Action or Server Function that accepts action
or request input without visible authentication or input-validation intent in
the same function. If exactly one control is visible, the finding is lowered to
LOW and names the missing control.

This is a deterministic review signal, not proof that the function is
reachable or exploitable.

## Why This Matters

Next.js Server Actions use server-side functions as request boundaries. Client
input can be modified before invocation, so sensitive mutations should
re-authorize the caller and validate the received values inside the action.

## Detection Logic

The rule recognizes:

- top-level `use server` files with directly exported function declarations or
  exported function variables;
- inline `use server` directives at the beginning of exported or nested
  function bodies;
- direct action parameters and visible request-like values such as
  `request.json()`, `formData.get()`, `params.id`, `searchParams.get()`,
  `headers()`, and `cookies()`;
- the existing v0.5 auth and validation intent vocabulary, plus short local
  input aliases, static allowlists, equality checks, and direct normalizer
  guards.

Reassigned aliases stop contributing to a guard relationship. Unknown local
wrappers do not count as proof of authentication or validation. The analyzer
does not resolve re-exports, dynamic imports, runtime reachability, or
cross-file/cross-function control flow.

## Example

```ts
'use server'

export async function updateProfile(formData: FormData) {
  const name = formData.get('name')
  return saveProfile(name)
}
```

The action is reported because it accepts form input without a recognized auth
or validation signal.

```ts
'use server'

import { auth } from 'next-auth'

export async function updateProfile(formData: FormData) {
  const session = await auth()
  const parsed = profileSchema.safeParse(formData.get('name'))
  if (!parsed.success || !session) throw new Error('Unauthorized')
  return saveProfile(parsed.data)
}
```

The action is not reported because both controls are visible in the same
function.

## Common False Positives

- Authorization or validation implemented only in a shared helper or data
  access layer
- Actions intentionally callable without authentication
- Framework or deployment controls that are not visible in source
- Functions whose public reachability depends on dynamic exports

## Recommendation

Re-authorize the caller inside the action and validate client-controlled input
with a schema or another explicit, visible validation guard before performing a
sensitive operation.

## References

- [Next.js `use server` directive](https://nextjs.org/docs/app/api-reference/directives/use-server)
- [Next.js data security guidance](https://nextjs.org/docs/app/guides/data-security)
- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
