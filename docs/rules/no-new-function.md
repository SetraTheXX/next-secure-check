# Dynamic Function constructor usage detected

**ID:** injection/no-new-function  
**Severity:** HIGH  
**Category:** injection  
**Confidence:** HIGH

## Description
Calls to the global `Function` constructor—including `Function(...)`, `new Function(...)`, and access through `window`, `globalThis`, `global`, or `self` using dot or static bracket notation—create functions from strings and may cause code injection when arguments contain untrusted input. Optional-call and optional-property forms still invoke the constructor whenever the recognized global resolves to it. Declarations, method definitions, shadowed bindings, and non-global methods such as `obj?.Function()` are not reported.

## Why is this a risk?
If an attacker can control any part of the source passed to the global `Function` constructor, the generated function can execute arbitrary JavaScript code on the server or in the user's browser, leading to data theft or system compromise.

## Recommendation
Avoid dynamic `Function` construction through direct calls, `new` calls, or global-object access, including optional-chain forms. Replace it with explicit logic, a safe parser (like `JSON.parse()`), or a well-vetted library for the specific task.

## Examples

### Insecure
```javascript
const formula = searchParams.get("formula");
const result = new Function(`return ${formula}`)();
const sameRisk = globalThis["Function"](`return ${formula}`)();
const optionalCall = Function?.(`return ${formula}`)();
const optionalGlobal = globalThis.Function?.(`return ${formula}`)();
const optionalReceiver = window?.Function(`return ${formula}`)();
```

### Secure
```javascript
// Use a safe math parser library or explicit logic
if (formula === "1+1") return 2;