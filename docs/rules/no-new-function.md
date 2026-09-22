# new Function() usage detected

**ID:** injection/no-new-function  
**Severity:** HIGH  
**Category:** injection  
**Confidence:** HIGH

## Description
`new Function()` can execute dynamically generated code and may lead to code injection if input is untrusted. Similar to `eval()`, it creates a new function object which can execute arbitrary code in the global scope. The same risk applies to bare `Function(...)` calls and to global access through `window`, `globalThis`, `global`, or `self` using either dot or bracket notation (for example `globalThis["Function"](...)`). Declaration and method forms such as `function Function() {}` or `obj.Function()` are not reported.

## Why is this a risk?
If an attacker can control any part of the string passed to `new Function()`, they can execute arbitrary JavaScript code on the server or in the user's browser, leading to full system compromise or data theft.

## Recommendation
Avoid dynamic code execution. Replace `new Function()` with explicit logic, a safe parser (like `JSON.parse()`), or a well-vetted library for the specific task.

## Examples

### Insecure
```javascript
const formula = searchParams.get("formula");
const result = new Function(`return ${formula}`)();
const sameRisk = globalThis["Function"](`return ${formula}`)();
```

### Secure
```javascript
// Use a safe math parser library or explicit logic
if (formula === "1+1") return 2;