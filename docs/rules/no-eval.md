# injection/no-eval

## Description
Detects the usage of the `eval()` function in JavaScript/TypeScript code.

## Why is this a problem?
The `eval()` function executes arbitrary JavaScript code represented as a string. If any part of that string comes from untrusted user input, it leads to a critical vulnerability known as Code Injection or Remote Code Execution (RCE). Attackers can run malicious scripts with the privileges of your application.

## How to fix
1. Never use `eval()`.
2. If you are parsing JSON, use `JSON.parse()`.
3. If you are evaluating mathematical expressions, use a safe math parser library.
4. If you need dynamic property access, use bracket notation (e.g., `obj[propName]`).