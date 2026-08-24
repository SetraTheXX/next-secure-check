# Shell command execution detected

**ID:** injection/command-exec  
**Severity:** HIGH  
**Category:** injection  
**Confidence:** MEDIUM

## Description
Shell command execution can lead to command injection if user input reaches the command or arguments. Using functions like `exec`, `spawn`, or `execSync` from `child_process` to run system commands is risky.

## Why is this a risk?
If user-controlled input is concatenated into a shell command, an attacker can use shell metacharacters (like `;`, `&`, `|`) to execute arbitrary commands on the host system with the privileges of the application.

## Recommendation
Avoid shell execution for user-controlled input. If command execution is required:
1. Use safe APIs that don't invoke a shell (like `spawn` with an argument array).
2. Use strict allowlists for commands and arguments.
3. Sanitize all inputs.

## Context and False Positives

The rule uses import-aware AST matching plus lightweight path context. It can still flag intentional command execution in `.github/**`, release scripts, changeset/version scripts, and CLI tooling helpers.

These findings are not automatic proof of exploitation. Command execution in app runtime code, API routes, or user-input paths is much higher risk. Command execution in CI, release, or local tooling code should still be reviewed, but it may be expected behavior.

The current bounded analysis also records an optional source-to-sink evidence path when a request-derived value can be followed inside the same function. Supported source signals include `request.json()`, `request.formData()`, `req.body`, `req.query`, `searchParams.get(...)`, and route parameters. The path is exposed as `evidencePath` in JSON and SARIF properties.

Static `spawn(...)` and `spawnSync(...)` calls with a literal executable, a literal argument array, and no shell (or an explicit `shell: false`) are treated as non-shell process launches and are not reported by this rule. Dynamic executable or argument values and explicit `shell: true` remain review signals.

This is intentionally conservative: it supports direct expressions, direct assignments, and up to two short identifier aliases. Tracking stops at reassignment, mutation, callback/closure escape, and function boundaries. Cross-function, cross-file, type-aware, and full control-flow analysis are not part of this pilot. A command finding without a proven source still remains a valid review signal.

Compared with the earlier broad matcher, unrelated calls such as `regex.exec(input)` and static non-shell `spawn("ls", ["-l"])` are excluded. Imported `child_process` sinks, dynamic command arguments, and explicit `shell: true` remain findings for review.

## Examples

### Insecure
```javascript
import { exec } from "child_process";
const cmd = searchParams.get("cmd");
exec(cmd); // Extremely dangerous
```

When the bounded source-to-sink pilot can prove the path, JSON and SARIF include metadata similar to:

```json
{
  "evidencePath": "searchParams.get()"
}
```

### Secure
```javascript
import { spawn } from "child_process";
// Use argument arrays and avoid shell: true
spawn("ls", ["-l", "/tmp/uploads"]);
