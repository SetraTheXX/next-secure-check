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

In v0.1, this rule uses lightweight static matching. It can flag intentional command execution in `.github/**`, release scripts, changeset/version scripts, and CLI tooling helpers.

These findings are not automatic proof of exploitation. Command execution in app runtime code, API routes, or user-input paths is much higher risk. Command execution in CI, release, or local tooling code should still be reviewed, but it may be expected behavior.

v0.2 is planned to add context-aware severity and confidence so tooling/release findings can be separated from application runtime findings.

## Examples

### Insecure
```javascript
import { exec } from "child_process";
const cmd = searchParams.get("cmd");
exec(cmd); // Extremely dangerous
```

### Secure
```javascript
import { spawn } from "child_process";
// Use argument arrays and avoid shell: true
spawn("ls", ["-l", "/tmp/uploads"]);
