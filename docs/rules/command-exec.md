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