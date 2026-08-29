# Reproducible README demo. Run from the repository root after `pnpm build`.
Require node
Require ffmpeg
Require ttyd

Output docs/assets/readme-security-demo.gif

Set Shell cmd
Set FontFamily "Consolas"
Set FontSize 17
Set Width 1280
Set Height 620
Set Padding 28
Set Theme "Catppuccin Mocha"
Set CursorBlink false
Set TypingSpeed 18ms

# Keep the public recording free of the local checkout path.
Hide
Type "prompt next-secure-check$G"
Enter
Type "cls"
Enter
Show

Type "echo === 1/3: VULNERABLE FIXTURE / STRICT ==="
Enter
Type "node packages/cli/dist/index.js scan examples/vulnerable-next-app --preset strict --summary"
Enter
Sleep 2.5s

Type "cls"
Enter
Type "echo === 2/3: SECURE FIXTURE / APP ==="
Enter
Type "node packages/cli/dist/index.js scan examples/secure-next-app --preset app --summary"
Enter
Sleep 2s

Type "cls"
Enter
Type "echo === 3/3: SELF-SCAN / APP / CLEAN ==="
Enter
Type "node packages/cli/dist/index.js scan . --preset app --summary"
Enter
Sleep 3s
