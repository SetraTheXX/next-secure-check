# Reproducible README demo for the published v0.5.0 release.
# Run from the repository root after `pnpm build`.
Require node
Require ffmpeg
Require ttyd

Output docs/assets/readme-security-demo.gif

Set Shell cmd
Set FontFamily "Consolas"
Set FontSize 18
Set Width 1280
Set Height 640
Set Padding 30
Set Theme "Catppuccin Mocha"
Set CursorBlink false
Set TypingSpeed 16ms

# Keep the public recording free of the local checkout path.
Hide
Type "prompt next-secure-check$G"
Enter
Type "cls"
Enter
Show

Type "echo next-secure-check v0.5.0 / deterministic review signal"
Enter
Type "echo mode: --summary keeps the demo compact and readable"
Enter
Type "node packages/cli/dist/index.js --version"
Enter
Sleep 1s
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
