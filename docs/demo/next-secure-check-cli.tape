# Reproducible main CLI demo for the published v0.6.0 line (issue #12).
# Runs on Windows `cmd` (Set Shell cmd; uses cls). See docs/demo/README.md.
# Run from the repository root after `pnpm build`.
Require node
Require git
Require ffmpeg
Require ttyd

Output docs/assets/next-secure-check-cli-demo.gif

Set Shell cmd
Set FontFamily "Consolas"
Set FontSize 16
Set Width 1680
Set Height 820
Set Padding 30
Set Theme "Catppuccin Mocha"
Set CursorBlink false
Set TypingSpeed 16ms

# Scan only the checked-in public secure fixture; never scan the developer checkout root.
# Exclude environment files explicitly so the command stays safe in any checkout.
# Fail closed unless the three tracked public files match HEAD and no others exist.
Hide
Type "prompt next-secure-check$G"
Enter
Type "cls"
Enter
Type "node scripts/assert-public-demo-fixture.mjs"
Enter
Type "if errorlevel 1 exit /b 1"
Enter
Type "cls"
Enter
Show

Type "echo fixture: three tracked public files only"
Enter
Sleep 1s
Type "echo next-secure-check v0.6.0 / 25 bounded review rules"
Enter
Type "echo mode: version, rules, explain, then a scan summary"
Enter
Type "node packages/cli/dist/index.js --version"
Enter
Sleep 1s

Type "cls"
Enter
Type "echo === rules: list the built-in checks ==="
Enter
Type "node packages/cli/dist/index.js rules"
Enter
Sleep 3s

Type "cls"
Enter
Type "echo === explain: why a rule fires and where it stops ==="
Enter
Type "node packages/cli/dist/index.js explain xss/dangerously-set-inner-html"
Enter
Sleep 3.5s

Type "cls"
Enter
Type "echo === scan: known-safe secure example ==="
Enter
Type "node packages/cli/dist/index.js scan examples/secure-next-app --preset app --exclude .env*,**/.env* --summary"
Enter
Sleep 3s
