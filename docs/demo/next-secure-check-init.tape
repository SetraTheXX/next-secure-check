# Reproducible `init` demo for the published v0.6.0 line (issue #12).
# Runs on Windows `cmd` (Set Shell cmd; uses cls, type, mkdir, set, if, &&, rmdir /s /q).
# Run from the repository root after `pnpm build`.
# `init` writes into the current directory, so the recording runs in a freshly
# created, uniquely named scratch directory under the git-ignored `.local/` path.
# The inherited flags are cleared before setup. CREATED follows successful mkdir;
# ENTERED follows cd; READY follows the ownership marker.
# Failed setup cleans up only a directory this run created, then exits before
# any init or file-display command can read from the checkout or a collision.
Require node
Require ffmpeg
Require ttyd

Output docs/assets/next-secure-check-init-demo.gif

Set Shell cmd
Set FontFamily "Consolas"
Set FontSize 18
Set Width 1280
Set Height 720
Set Padding 30
Set Theme "Catppuccin Mocha"
Set CursorBlink false
Set TypingSpeed 16ms

# Keep the public recording free of the local checkout path and leave no files behind.
Hide
Type "prompt next-secure-check$G"
Enter
Type "set DEMO_SCRATCH_READY=&&set DEMO_SCRATCH_CREATED=&&set DEMO_SCRATCH_ENTERED="
Enter
Type "set DEMO_SCRATCH=.local\demo-init-%RANDOM%-%RANDOM%"
Enter
Type "if not exist %DEMO_SCRATCH% (mkdir %DEMO_SCRATCH% 2>nul && set DEMO_SCRATCH_CREATED=1 && cd /d %DEMO_SCRATCH% && set DEMO_SCRATCH_ENTERED=1 && type nul > .demo-scratch-owner && set DEMO_SCRATCH_READY=1)"
Enter
Type "if not defined DEMO_SCRATCH_READY if defined DEMO_SCRATCH_ENTERED cd ..\.."
Enter
Type "if not defined DEMO_SCRATCH_READY if defined DEMO_SCRATCH_CREATED rmdir /s /q %DEMO_SCRATCH%"
Enter
Type "if not defined DEMO_SCRATCH_READY exit"
Enter
Type "cls"
Enter
Show

Type "echo === init: generate a starter config and CI workflow ==="
Enter
Type "node ..\..\packages\cli\dist\index.js init"
Enter
Sleep 2s

Type "echo --- .next-secure-check.json ---"
Enter
Type "type .next-secure-check.json"
Enter
Sleep 2.5s

Type "echo --- .github\workflows\next-secure-check.yml ---"
Enter
Type "type .github\workflows\next-secure-check.yml"
Enter
Sleep 3.5s

# Remove only the scratch directory this recording created.
Hide
Type "if defined DEMO_SCRATCH_ENTERED cd ..\.."
Enter
Type "if defined DEMO_SCRATCH_CREATED if exist %DEMO_SCRATCH%\.demo-scratch-owner rmdir /s /q %DEMO_SCRATCH%"
Enter
Show
