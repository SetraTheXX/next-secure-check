# Reproducible `init` demo for the published v0.6.0 line (issue #12).
# Runs on Windows `cmd` (Set Shell cmd; uses cls, type, mkdir, set, if, &&, rmdir /s /q).
# Run from the repository root after `pnpm build`.
# `init` writes into the current directory, so the recording runs in a freshly
# created, uniquely named scratch directory under the git-ignored `.local/` path.
# Entering that directory is bound to a successful `mkdir` (`&&`), a per-run
# ownership marker is written inside it, and cleanup only removes the directory
# when the readiness flag and the marker both confirm this recording created it.
# The readiness flag is cleared first, so an inherited `DEMO_SCRATCH_READY` from
# the parent environment cannot arm cleanup. A name collision or a failed
# `mkdir` therefore never enters, writes to, or deletes a pre-existing directory.
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
Type "set DEMO_SCRATCH_READY="
Enter
Type "set DEMO_SCRATCH=.local\demo-init-%RANDOM%-%RANDOM%"
Enter
Type "mkdir %DEMO_SCRATCH% 2>nul && cd %DEMO_SCRATCH% && type nul > .demo-scratch-owner && set DEMO_SCRATCH_READY=1"
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
Type "if defined DEMO_SCRATCH_READY cd ..\.."
Enter
Type "if defined DEMO_SCRATCH_READY if exist %DEMO_SCRATCH%\.demo-scratch-owner rmdir /s /q %DEMO_SCRATCH%"
Enter
Show
