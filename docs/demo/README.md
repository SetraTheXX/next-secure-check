# Terminal demos

Recording sources for the short terminal demos referenced by [issue #12](https://github.com/SetraTheXX/next-secure-check/issues/12). Each demo pairs a checked-in [VHS](https://github.com/charmbracelet/vhs) tape with the GIF it renders, so the visuals stay reproducible from the local CLI.

## Assets

| Demo | Recording source | Rendered asset | Shows |
| --- | --- | --- | --- |
| Main CLI | [`next-secure-check-cli.tape`](./next-secure-check-cli.tape) | [`docs/assets/next-secure-check-cli-demo.gif`](../assets/next-secure-check-cli-demo.gif) | `--version`, `rules`, `explain`, and a `scan --summary` |
| Fixtures | [`next-secure-check.tape`](./next-secure-check.tape) | [`docs/assets/readme-security-demo.gif`](../assets/readme-security-demo.gif) | vulnerable, secure, and self-scan summaries |
| Init | [`next-secure-check-init.tape`](./next-secure-check-init.tape) | [`docs/assets/next-secure-check-init-demo.gif`](../assets/next-secure-check-init-demo.gif) | generated config and GitHub Actions workflow |

The root README links all three demos: fixture comparisons, the main CLI walkthrough, and the init flow.

## Regenerating

Requires Node.js 20.9 or newer plus `vhs`, `ttyd`, and `ffmpeg` on `PATH`. Run from the repository root:

```bash
pnpm build
vhs docs/demo/next-secure-check-cli.tape
vhs docs/demo/next-secure-check.tape
vhs docs/demo/next-secure-check-init.tape
```

Each tape writes its GIF into `docs/assets/` and uses the local `packages/cli/dist/index.js` build, so the recording matches the checked-out source rather than the published npm package.

### Platform

All three tapes target **Windows `cmd`** (`Set Shell cmd`): they rely on `cls`, `type`, `mkdir`, `set`, `rmdir /s /q`, cmd's `$G` prompt escape, and cmd `&&` chaining with `if defined` / `if exist` (the init tape uses these for its scratch-directory guard). Recording on macOS or Linux requires adapting the shell commands (for example `clear`, `cat`, `rm -rf`, `mkdir -p`) and the prompt in a local copy of the tape; the checked-in tapes are not shell-portable by design.

## Privacy checklist

Before a demo is linked from the README or a launch post, confirm:

- the shell prompt is replaced so the local checkout path is never shown;
- no tokens, `.env` files, credentials, or private repository content appear;
- the `init` demo runs inside a freshly created, uniquely named scratch directory under the git-ignored `.local/` path: the readiness flag is cleared before the scratch block, entering the directory is bound to a successful `mkdir` (`&&`), a per-run `.demo-scratch-owner` marker is written inside it, and the recording removes the directory only when the readiness flag and that marker confirm this recording created it. Clearing the flag first means a `DEMO_SCRATCH_READY` inherited from the parent shell cannot arm cleanup, so a scratch name collision or any other `mkdir` failure leaves a pre-existing directory untouched — no write into it and no delete of it — and nothing is left behind;
- the generated config and workflow files shown are the public `init` templates only; and
- the fixture counts in the recording still match [`README.md`](../../README.md#reproducible-fixtures).

## Review status

Issue #12 requires the visuals to be reviewed before they are added to the README or social posts.

- [x] Main CLI tape and GIF prepared.
- [x] Init tape and GIF prepared.
- [x] Fixture demo already exists and is linked from the README.
- [x] QA reviewed the main CLI and init GIFs; both are linked from the root README.
