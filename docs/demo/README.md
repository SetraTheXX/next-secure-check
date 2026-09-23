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

Requires Node.js 20.9 or newer, Git, and `vhs`, `ttyd`, and `ffmpeg` on `PATH`. The main CLI tape rejects ignored or untracked files in its secure fixture, so install the other workspaces without installing `secure-next-app` there:

```bash
pnpm install --frozen-lockfile --filter '!secure-next-app'
pnpm build
vhs docs/demo/next-secure-check-cli.tape
vhs docs/demo/next-secure-check.tape
vhs docs/demo/next-secure-check-init.tape
```

Each tape writes its GIF into `docs/assets/` and uses the local `packages/cli/dist/index.js` build, so the recording matches the checked-out source rather than the published npm package.

### Platform

All three tapes target **Windows `cmd`** (`Set Shell cmd`): they rely on `cls`, `type`, `mkdir`, `set`, `rmdir /s /q`, cmd's `$G` prompt escape, and cmd `&&` chaining with `if defined` / `if exist` (the init tape uses these for its scratch-directory guard). Recording on macOS or Linux requires adapting the shell commands (for example `clear`, `cat`, `rm -rf`, `mkdir -p`) and the prompt in a local copy of the tape; the checked-in tapes are not shell-portable by design.

## Privacy checklist

Before treating a linked demo as final or using it in a launch post, confirm:

- the shell prompt is replaced so the local checkout path is never shown;
- the main CLI tape runs `scripts/assert-public-demo-fixture.mjs` before scanning; it fails closed unless both Git and the recursive file inventory contain exactly `README.md`, `next.config.js`, and `package.json` under `examples/secure-next-app`;
- the main CLI scan is limited to that checked-in public fixture, explicitly excludes `.env*` paths, and never scans the developer checkout root;
- no tokens, `.env` files, credentials, or private repository content appear;
- the init demo clears inherited flags before setup; CREATED is set only after successful mkdir, ENTERED only after cd, and READY only after the ownership marker is written. If setup fails, it removes only a directory this run created and exits before any init or file display can touch the checkout or a collision directory. After successful setup, cleanup returns to the root only when ENTERED is set and removes the scratch path only when CREATED and the per-run marker confirm ownership;
- the generated config and workflow files shown are the public `init` templates only; and
- the fixture counts in the recording still match [`README.md`](../../README.md#reproducible-fixtures).

## Review status

The CLI and init visuals are linked from the README in PR #37. Final approval of these recordings and any launch-post use remain pending review.

- [x] Main CLI tape and GIF prepared.
- [x] Init tape and GIF prepared.
- [x] Fixture demo already exists and is linked from the README.
- [ ] QA review of the updated main CLI and init GIFs is pending; keep PR #37 unmerged until review is complete.
