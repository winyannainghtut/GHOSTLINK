---
name: release
description: Release a new Ghostlink version from a branch, from the version bump through the draft release, verified file by file. Publishes only when the maintainer asks.
disable-model-invocation: true
argument-hint: "X.Y.Z"
---

# Release Ghostlink $ARGUMENTS

Follow agent.md, *Rules for contributors and AI agents* and *Version bump*. On Windows, `gh` is `"/c/Program Files/GitHub CLI/gh.exe"`.

## 1. On the release branch

1. **Bump the version everywhere at once:**
   - `Cargo.toml` and `apps/desktop/src-tauri/Cargo.toml`;
   - `apps/desktop/src-tauri/tauri.conf.json`;
   - `core/outline-worker/internal/version/version.go`;
   - `core/vpn-engine/src/worker_session.rs` (`WORKER_VERSION`);
   - `ui/desktop/src/version.ts`;
   - the CLI version assertion in `tests/integration/control-plane.test.mjs`;
   - the worker identity line in agent.md §5.
2. **Update both lockfiles:** `scripts/cargo.ps1 update --workspace --offline`, then the same with `--manifest-path apps/desktop/src-tauri/Cargo.toml`.
3. **Check the version:** `node scripts/release-version.mjs --tag v$ARGUMENTS` must print the version.
4. **Write the notes:** add `## [$ARGUMENTS] - YYYY-MM-DD` to the CHANGELOG, in the style of the earlier sections: plain words, what changes for users, verified claims only. Check the extract with `node scripts/changelog-section.mjs $ARGUMENTS`.
5. **Rebuild and commit the UI build output:** `cd ui && npm run build && npm test`.
6. **Run every suite:**
   - Go, with `-tags with_gvisor,with_utls,with_wireguard`;
   - Rust: fmt, `clippy -D warnings` and the tests, in both workspaces;
   - the UI tests;
   - the process suite, against fresh debug builds and `GHOSTLINK_TEST_SERVER`.
7. **Record the checks** in the ledger, `docs/development/verification.md`: what was actually observed, and what was not verified.

## 2. Pull request and CI

1. **Commit and push.** The pre-commit hook scans for secrets. Open the PR.
2. **Run the dry run:** `gh workflow run release.yml --ref <branch>`.
3. **Wait for every run on the head commit**, the PR's checks and the dry run, and read the log of any failure. Flaky jobs are listed in agent.md.

## 3. Merge and tag

1. **Squash-merge, pinned to the tested commit:** `gh pr merge N --squash --match-head-commit <sha>`.
2. **Tag the merge commit on `main`:** `git tag -a v$ARGUMENTS -m "Ghostlink $ARGUMENTS" <merge sha>`, then `git push origin v$ARGUMENTS`.
3. **Wait for the tag's Release run.** It builds a draft pre-release.

## 4. Verify the draft before anyone publishes it

1. **Files:** `gh release view v$ARGUMENTS --json isDraft,assets`. Expect 20 files, the arm64 ones included. Never publish before the arm64 files are attached.
2. **Checksums:** download into a new empty directory, then `sha256sum -c SHA256SUMS.txt`. Every line must say OK.
3. **Notes:** the body is the template from `.github/release-notes.md` around exactly the output of `node scripts/changelog-section.mjs $ARGUMENTS`.
4. **Versions:** the portable zip's `ghostlink.exe --version` and `ghostlink-tunnel.exe version` report $ARGUMENTS.

## 5. Publish only when the maintainer asks

1. **Publish:** `gh release edit v$ARGUMENTS --draft=false --prerelease`.
2. **Check what installers see:** the anonymous `https://api.github.com/repos/winyannainghtut/GHOSTLINK/releases` must list v$ARGUMENTS first.
3. **Tell the maintainer** what was verified, and what to do on their servers.
