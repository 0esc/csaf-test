# CSAF publishing automation

## How it works
```
coordinator / Actions tab / push to incoming/
        │
        ▼
csaf-ingest.yml ─ prepare (no secrets) ─ fetch → collect → validate
        │           publish (signing key) ─ sign → hash → place → one PR per advisory
        ▼
csaf/<advisory> branch ── PR to develop ── check-pr (required check) ── review ── merge
        │
        ▼
csaf-feeds.yml ─ rebuild index.txt, changes.csv, ROLIE feed, CHANGELOG.md from develop → push
```

## Files
- `.github/workflows/csaf-ingest.yml`: replaces the SSH box. It has two jobs:
  - `prepare` fetches and validates with no signing key loaded. It hands exactly the validated files to the next job.
  - `publish` runs in the `csaf-publishing` environment. It signs, hashes and places each advisory, then opens a PR for it. It only runs when there is something to publish, so environment reviewers are never asked to approve a run that does nothing.
- `.github/workflows/csaf-feeds.yml`: the only writer of the shared feed files. It runs after every merge that adds or changes an advisory, rebuilds the files from `develop` and pushes them.
- `.github/workflows/test.yml`: runs the test suite. On every PR that touches `incoming/` or `csaf_files/`, it also runs `check-pr`. That job validates the advisories the PR adds or changes, checks every advisory's placement and `.sha512`, and fails if the PR edits a generated feed file.
- `scripts/ingest.py`: the workflow steps as subcommands (`fetch`, `collect`, `validate`, `publish`, `commit`, `feeds`, `check-pr`). `fetch` only accepts https URLs (redirects included) on `COORDINATOR_HOST`, caps downloads at 50 MiB, and drops the coordinator token if a redirect leaves that host.
- `scripts/publish_csaf.py`: signs, hashes and places advisories. It never touches the shared feed files.
- `scripts/build_feeds.py`: regenerates `index.txt`, `changes.csv`, `cisa-csaf-<feed>-feed-tlp-white.json` and `CHANGELOG.md` for each feed from the advisories in `csaf_files/`. Before writing anything, it checks every advisory's file name, year folder, TLP folder, `.sha512` and `.asc`.
- `scripts/validate_csaf.mjs`: validates against the CSAF 2.0 schema and every mandatory test (§6.1). It runs in-process using `@secvisogram/csaf-validator-lib`, pinned in `package-lock.json`, so it needs no service, port or download.
- `scripts/test_publish.py`: end-to-end tests using synthetic advisories, a throwaway GPG key, a local bare git repo standing in for GitHub and a stub `gh`. They cover concurrent PRs, re-runs, revisions, merge order, feed-rebuild races and push mode.

## Concurrent submissions (several people and organisations)
- **One PR per advisory.** Each PR is on branch `csaf/<file name>` (e.g. `csaf/icsa-26-307-01`) and holds only that advisory's `.json`, `.asc` and `.sha512`, plus the removal of its `incoming/` file if that was committed. Two PRs for different advisories never touch the same file, so they can be reviewed, approved and merged in any order.
- **Shared files are generated, never edited in PRs.** `index.txt`, `changes.csv`, the ROLIE feed and `CHANGELOG.md` are rebuilt from scratch from `develop` after each merge. The output depends only on which advisories are on `develop`, not on merge order. Re-running the rebuild with nothing new commits nothing. `check-pr` rejects PRs that edit these files.
- **Updates to shared files are atomic.** The rebuild commits all of a feed's files together in one commit. Only one rebuild runs at a time (`concurrency: csaf-feeds`). If `develop` moves before the push, it resets to the new `develop`, rebuilds and retries. If several merges land together, GitHub may cancel a waiting rebuild in favour of a newer one. That's safe, because each rebuild covers everything on `develop` at the time it runs.
- **New revision while the PR is still open:** the same branch is updated and the existing PR picks it up, so there's no second PR.
- **Same advisory submitted again while its PR is open:** it's left alone (no re-signing, no new PR). This also covers a file committed to `incoming/`, which stays on `develop` until its PR is merged.
- **The ingest workflow has no global concurrency group.** GitHub keeps only one *pending* run per group and cancels the others, which would silently drop advisories that arrive together. Ingest runs don't share files any more, so they run in parallel.
- **Two people's revisions of the *same* advisory at the same moment:** the later run's force-push wins the branch, and the PR shows the final content for review. A revision that isn't newer than what's on `develop` is refused.

## Setup
1. **Environment:** under Settings → Environments, create `csaf-publishing` with these secrets:
   - `CSAF_GPG_PRIVATE_KEY`: the armored private signing key. Publish its public key wherever consumers fetch it (e.g. `provider-metadata.json`), so they can verify the `.asc` files.
   - `CSAF_GPG_PASSPHRASE`
   - If you want a person to approve each run before anything is signed, add required reviewers.
2. **Repository variables:**
   - `COORDINATOR_HOST`: the hostname the advisory URLs come from.
   - `CSAF_PUBLISH_MODE`: `pr` (the default) or `push`. Push mode commits straight to `develop`, rebasing and retrying if needed, then triggers the feed rebuild.
   - `CSAF_PUBLIC_BASE_URL` (optional): see Hosting.
3. **Optional repository secret:** `COORDINATOR_TOKEN`, if the coordinator needs a login to download the file. It must be a repository secret, not an environment secret, because the download runs in the `prepare` job.
4. **Branch protection on `develop`:** require PR review, and make the `check-pr` status check required. The feed rebuild pushes straight to `develop`, so it must be allowed to bypass the PR rule (see step 5).
5. **GitHub App (recommended when several organisations use this):** create a GitHub App with Contents, Pull requests and Actions read/write on this repo, and install it. Set the repository variable `CSAF_APP_ID` and the repository secret `CSAF_APP_PRIVATE_KEY`, then add the App as a bypass actor on `develop`'s branch protection or ruleset. The workflows use its token automatically when `CSAF_APP_ID` is set. Without it:
   - PRs opened by the default `GITHUB_TOKEN` **do not trigger other workflows**, so `check-pr` won't run on bot PRs until someone closes and reopens them.
   - The feed rebuild (and push mode) can't push to a protected `develop`.
6. **PR permission:** under Settings → Actions → General, turn on "Allow GitHub Actions to create and approve pull requests". This is needed for `pr` mode without an App.
7. **Webhook from the coordination platform:** use a fine-grained token with Contents read/write on this repo.
   ```
   curl -X POST -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
     https://api.github.com/repos/0esc/csaf-test/dispatches \
     -d '{"event_type":"csaf-advisory","client_payload":{"url":"https://<coordinator>/.../icsa-26-307-01.json","feed":"OT"}}'
   ```
   For `feed`, ICSA- and ICSMA- IDs are detected automatically as OT. VA- IDs need `IT` or `VA` given explicitly.
8. **First test:** run `npm ci && npm test` locally. Then, in a fork, submit one known-good advisory and one broken one. The broken one must fail at the Validate step.

## Notes
- Validation uses the current CWE catalogue, so advisories copied with old CWE names (e.g. CWE-78's former "...('OS Command Injection')" name) fail mandatory test 6.1.11 until the name is updated.
- Only files directly in `incoming/` or in `incoming/IT|OT|VA/` are processed, and only processed files are removed. Anything else in `incoming/` is left alone.

## Hosting
Published advisories, signatures, hashes, `index.txt`, `changes.csv` and the ROLIE feeds all live in `csaf_files/` on `develop`, and are served from `raw.githubusercontent.com`.

To serve the files from a different host, set the repository variable `CSAF_PUBLIC_BASE_URL` to the public URL of `csaf_files/` (no trailing slash). The ROLIE feeds are regenerated on the next rebuild, so every entry switches to the new URL at once. To rebuild immediately, run "Rebuild CSAF feeds" from the Actions tab.

## Feed changelogs (CHANGELOG.md)
`csaf_files/<FEED>/white/CHANGELOG.md` is generated from each advisory's `revision_history`. It has one row per revision, newest first, giving the revision date, a link to the file, the title, the version and the revision summary. Unlike `changes.csv`, which keeps only the latest date per advisory, it keeps one row per version.

- **Turn off:** set the repository variable `CSAF_WRITE_CHANGELOG=false`. The next rebuild removes the files.
- **Remove completely:** also delete `render_changelog` and its call in `scripts/build_feeds.py`, and the `WRITE_CHANGELOG` line in `.github/workflows/csaf-feeds.yml`.
