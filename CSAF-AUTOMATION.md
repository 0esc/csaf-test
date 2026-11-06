# CSAF publishing automation

## Files
- `.github/workflows/csaf-ingest.yml`: replaces the SSH box. It takes the coordinator JSON, validates it, signs it, places it in `csaf_files/`, and opens a PR to `develop`.
- `scripts/publish_csaf.py`: does the signing, hashing and placement, and updates `index.txt`, `changes.csv` and the ROLIE feed in the repo's existing formats.
- `scripts/validate_csaf.mjs`: validates against the CSAF 2.0 schema and every mandatory test (§6.1). It runs in-process using `@secvisogram/csaf-validator-lib`, pinned in `package-lock.json` (the same engine as the Secvisogram validator service), so it needs no service, port or download.
- `scripts/test_publish.py`: end-to-end tests covering IT/VA/OT placement, signatures, hashes, index, changes, ROLIE, revision bumps, and refusal of bad IDs, non-WHITE TLP and drafts. It uses a throwaway GPG key and a temp copy of the repo.
- `.github/workflows/test.yml`: checks the Python scripts compile, runs the tests and validation of anything in `incoming/` on pull requests. It uses no secrets.

## Setup
1. **Environment:** under Settings → Environments, create `csaf-publishing` with these secrets:
   - `CSAF_GPG_PRIVATE_KEY`: the armored private key that signs advisories today. Sampled signatures in the repo all use key ID `CAC5AC4F74164B17`.
   - `CSAF_GPG_PASSPHRASE`
   - If you want a person to approve each run before anything is signed, add required reviewers.
2. **Repository variables:**
   - `COORDINATOR_HOST`: the hostname the advisory URLs come from.
   - `CSAF_PUBLISH_MODE`: `pr` (the default) or `push`.
3. **Optional secret:** `COORDINATOR_TOKEN`, if the coordinator needs a login to download the file.
4. **PR permission:** under Settings → Actions → General, turn on "Allow GitHub Actions to create and approve pull requests". This is needed for `pr` mode.
5. **Webhook from the coordination platform:** use a fine-grained token with Contents read/write on this repo.
   ```
   curl -X POST -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
     https://api.github.com/repos/0esc/csaf-test/dispatches \
     -d '{"event_type":"csaf-advisory","client_payload":{"url":"https://<coordinator>/.../icsa-26-307-01.json","feed":"OT"}}'
   ```
   For `feed`, ICSA- and ICSMA- IDs are detected automatically as OT. VA- IDs need `IT` or `VA` given explicitly.
6. **First test:** run `npm ci && npm test` locally. Then, in a fork, submit one known-good advisory and one broken one. The broken one must fail at the Validate step.

## Known issues
- `csaf_files/OT/white/2026/icsa-26-302-03.json` fails mandatory test 6.1.11. Its CWE-78 name, "...OS Command ('OS Command Injection')", is the older CWE name. The validator checks names against the current CWE catalogue, which drops the parenthetical. Advisories copied with older CWE names will be stopped at Validate until the name is updated.

## Hosting
Published advisories, signatures, hashes, `index.txt`, `changes.csv` and the ROLIE feeds all live in `csaf_files/` on `develop`, and are served from `raw.githubusercontent.com`. GitHub Pages (`gh-pages` and `csaf-tools/csaf-action`) is no longer used.

To serve the files from a different host, set the repository variable `CSAF_PUBLIC_BASE_URL` to the public URL of `csaf_files/` (no trailing slash). New ROLIE feed entries will use that base URL. Entries already in the feeds keep their old links until they are rewritten.

<!-- >>> CHANGELOG-MD FEATURE (added 2026-11-04) >>> -->
## Feed changelogs (CHANGELOG.md)
Every publish adds a row to `csaf_files/<FEED>/white/CHANGELOG.md` (newest first): the advisory's `current_release_date`, a link to the file, title, version, and the summary from the matching `revision_history` entry. Re-publishing the same ID and version replaces its row instead of adding a duplicate. Unlike `changes.csv`, which keeps only the latest date per advisory, this keeps one row per version.

- **Turn off:** set the repository variable `CSAF_WRITE_CHANGELOG=false`.
- **Remove completely:** delete every block between the `CHANGELOG-MD FEATURE` markers (`grep -rn "CHANGELOG-MD FEATURE" .`) in `scripts/publish_csaf.py`, `.github/workflows/csaf-ingest.yml` and this file, then delete `csaf_files/*/*/CHANGELOG.md`.
<!-- <<< CHANGELOG-MD FEATURE <<< -->
