# CSAF publishing automation

## Files
- `.github/workflows/csaf-ingest.yml`: replaces the SSH box. It takes the coordinator JSON, validates it, signs it, places it in `csaf_files/`, and opens a PR to `develop`.
- `scripts/publish_csaf.sh`: does the signing, hashing and placement, and updates `index.txt`, `changes.csv` and the ROLIE feed in the repo's existing formats.
- `.github/workflows/csaf-pages.yml`: phase 2 (issue #457). It serves the provider from GitHub Pages using `csaf-tools/csaf-action`. It only runs when started by hand until cutover.

## Phase 1 setup (replace the black box)
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
6. **First test:** in a fork, submit one known-good advisory and one broken one. The broken one must fail at the Validate step.

## Phase 2 cutover (GitHub Pages, issue #457)
1. **Turn on Pages:** under Settings → Pages, choose "Deploy from a branch" and select `gh-pages`.
2. **Repository variables:**
   - `CSAF_OPENPGP_PUBLIC_KEY`: the armored public key.
   - `CSAF_PUBLISHER_ISSUING_AUTHORITY`
   - Optional publisher overrides: `CSAF_PUBLISHER_CATEGORY`, `CSAF_PUBLISHER_NAME`, `CSAF_PUBLISHER_NAMESPACE` and `CSAF_PUBLISHER_CONTACT_DETAILS`. The defaults match the publisher block in current advisories.
3. **Move the ROLIE feeds:** move `csaf_files/*/white/cisa-csaf-*-feed-tlp-white.json` out of `csaf_files/`. The action uploads every `.json` under that folder, and a feed file would fail as an advisory.
4. **Dry run in a fork:** run `csaf-pages.yml` there first. Each run re-uploads and re-validates about 4,100 advisories, so measure how long it takes. Any historical advisory that fails the mandatory tests stops the run.
5. **Update provider-metadata:** point `https://www.cisa.gov/.../provider-metadata.json` (its `distributions`) at the Pages URLs. Keep the raw files in place until consumers have moved.
6. **Switch over:**
   - Uncomment the `push` trigger in `csaf-pages.yml`.
   - Set the variable `CSAF_WRITE_FEEDS=false`, because the action now generates the indexes and feeds.
   - Set `CSAF_PAGES_ENABLED=true`. This is only needed in `push` mode.

## Open questions for csaf-action (@bernhardreiter, per issue #457)
- The action builds a single TLP:WHITE feed. Today there are three: IT, OT and VA. Can ROLIE `categories` be passed through the action to keep that split?
- Every run is a full rebuild. Is incremental publishing planned?
