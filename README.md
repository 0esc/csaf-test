# How to use this repo

This repo publishes CSAF 2.0 advisories through GitHub Actions: an advisory is validated, signed with your PGP key, hashed, and placed in `csaf_files/<IT|OT|VA>/white/<year>/` via one PR per advisory. Merging rebuilds the feed files (`index.txt`, `changes.csv`, the ROLIE feed, `CHANGELOG.md`) automatically.

This guide covers:

1. [One-time setup checklist](#1-one-time-setup-checklist)
2. [PGP signing key](#2-pgp-signing-key)
3. [The GitHub App (the bot)](#3-the-github-app-the-bot)
4. [Secrets and variables](#4-secrets-and-variables)
5. [Branch protection on `develop`](#5-branch-protection-on-develop)
6. [Actions settings](#6-actions-settings)
7. [Webhook from the coordination platform](#7-webhook-from-the-coordination-platform)
8. [Publishing an advisory: what changes each time](#8-publishing-an-advisory-what-changes-each-time)
9. [Values to change when you copy this repo](#9-values-to-change-when-you-copy-this-repo)
10. [Testing and troubleshooting](#10-testing-and-troubleshooting)
11. [How it works](#11-how-it-works)

---

## 1. One-time setup checklist

Do these in order. Each one has its own section below.

- [ ] Generate a PGP signing key and publish the public key (Section 2)
- [ ] Create and install the GitHub App (Section 3)
- [ ] Create the `csaf-publishing` environment and add its secrets (Section 4)
- [ ] Add the repository secrets and variables (Section 4)
- [ ] Protect `develop`, make `check-pr` required, and let the App bypass it (Section 5)
- [ ] Set Actions permissions (Section 6)
- [ ] Create the token the coordination platform will use (Section 7)
- [ ] Run one good advisory and one broken advisory through (Section 10)

---

## 2. PGP signing key

Every advisory gets a detached, ASCII-armored signature (`<id>.json.asc`). The `publish` job imports your private key via `crazy-max/ghaction-import-gpg`, signs, and verifies before continuing.

### 2.1 Generate the key

Use a trusted machine, not a shared server.

```bash
gpg --full-generate-key
```

When prompted, choose:

| Prompt | Recommended answer |
|---|---|
| Kind of key | `(1) RSA and RSA` (works with the most CSAF tools), or `ECC (sign only)` / ed25519 if all your consumers support it |
| Key size | `4096` |
| Expiry | `2y` (set a reminder to extend it; see Section 2.5) |
| Real name | Your organisation, e.g. `Example Org CSAF Signing` |
| Email | A role address, e.g. `csaf@example.org` |
| Passphrase | A long random passphrase. **Keep it**: it goes into `CSAF_GPG_PASSPHRASE`. |

Non-interactive version (same result):

```bash
gpg --batch --quick-generate-key "Example Org CSAF Signing <csaf@example.org>" rsa4096 sign 2y
```

### 2.2 Find the fingerprint

```bash
gpg --list-secret-keys --keyid-format=long --with-fingerprint
```

The 40-character fingerprint is what you give consumers. The workflow reads it automatically from the import step, so you don't set it anywhere.

### 2.3 Export the private key (for the GitHub secret)

```bash
gpg --armor --export-secret-keys <FINGERPRINT> > csaf-signing-private.asc
```

Paste the **whole file, BEGIN/END lines included**, into the `CSAF_GPG_PRIVATE_KEY` secret (Section 4), then delete it:

```bash
shred -u csaf-signing-private.asc   # or rm -P on macOS
```

### 2.4 Export and publish the public key

```bash
gpg --armor --export <FINGERPRINT> > csaf-signing-public.asc
```

Publish it where consumers will look for it:

- In your `provider-metadata.json`, under `public_openpgp_keys`, with its URL and fingerprint.
- Optionally on `keys.openpgp.org` and on your website.

Consumers check the `.asc` files with:

```bash
gpg --import csaf-signing-public.asc
gpg --verify va-26-314-90.json.asc va-26-314-90.json
```

### 2.5 Back up, extend, revoke

- **Back up** the private key and a revocation certificate offline (password manager or offline media):
  ```bash
  gpg --output csaf-revoke.asc --gen-revoke <FINGERPRINT>
  ```
- **Before it expires**, extend and re-export the public key (re-exporting both is safest):
  ```bash
  gpg --quick-set-expire <FINGERPRINT> 2y
  ```
- **If it leaks**: publish the revocation certificate, generate a new key, replace both secrets, publish the new public key. Already-signed advisories keep the old signature; bump the revision to re-sign them.

---

## 3. The GitHub App (the bot)

The App opens PRs and pushes rebuilt feed files. Without it:

- PRs opened by the default `GITHUB_TOKEN` **don't trigger other workflows**, so `check-pr` never runs on them until someone closes and reopens the PR.
- The feed rebuild (and push mode) **can't push to a protected `develop`**.

With branch protection on, use the App.

### 3.1 Create it

**Settings → Developer settings → GitHub Apps → New GitHub App** (user account, or **Org settings → Developer settings → GitHub Apps** if the org owns the repo).

| Field | Value |
|---|---|
| GitHub App name | Anything unique, e.g. `csaf-publisher-<org>` |
| Homepage URL | The repo URL is fine |
| Webhook → Active | **Uncheck** (the App doesn't need to receive events) |
| Repository permissions → **Contents** | Read and write |
| Repository permissions → **Pull requests** | Read and write |
| Repository permissions → **Actions** | Read and write (push mode dispatches the feed rebuild) |
| Repository permissions → Metadata | Read-only (set automatically) |
| Where can this App be installed? | Only on this account |

Click **Create GitHub App**.

### 3.2 Get the App ID and private key

On the App's settings page:

1. Copy the **App ID** (a number, near the top). This goes into the variable `CSAF_APP_ID`.
2. Scroll to **Private keys → Generate a private key**. A `.pem` file downloads. Its whole contents (including `-----BEGIN RSA PRIVATE KEY-----` and the END line) go into the secret `CSAF_APP_PRIVATE_KEY`. Delete the file afterwards.

> Different key from section 2's PGP key: the `.pem` authenticates the bot to GitHub, the PGP key signs advisories.

### 3.3 Install it

On the App page, **Install App → your account/org → Only select repositories → `<repo>` → Install**.

### 3.4 How the workflows use it

Both `csaf-ingest.yml` and `csaf-feeds.yml` have a step that runs only when `vars.CSAF_APP_ID` is set:

```yaml
- uses: actions/create-github-app-token@v2
  with:
    app-id: ${{ vars.CSAF_APP_ID }}
    private-key: ${{ secrets.CSAF_APP_PRIVATE_KEY }}
```

Everything after it uses that token instead of `GITHUB_TOKEN`. Setting the variable is the on-switch; deleting it falls back to `GITHUB_TOKEN`.

> Commits are still authored as `github-actions[bot]` (hard-coded as `BOT_NAME`/`BOT_EMAIL` in `scripts/ingest.py`). The PRs themselves show the App as the author. Change those two constants if you want the App's name on commits too (`<app-slug>[bot]` and `<user-id>+<app-slug>[bot]@users.noreply.github.com`).

---

## 4. Secrets and variables

### 4.1 Environment: `csaf-publishing`

**Settings → Environments → New environment → `csaf-publishing`**

Only the `publish` job runs in this environment, so the signing key never reaches the job that downloads untrusted files.

| Environment secret | What goes in it |
|---|---|
| `CSAF_GPG_PRIVATE_KEY` | Full armored private key from section 2.3 |
| `CSAF_GPG_PASSPHRASE` | Its passphrase |

Optional on the same page:

- **Required reviewers**: must approve before signing; only triggered when there's something to publish.
- **Deployment branches**: restrict to `develop`.

### 4.2 Repository secrets

**Settings → Secrets and variables → Actions → Secrets → New repository secret**

| Secret | Required? | What goes in it |
|---|---|---|
| `CSAF_APP_PRIVATE_KEY` | If using the App | Full `.pem` from section 3.2 |
| `COORDINATOR_TOKEN` | Only if the coordinator needs a login to download | Bearer token for the coordinator. **Must be a repository secret, not an environment secret**, because the download happens in the `prepare` job. It's dropped automatically if a redirect leaves `COORDINATOR_HOST`. |

### 4.3 Repository variables

**Settings → Secrets and variables → Actions → Variables → New repository variable**

| Variable | Required? | Default | What it does |
|---|---|---|---|
| `COORDINATOR_HOST` | Yes, for URL imports | none | Hostname advisory URLs must come from, e.g. `coordinator.example.org`. Host only: no `https://`, no path. Any other host is refused. |
| `CSAF_APP_ID` | If using the App | none | The App ID from section 3.2. Turns the App token on. |
| `CSAF_PUBLISH_MODE` | No | `pr` | `pr` = one PR per advisory. `push` = commit straight to `develop` (needs the App if `develop` is protected). |
| `CSAF_PUBLIC_BASE_URL` | No | `https://raw.githubusercontent.com/<owner>/<repo>/develop/csaf_files` | Public URL of `csaf_files/`, **no trailing slash**. Used for links in the ROLIE feeds. Set it if you serve the files from your own host. |
| `CSAF_WRITE_CHANGELOG` | No | `true` | `false` stops generating `CHANGELOG.md` (the next rebuild deletes them). |

After changing `CSAF_PUBLIC_BASE_URL`, run **Actions → Rebuild CSAF feeds → Run workflow** to apply it immediately.

---

## 5. Branch protection on `develop`

**Settings → Rules → Rulesets → New ruleset → New branch ruleset** (or classic **Settings → Branches → Add rule**):

- Target: `develop`
- **Require a pull request before merging**, with at least 1 approval.
- **Require status checks to pass**: add `check-pr`.
  - The check only shows up in the picker after it has run once. Open any test PR touching `incoming/` or `csaf_files/` first.
- **Bypass list**: add your GitHub App (Section 3). The feed rebuild pushes directly to `develop` and needs this.
- Block force pushes and deletions.

`check-pr` validates the advisories a PR adds or changes, checks every advisory's location and `.sha512`, and fails if the PR edits a generated feed file.

> `check-pr` only runs on PRs that touch `scripts/`, `incoming/`, `csaf_files/`, `package*.json` or `.github/workflows/`. If you make it a required check, PRs touching only other files (e.g. a README) will sit at "Expected — waiting". Either merge those as an admin, or use a ruleset that limits the required check to those paths.

---

## 6. Actions settings

**Settings → Actions → General**:

- **Workflow permissions**: "Read and write permissions".
- **Allow GitHub Actions to create and approve pull requests**: on. Needed for `pr` mode when you're not using the App; harmless with it.

---

## 7. Webhook from the coordination platform

The coordination platform triggers an import by calling `repository_dispatch`.

### 7.1 Create its token

**Your profile → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**

- Resource owner: the owner of the repo
- Repository access: **Only select repositories → `<repo>`**
- Repository permissions: **Contents: Read and write** (that's what `repository_dispatch` needs; nothing else)
- Expiry: set one and diary the renewal

Give this token to whoever runs the coordinator. It's stored on **their** side, not in this repo.

### 7.2 The call

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/<OWNER>/<REPO>/dispatches \
  -d '{"event_type":"csaf-advisory","client_payload":{"url":"https://<COORDINATOR_HOST>/path/icsa-26-307-01.json","feed":"OT"}}'
```

A `204 No Content` reply means it was accepted. Watch the run under **Actions → Ingest CSAF advisory**.

---

## 8. Publishing an advisory: what changes each time

### 8.1 Three ways in

| Method | When to use | What you set |
|---|---|---|
| **Webhook** (Section 7) | Coordinator publishes automatically | `client_payload.url`, `client_payload.feed` |
| **Actions tab** → *Ingest CSAF advisory* → *Run workflow* | Manual import from a URL | `url` input, `feed` dropdown (`auto`/`OT`/`IT`/`VA`) |
| **Commit the JSON** to `incoming/` on `develop` | You have the file locally | Folder you put it in (see below) |

Committing the file:

```
incoming/advisory.json         feed auto-detected from the id
incoming/OT/advisory.json      forced to OT
incoming/IT/advisory.json      forced to IT
incoming/VA/advisory.json      forced to VA
```

Only files directly in those folders are processed. Leave the file name as you like; the published name comes from the id.

### 8.2 Per-advisory values

These are the things that change for every advisory. The pipeline reads them from the JSON and refuses to publish if they're wrong.

| Field / input | What to put | Why it matters |
|---|---|---|
| **URL** (`url`) | `https://` link on `COORDINATOR_HOST` | Anything else (http, other host, redirect elsewhere, >50 MiB, not JSON) is refused. |
| **Feed** (`feed`) | `auto`, `OT`, `IT` or `VA` | `auto`: `ICSA-` / `ICSMA-` → OT. Anything else with `auto` fails, so give the feed explicitly. **`VA-` ids always go to IT**, whatever you pick. |
| `document.tracking.id` | e.g. `ICSA-26-307-01`, `VA-26-302-01` | Becomes the file name (lower-cased, anything outside `a-z0-9+-` becomes `_`). VA ids must be `VA-` then numbers separated by `-`. |
| `document.tracking.initial_release_date` | ISO 8601 date-time | Its **year** picks the folder (`.../white/2026/`). Keep it the same across revisions. |
| `document.tracking.current_release_date` | ISO 8601 date-time | **Must be later than the published copy for a revision**, or it's refused. Goes into `changes.csv`. |
| `document.tracking.status` | `final` or `interim` | `draft` is refused. |
| `document.tracking.version` + `revision_history[]` | Bump the version and add an entry for every revision | Each `revision_history` entry becomes a `CHANGELOG.md` row. |
| `document.distribution.tlp.label` | `WHITE` | Anything else is refused (`ALLOWED_TLP` defaults to `WHITE`). |
| `document.title` | Advisory title | Shown in ROLIE feed and changelog. |
| CWE names in `vulnerabilities[].cwe.name` | The **current** CWE catalogue name | Old names (e.g. CWE-78's old "('OS Command Injection')" wording) fail mandatory test 6.1.11. |

### 8.3 What happens next

1. `prepare` downloads and validates (no secrets loaded). A broken advisory stops here.
2. `publish` (in `csaf-publishing`, after reviewer approval if you set one) signs, hashes, places it, and opens PR `csaf/<file name>`.
3. `check-pr` runs on the PR. Review and merge.
4. `Rebuild CSAF feeds` runs and pushes updated `index.txt`, `changes.csv`, ROLIE feed and `CHANGELOG.md`.

**Revisions:** send the updated JSON the same way with a later `current_release_date`. If the PR is still open, the same PR updates. Sending an identical file again is a no-op.

---

## 9. Values to change when you copy this repo

Hard-coded values to edit if you fork this or deploy it elsewhere:

| Where | Value | Change it if… |
|---|---|---|
| `.github/workflows/csaf-ingest.yml`, `csaf-feeds.yml` → `env.BASE_BRANCH` | `develop` | Your publishing branch has a different name. Also update the `branches: [develop]` triggers in all three workflows. |
| `scripts/publish_csaf.py` → `ALLOWED_TLP` | `WHITE` | You publish other TLPs. Add `ALLOWED_TLP: "WHITE"` (space-separated) to the publish step's `env:`. |
| `scripts/publish_csaf.py` → feed rules | `ICSA-`/`ICSMA-` → OT, `VA-` → IT | Your id prefixes differ. |
| `scripts/ingest.py` → `BOT_NAME`, `BOT_EMAIL` | `github-actions[bot]` | You want commits attributed to your App (Section 3.4). |
| `CSAF_ROOT` env | `csaf_files` | You want a different top folder. |
| Feed file name in `build_feeds.py` | `cisa-csaf-<feed>-feed-tlp-<tlp>.json` | You don't want "cisa" in the ROLIE file name. |
| Webhook URL (Section 7.2), `CSAF-AUTOMATION.md` | `<owner>/<repo>` | The repo owner/name changed. |
| Repository variables (Section 4.3) | `COORDINATOR_HOST`, `CSAF_PUBLIC_BASE_URL` | Always, per deployment. |

---

## 10. Testing and troubleshooting

### 10.1 Locally

Needs Python 3.11+, Node 20+, gpg, git (and openssl for the fetch tests).

```bash
npm ci                                                   # installs the pinned validator
node scripts/validate_csaf.mjs path/to/advisory.json     # schema + mandatory tests, offline
python3 scripts/test_publish.py                          # end-to-end tests with a throwaway key
RAW_BASE=https://example.invalid/csaf_files python3 scripts/build_feeds.py
```

### 10.2 First live run

1. Commit a known-good advisory to `incoming/`. Expect a PR, a green `check-pr`, and after merge a feed rebuild commit.
2. Commit a broken one (e.g. remove `document.title`). Expect the **Validate** step to fail and no PR.
3. Verify a published signature with your public key (Section 2.4).

### 10.3 Common errors

| Error | Cause / fix |
|---|---|
| `Host 'x' is not COORDINATOR_HOST` | Variable missing, has `https://` in it, or URL is on another host. |
| `download failed: HTTP 401/403` | `COORDINATOR_TOKEN` missing, expired, or saved as an environment secret instead of a repository secret. |
| `can't tell the feed from id` | Feed was `auto` and the id isn't `ICSA-`/`ICSMA-`/`VA-`. Pick the feed. |
| `Bump the revision before re-publishing` | Same advisory, different content, `current_release_date` not newer. |
| `TLP '...' is not in ALLOWED_TLP` / `status is 'draft'` | Fix the JSON (Section 8.2). |
| Mandatory test 6.1.11 fails | Outdated CWE name. |
| Import GPG step fails / `gpg could not sign` | Private key secret is truncated (missing BEGIN/END lines), passphrase wrong, or key expired. |
| `check-pr` never runs on bot PRs | No App configured (`CSAF_APP_ID` unset). Set it up, or close and reopen the PR. |
| Feed rebuild: push rejected / protected branch | App isn't on `develop`'s bypass list. |
| Publish job waits forever | Environment has required reviewers; someone needs to approve under the run. |
| `.sha512 does not match` in `check-pr` | Someone edited an advisory JSON by hand. Re-submit through the pipeline instead. |
| PR edits `index.txt` / `changes.csv` and fails | Those are generated. Drop them from the PR. |

See [CSAF-AUTOMATION.md](CSAF-AUTOMATION.md) for how concurrency, re-runs and hosting work under the hood.


---

## 11. How it works

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

### 11.1 Several submissions at once

- **One PR per advisory.** Each PR is on branch `csaf/<file name>` and holds only that advisory's `.json`, `.asc` and `.sha512` (plus removal of its `incoming/` file, if it was committed). Different advisories never touch the same file, so their PRs can be merged in any order.
- **Feed files are generated, never edited in PRs.** `index.txt`, `changes.csv`, the ROLIE feed and `CHANGELOG.md` are rebuilt from `develop` after each merge. The result depends only on what's on `develop`, not on merge order, and a rebuild with nothing new commits nothing.
- **One rebuild at a time** (`concurrency: csaf-feeds`). If `develop` moves before the push, it rebuilds and retries. GitHub may cancel a waiting rebuild in favour of a newer one; that's safe, because each rebuild covers everything on `develop`.
- **Ingest runs in parallel.** There's deliberately no concurrency group: GitHub keeps only one pending run per group and cancels the rest, which would silently drop advisories that arrive together.
- **Push mode** commits straight to `develop`, rebasing and retrying if it moved, then starts the feed rebuild.

### 11.2 Re-submissions and revisions

| Situation | What happens |
|---|---|
| New revision while its PR is open | The same branch and PR are updated. |
| Same advisory sent again while its PR is open | Left alone: no re-signing, no new PR. |
| Two revisions of the same advisory at the same moment | The later run's force-push wins; the PR shows the final content. |
| Revision not newer than the copy on `develop` | Refused (see Section 8.2). |

### 11.3 `incoming/`

Only files directly in `incoming/` or `incoming/IT|OT|VA/` are processed, and only processed files are removed. Anything else in `incoming/` is left alone.

### 11.4 Feed changelogs

`csaf_files/<FEED>/white/CHANGELOG.md` has one row per revision, newest first: date, link, title, version and revision summary. (`changes.csv` keeps only the latest date per advisory.)

- **Turn off:** set `CSAF_WRITE_CHANGELOG=false`. The next rebuild removes the files.
- **Remove completely:** also delete `render_changelog` and its call in `scripts/build_feeds.py`, and the `WRITE_CHANGELOG` line in `.github/workflows/csaf-feeds.yml`.