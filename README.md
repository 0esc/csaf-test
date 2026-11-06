# csaf-test

GitHub Actions pipeline for publishing CISA CSAF 2.0 advisories, replacing the SSH "black box". It mirrors the `csaf_files/<IT|OT|VA>/white/` layout of [cisagov/CSAF](https://github.com/cisagov/CSAF).

The pipeline takes the advisory JSON, validates it (schema and mandatory tests), signs it, writes the `.sha512` hash and places it under `csaf_files/<FEED>/white/<year>/`. It then opens **one pull request per advisory** to `develop`. After each merge, a separate workflow rebuilds `index.txt`, `changes.csv`, the ROLIE feed and `CHANGELOG.md` from what is on `develop`. Many advisory PRs can therefore be open at once, from different people and organisations, and merged in any order without conflicts.

Setup, triggers, concurrency and hosting: [CSAF-AUTOMATION.md](CSAF-AUTOMATION.md).

## Run it locally (no external hosts)
```
npm ci                                                # once: installs the pinned validator
node scripts/validate_csaf.mjs path/to/advisory.json  # schema + mandatory tests, offline
RAW_BASE=https://example.invalid/csaf_files python3 scripts/build_feeds.py   # rebuild feed files
python3 scripts/test_publish.py                       # end-to-end tests (throwaway GPG key, temp repos)
```
Requires Python 3.11 or later, gpg, git and Node 20 or later (openssl too, for the fetch tests).

The workflows' steps live in `scripts/ingest.py`; each workflow step is a one-line call to it.
