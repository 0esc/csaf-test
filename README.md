# csaf-test

GitHub Actions pipeline for publishing CISA CSAF 2.0 advisories, replacing the SSH "black box". It mirrors the `csaf_files/<IT|OT|VA>/white/` layout of [cisagov/CSAF](https://github.com/cisagov/CSAF).

The pipeline takes the advisory JSON, validates it (schema and mandatory tests), signs it, writes the `.sha512` hash, places it under `csaf_files/<FEED>/white/<year>/`, updates `index.txt`, `changes.csv`, the ROLIE feed and `CHANGELOG.md`, then opens a pull request to `develop`.

Setup, triggers and hosting: [CSAF-AUTOMATION.md](CSAF-AUTOMATION.md).

## Run it locally (no external hosts)
```
npm ci                                              # once: installs the pinned validator
node scripts/validate_csaf.mjs path/to/advisory.json  # schema + mandatory tests, offline
python3 scripts/test_publish.py                     # end-to-end tests (throwaway GPG key, temp copy)
```
Requires Python 3.11 or later, gpg, git and Node 20 or later (openssl too, for the fetch tests).

The workflows' steps live in `scripts/ingest.py`; each step in `.github/workflows/csaf-ingest.yml` is a one-line call to it.
