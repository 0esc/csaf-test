#!/usr/bin/env bash
# test_publish.sh: end-to-end tests for validate_csaf.mjs and publish_csaf.sh.
#
# Fully local: works on a throwaway copy of the repo with a throwaway GPG key
# in a temp GNUPGHOME. It never touches your real keyring, your csaf_files/,
# the network or any external host. Needs: bash, jq, gpg, python3, node,
# and `npm ci` run once in the repo.
#
# Usage:  bash scripts/test_publish.sh        (or: npm test)
# Exit:   0 if every check passes, 1 otherwise.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
expect_ok()   { local n="$1"; shift; if "$@" >"$WORK/out" 2>&1; then ok "$n"; else bad "$n"; sed 's/^/        /' "$WORK/out"; fi; }
expect_fail() { local n="$1"; shift; if "$@" >"$WORK/out" 2>&1; then bad "$n (should have failed)"; sed 's/^/        /' "$WORK/out"; else ok "$n"; fi; }

for t in jq gpg python3 node sha512sum; do command -v "$t" >/dev/null || { echo "missing: $t"; exit 1; }; done
[ -d "$REPO/node_modules/@secvisogram/csaf-validator-lib" ] || { echo "run 'npm ci' first"; exit 1; }

# ---- sandbox: copy of the repo + throwaway signing key ----------------------
mkdir -p "$WORK/repo"
cp -r "$REPO/scripts" "$REPO/csaf_files" "$WORK/repo/"
ln -s "$REPO/node_modules" "$WORK/repo/node_modules"
cp "$REPO/package.json" "$WORK/repo/"
export GNUPGHOME="$WORK/gnupg"; mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key "CSAF test <test@example.invalid>" rsa2048 sign never 2>/dev/null
export RAW_BASE="https://example.invalid/csaf_files"
cd "$WORK/repo"
VALIDATE=(node scripts/validate_csaf.mjs)
PUBLISH=(bash scripts/publish_csaf.sh)

# ---- fixtures: built from the published OT advisory -------------------------
# The CWE-78 name is set to the current catalogue name (see README "Known issues").
SAMPLE=csaf_files/OT/white/2026/icsa-26-302-03.json
F="$WORK/fx"; mkdir -p "$F"
base='(.vulnerabilities[]?.cwe | select(.id=="CWE-78") | .name) |= "Improper Neutralization of Special Elements used in an OS Command"'
mk() { jq "$base | $1" "$SAMPLE" > "$F/$2"; }
ts='"2026-11-05T12:00:00.000Z"'
mk ".document.tracking.id=\"VA-26-309-01\" | .document.title=\"Test VA advisory\" | .document.tracking.initial_release_date=$ts | .document.tracking.current_release_date=$ts | .document.tracking.revision_history[-1].date=$ts" va.json
jq '.document.tracking.current_release_date="2026-11-06T12:00:00.000Z" | .document.tracking.version="3"
    | .document.tracking.revision_history += [{"date":"2026-11-06T12:00:00.000Z","number":"3","summary":"Test update"}]' "$F/va.json" > "$F/va-v3.json"
mk '.document.tracking.id="ICSA-26-309-02" | .document.tracking.current_release_date="2026-11-07T00:00:00.000Z" | .document.tracking.version="3" | .document.tracking.revision_history += [{"date":"2026-11-07T00:00:00.000Z","number":"3","summary":"x"}]' icsa.json
mk 'del(.document.title)' no-title.json
mk '.vulnerabilities[0].product_status.known_affected += ["CSAFPID-NOPE"]' bad-pid.json
jq '.document.tracking.id="VA-ABC"'               "$F/va.json" > "$F/va-badid.json"
jq '.document.tracking.id="VA-26-309-09"'         "$F/va.json" > "$F/va-auto.json"
jq '.document.tracking.id="VA-26-309-03"'         "$F/va.json" > "$F/va-vafeed.json"
jq '.document.tracking.id="VA-26-309-05" | .document.distribution.tlp.label="AMBER"' "$F/va.json" > "$F/va-amber.json"
jq '.document.tracking.id="VA-26-309-06" | .document.tracking.status="draft"'        "$F/va.json" > "$F/va-draft.json"

echo "Validation (schema + mandatory tests, offline)"
expect_ok   "valid VA advisory passes"               "${VALIDATE[@]}" "$F/va.json"
expect_ok   "valid ICSA advisory passes"             "${VALIDATE[@]}" "$F/icsa.json"
expect_fail "missing /document/title is rejected"    "${VALIDATE[@]}" "$F/no-title.json"
expect_fail "undefined product id is rejected"       "${VALIDATE[@]}" "$F/bad-pid.json"
printf 'not json' > "$F/garbage.json"
expect_fail "non-JSON file is rejected"              "${VALIDATE[@]}" "$F/garbage.json"

echo "Publish: VA advisory into IT/white"
expect_ok   "VA-26-309-01 publishes to IT"           "${PUBLISH[@]}" IT "$F/va.json"
d=csaf_files/IT/white
for f in 2026/va-26-309-01.json 2026/va-26-309-01.json.asc 2026/va-26-309-01.json.sha512 index.txt changes.csv CHANGELOG.md cisa-csaf-it-feed-tlp-white.json; do
  [ -f "$d/$f" ] && ok "created IT/white/$f" || bad "missing IT/white/$f"
done
expect_ok   "signature verifies"                     gpg --batch --verify "$d/2026/va-26-309-01.json.asc" "$d/2026/va-26-309-01.json"
( cd "$d/2026" && [ "$(cut -d' ' -f1 va-26-309-01.json.sha512)" = "$(sha512sum va-26-309-01.json | cut -d' ' -f1)" ] ) \
  && ok ".sha512 matches file" || bad ".sha512 does not match"
grep -qxF '2026/va-26-309-01.json' "$d/index.txt" && ok "index.txt lists it" || bad "index.txt missing entry"
grep -qxF '2026/va-26-309-01.json,2026-11-05T12:00:00.000Z' "$d/changes.csv" \
  && ok "changes.csv row (IT style: unquoted)" || { bad "changes.csv row wrong"; cat "$d/changes.csv"; }
[ "$(jq -r '.feed.entry[0].id' "$d/cisa-csaf-it-feed-tlp-white.json")" = "VA-26-309-01" ] && ok "ROLIE entry added" || bad "ROLIE entry missing"
[ "$(jq -r '.feed.entry[0].content.src' "$d/cisa-csaf-it-feed-tlp-white.json")" = "$RAW_BASE/IT/white/2026/va-26-309-01.json" ] \
  && ok "ROLIE link uses RAW_BASE" || bad "ROLIE link wrong"
expect_ok   "published file still validates"         "${VALIDATE[@]}" "$d/2026/va-26-309-01.json"

echo "Publish: revisions and guards"
expect_fail "same revision is not overwritten"       "${PUBLISH[@]}" IT "$F/va.json"
expect_ok   "newer revision replaces it"             "${PUBLISH[@]}" IT "$F/va-v3.json"
[ "$(grep -c 'va-26-309-01' "$d/changes.csv")" = 1 ] && ok "changes.csv keeps one row per advisory" || bad "duplicate changes.csv rows"
[ "$(jq '[.feed.entry[]|select(.id=="VA-26-309-01")]|length' "$d/cisa-csaf-it-feed-tlp-white.json")" = 1 ] && ok "ROLIE keeps one entry" || bad "duplicate ROLIE entries"
[ "$(grep -c 'VA-26-309-01' "$d/CHANGELOG.md")" = 2 ] && ok "CHANGELOG.md has one row per version" || bad "CHANGELOG.md rows wrong"
expect_fail "malformed VA id is refused"             "${PUBLISH[@]}" IT "$F/va-badid.json"
expect_fail "VA id with feed=auto is refused"        "${PUBLISH[@]}" auto "$F/va-auto.json"
expect_fail "TLP:AMBER is refused"                   "${PUBLISH[@]}" IT "$F/va-amber.json"
expect_fail "draft status is refused"                "${PUBLISH[@]}" IT "$F/va-draft.json"
expect_ok   "VA advisory publishes to VA feed"       "${PUBLISH[@]}" VA "$F/va-vafeed.json"
[ -f csaf_files/VA/white/2026/va-26-309-03.json ] && ok "VA/white file placed" || bad "VA/white file missing"
grep -qxF '"2026/va-26-309-03.json","2026-11-05T12:00:00.000Z"' csaf_files/VA/white/changes.csv \
  && ok "VA changes.csv row (quoted)" || bad "VA changes.csv row wrong"

echo "Publish: OT feed auto-detection"
expect_ok   "ICSA id auto-routes to OT"              "${PUBLISH[@]}" auto "$F/icsa.json"
[ "$(head -1 csaf_files/OT/white/index.txt)" = "2026/icsa-26-309-02.json" ] && ok "OT index.txt updated" || bad "OT index.txt wrong"
head -1 csaf_files/OT/white/changes.csv | grep -q '^"2026/icsa-26-309-02.json",' && ok "OT changes.csv newest first, quoted" || bad "OT changes.csv wrong"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
