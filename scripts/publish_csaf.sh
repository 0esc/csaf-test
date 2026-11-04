#!/usr/bin/env bash
# publish_csaf.sh: place validated CSAF documents into this repo's layout,
# sign and hash them, and update index.txt, changes.csv and the ROLIE feed.
# This is what the old "black box" did after validation.
#
# Usage:   scripts/publish_csaf.sh <FEED> advisory.json [more.json ...]
#          FEED = IT | OT | VA | auto   (auto: ICSA-/ICSMA- ids -> OT)
#
# Environment:
#   CSAF_ROOT    repo folder holding the feeds  (default: csaf_files)
#   RAW_BASE     public URL of CSAF_ROOT, used in ROLIE feed links
#                (default: https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files)
#   ALLOWED_TLP  space-separated TLP labels     (default: WHITE)
#   GPG_KEY_ID   key/fingerprint to sign with   (default: gpg's default key)
#   WRITE_FEEDS  "true" to update index.txt, changes.csv and the ROLIE feed
#                (default: true). Only set "false" if some other system
#                generates those files for you.
#
# Produces, matching the existing files in this repo:
#   csaf_files/<FEED>/white/<year>/<id>.json  (+ .asc, .sha512)
#   csaf_files/<FEED>/white/index.txt          (sort -r)
#   csaf_files/<FEED>/white/changes.csv        (newest first)
#   csaf_files/<FEED>/white/cisa-csaf-<feed>-feed-tlp-white.json  (ROLIE)
set -euo pipefail

CSAF_ROOT="${CSAF_ROOT:-csaf_files}"
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files}"
ALLOWED_TLP="${ALLOWED_TLP:-WHITE}"
WRITE_FEEDS="${WRITE_FEEDS:-true}"

die() { echo "::error::$*" >&2; exit 1; }

[ "$#" -ge 2 ] || die "usage: $0 <IT|OT|VA|auto> file.json [file.json ...]"
FEED_ARG=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]'); shift
for t in jq gpg python3 sha512sum; do command -v "$t" >/dev/null || die "$t is required"; done

sign_args=(--batch --yes --armor --detach-sign)
[ -n "${GPG_KEY_ID:-}" ] && sign_args+=(--local-user "$GPG_KEY_ID")

for src in "$@"; do
  echo "::group::Publishing $src"

  id=$(jq -er '.document.tracking.id' "$src")                        || die "$src: missing /document/tracking/id"
  title=$(jq -er '.document.title' "$src")                           || die "$src: missing /document/title"
  tlp=$(jq -er '.document.distribution.tlp.label' "$src")            || die "$src: missing /document/distribution/tlp/label"
  initial=$(jq -er '.document.tracking.initial_release_date' "$src") || die "$src: missing initial_release_date"
  current=$(jq -er '.document.tracking.current_release_date' "$src") || die "$src: missing current_release_date"
  status=$(jq -r '.document.tracking.status // ""' "$src")

  # Which feed (IT/OT/VA)?
  feed="$FEED_ARG"
  if [ "$feed" = "AUTO" ]; then
    case "$id" in
      ICSA-*|ICSMA-*) feed=OT ;;
      *) die "$src: can't tell the feed from id '$id'; pass IT, OT or VA explicitly" ;;
    esac
  fi
  case "$feed" in IT|OT|VA) ;; *) die "unknown feed '$feed' (expected IT, OT or VA)";; esac

  allowed=false
  for t in $ALLOWED_TLP; do [ "$tlp" = "$t" ] && allowed=true; done
  $allowed || die "$src: TLP '$tlp' is not in ALLOWED_TLP ($ALLOWED_TLP); refusing to publish"
  [ "$status" = "draft" ] && die "$src: tracking.status is 'draft'; refusing to publish"

  # CSAF 2.0 §5.1 file name: lowercase id, anything outside [+-a-z0-9] -> '_'
  fname="$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]' | sed 's/[^+a-z0-9-]/_/g').json"
  tlp_lc=$(printf '%s' "$tlp" | tr '[:upper:]' '[:lower:]')
  feed_lc=$(printf '%s' "$feed" | tr '[:upper:]' '[:lower:]')
  tlp_dir="$CSAF_ROOT/$feed/$tlp_lc"
  year="${initial:0:4}"
  rel="$year/$fname"
  dest="$tlp_dir/$rel"
  url_base="$RAW_BASE/$feed/$tlp_lc/$rel"
  rolie="$tlp_dir/cisa-csaf-$feed_lc-feed-tlp-$tlp_lc.json"

  # Don't overwrite a published advisory unless the revision is newer.
  if [ -f "$dest" ]; then
    old=$(jq -r '.document.tracking.current_release_date' "$dest")
    if [ "$(date -u -d "$current" +%s)" -le "$(date -u -d "$old" +%s)" ]; then
      die "$src: $dest already exists with current_release_date $old (incoming: $current). Bump the revision before re-publishing."
    fi
    echo "Updating $dest ($old -> $current)"
  fi

  mkdir -p "$tlp_dir/$year"
  [ "$(readlink -f "$src")" = "$(readlink -f "$dest")" ] || cp "$src" "$dest"

  # Hash: same format as the existing .sha512 files ("<hash>  <name>", no newline)
  ( cd "$tlp_dir/$year" && printf '%s  %s' "$(sha512sum "$fname" | cut -d' ' -f1)" "$fname" > "$fname.sha512" )

  # Detached, ASCII-armored OpenPGP signature, then verify it.
  rm -f "$dest.asc"
  gpg "${sign_args[@]}" --output "$dest.asc" "$dest"
  gpg --batch --verify "$dest.asc" "$dest" 2>&1 | sed 's/^/  /'

  # >>> CHANGELOG-MD FEATURE (added 2026-11-04) >>>
  # Adds one row per publish to <feed>/<tlp>/CHANGELOG.md, newest first:
  #   date (current_release_date) | advisory | title | version | change summary
  # The summary is the revision_history entry whose number matches
  # tracking.version (falls back to the last entry). Re-publishing the same
  # id + version replaces its row instead of adding a second one.
  # Turn off without deleting: WRITE_CHANGELOG=false (repo variable
  # CSAF_WRITE_CHANGELOG). To remove the feature entirely, delete everything
  # between the CHANGELOG-MD FEATURE markers in this file, csaf-ingest.yml and
  # CSAF-AUTOMATION.md, then delete csaf_files/*/*/CHANGELOG.md.
  if [ "${WRITE_CHANGELOG:-true}" = "true" ]; then
    python3 - "$tlp_dir/CHANGELOG.md" "$src" "$rel" "$feed" "$tlp" <<'PY'
import json, os, re, sys
path, src, rel, feed, tlp = sys.argv[1:]
t = json.load(open(src, encoding="utf-8"))["document"]
tr = t["tracking"]
hist = tr.get("revision_history", [])
rev = next((r for r in hist if str(r.get("number")) == str(tr.get("version"))), hist[-1] if hist else {})
cell = lambda s: re.sub(r"\s+", " ", str(s)).replace("|", "\\|").strip()
row = "| {} | [{}]({}) | {} | {} | {} |".format(
    cell(tr["current_release_date"][:10]), cell(tr["id"]), rel,
    cell(t["title"]), cell(tr.get("version", "")), cell(rev.get("summary", "")))
key = (tr["id"], str(tr.get("version", "")))
header = [
    f"# CISA CSAF {feed} feed changelog (TLP:{tlp})", "",
    "Written automatically by `scripts/publish_csaf.sh` on every publish. Newest first.", "",
    "| Date | Advisory | Title | Version | Change |",
    "|---|---|---|---|---|",
]
rows = []
if os.path.exists(path):
    for line in open(path, encoding="utf-8").read().splitlines():
        cols = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        if len(cols) != 5 or not re.match(r"\d{4}-\d\d-\d\d$", cols[0]):
            continue                                   # header / separator / other text
        m = re.match(r"\[([^\]]+)\]", cols[1])
        if (m.group(1) if m else cols[1], cols[3]) != key:
            rows.append(line)
rows.append(row)
rows.sort(key=lambda r: r[2:12], reverse=True)   # stable: same day keeps order
with open(path, "w", encoding="utf-8") as f:
    f.write("\n".join(header + rows) + "\n")
PY
    echo "Updated $tlp_dir/CHANGELOG.md"
  fi
  # <<< CHANGELOG-MD FEATURE <<<

  if [ "$WRITE_FEEDS" != "true" ]; then
    echo "Published $dest (WRITE_FEEDS=false: index/changes/ROLIE left alone)"
    echo "::endgroup::"
    continue
  fi

  # index.txt: one path per line, reverse-sorted (as the repo has it)
  touch "$tlp_dir/index.txt"
  { grep -vxF "$rel" "$tlp_dir/index.txt" || true; echo "$rel"; } | sort -r > "$tlp_dir/index.txt.tmp"
  mv "$tlp_dir/index.txt.tmp" "$tlp_dir/index.txt"

  # changes.csv: <path>,<current_release_date>, newest first. The OT/VA files
  # quote both fields and the IT file doesn't, so follow whatever is there.
  touch "$tlp_dir/changes.csv"
  q='"'; [ -s "$tlp_dir/changes.csv" ] && [ "$(head -c1 "$tlp_dir/changes.csv")" != '"' ] && q=''
  { grep -vE "^\"?${rel//./\\.}\"?," "$tlp_dir/changes.csv" || true; printf '%s%s%s,%s%s%s\n' "$q" "$rel" "$q" "$q" "$current" "$q"; } \
    | sort -t, -k2,2r -k1,1r > "$tlp_dir/changes.csv.tmp"
  mv "$tlp_dir/changes.csv.tmp" "$tlp_dir/changes.csv"

  # ROLIE feed: replace/insert the entry and keep the file's existing formatting.
  python3 - "$rolie" "$id" "$title" "$initial" "$current" "$url_base" "$feed" "$tlp" "$RAW_BASE/$feed/$tlp_lc/$(basename "$rolie")" <<'PY'
import json, os, sys, datetime
path, id_, title, published, updated, url, feed, tlp, self_url = sys.argv[1:]
fmt = {"sort_keys": False, "nl": ""}
if os.path.exists(path):
    raw = open(path, encoding="utf-8").read()
    doc = json.loads(raw)
    for sk in (False, True):
        for nl in ("", "\n"):
            if json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=sk) + nl == raw:
                fmt = {"sort_keys": sk, "nl": nl}
else:
    doc = {"feed": {
        "id": os.path.basename(path)[:-5],
        "title": f"CISA CSAF {feed} feed (TLP:{tlp})",
        "link": [{"rel": "self", "href": self_url}],
        "category": [{"scheme": "urn:ietf:params:rolie:category:information-type", "term": "csaf"}],
        "updated": "", "entry": []}}
entry = {
    "id": id_,
    "title": title,
    "link": [
        {"href": url, "rel": "self"},
        {"href": url + ".asc", "rel": "signature"},
        {"href": url + ".sha512", "rel": "hash"},
    ],
    "published": published,
    "updated": updated,
    "content": {"src": url, "type": "application/json"},
    "format": {"schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "version": "2.0"},
}
feed_obj = doc["feed"]
entries = [e for e in feed_obj.get("entry", []) if e.get("id") != id_]
entries.insert(0, entry)
entries.sort(key=lambda e: e.get("updated", ""), reverse=True)  # stable: ties keep order
feed_obj["entry"] = entries
feed_obj["updated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
with open(path, "w", encoding="utf-8") as f:
    f.write(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=fmt["sort_keys"]) + fmt["nl"])
PY

  echo "Published $dest"
  echo "::endgroup::"
done
