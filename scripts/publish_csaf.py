#!/usr/bin/env python3
"""publish_csaf.py: place validated CSAF documents into this repo's layout,
sign and hash them, and update index.txt, changes.csv and the ROLIE feed.
This is what the old "black box" did after validation.

Usage:   python3 scripts/publish_csaf.py <FEED> advisory.json [more.json ...]
         FEED = IT | OT | VA | auto   (auto: ICSA-/ICSMA- ids -> OT)

Environment:
  CSAF_ROOT    repo folder holding the feeds  (default: csaf_files)
  RAW_BASE     public URL of CSAF_ROOT, used in ROLIE feed links
               (default: https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files)
  ALLOWED_TLP  space-separated TLP labels     (default: WHITE)
  GPG_KEY_ID   key/fingerprint to sign with   (default: gpg's default key)
  WRITE_FEEDS  "true" to update index.txt, changes.csv and the ROLIE feed
               (default: true). Only set "false" if some other system
               generates those files for you.

Produces, matching the existing files in this repo:
  csaf_files/<FEED>/white/<year>/<id>.json  (+ .asc, .sha512)
  csaf_files/<FEED>/white/index.txt          (reverse-sorted)
  csaf_files/<FEED>/white/changes.csv        (newest first)
  csaf_files/<FEED>/white/cisa-csaf-<feed>-feed-tlp-white.json  (ROLIE)

Needs Python 3.11+ and gpg. No other tools.
"""
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

CSAF_ROOT = os.environ.get("CSAF_ROOT", "csaf_files")
RAW_BASE = os.environ.get("RAW_BASE", "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files")
ALLOWED_TLP = os.environ.get("ALLOWED_TLP", "WHITE")
WRITE_FEEDS = os.environ.get("WRITE_FEEDS", "true")
GPG_KEY_ID = os.environ.get("GPG_KEY_ID", "")


def die(msg):
    print(f"::error::{msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def require(doc, path, src, label):
    """Like `jq -e`: the value must exist and not be null/false."""
    cur = doc
    for key in path:
        cur = cur.get(key) if isinstance(cur, dict) else None
    if cur is None or cur is False:
        die(f"{src}: missing {label}")
    return cur if isinstance(cur, str) else json.dumps(cur, ensure_ascii=False)


def epoch(ts, what):
    try:
        return int(datetime.datetime.fromisoformat(ts).timestamp())
    except (TypeError, ValueError):
        die(f"can't parse {what} '{ts}'")


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def write_lines(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(line + "\n" for line in lines))
    os.replace(tmp, path)


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
def update_changelog(path, doc, rel, feed, tlp):
    t = doc["document"]
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
        "Written automatically by `scripts/publish_csaf.py` on every publish. Newest first.", "",
        "| Date | Advisory | Title | Version | Change |",
        "|---|---|---|---|---|",
    ]
    rows = []
    if os.path.exists(path):
        for line in read_lines(path):
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
# <<< CHANGELOG-MD FEATURE <<<


def update_index(path, rel):
    """index.txt: one path per line, reverse-sorted (as the repo has it)."""
    lines = read_lines(path) if os.path.exists(path) else []
    lines = [l for l in lines if l and l != rel] + [rel]
    write_lines(path, sorted(lines, reverse=True))


def update_changes(path, rel, current, feed):
    """changes.csv: <path>,<current_release_date>, newest first. The OT/VA files
    quote both fields and the IT file doesn't, so follow whatever is there;
    a brand-new file gets that feed's style (IT unquoted, OT/VA quoted)."""
    lines = read_lines(path) if os.path.exists(path) else []
    if any(lines):
        q = '"' if lines[0].startswith('"') else ""
    else:
        q = "" if feed == "IT" else '"'
    drop = re.compile(r'^"?' + re.escape(rel) + r'"?,')
    lines = [l for l in lines if l and not drop.match(l)]
    lines.append(f"{q}{rel}{q},{q}{current}{q}")

    def key(line):
        parts = line.split(",")
        return (parts[1] if len(parts) > 1 else "", parts[0])
    write_lines(path, sorted(lines, key=key, reverse=True))


def update_rolie(path, id_, title, published, updated, url, feed, tlp, self_url):
    """ROLIE feed: replace/insert the entry and keep the file's existing formatting."""
    fmt = {"sort_keys": False, "nl": ""}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            raw = f.read()
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


def sign(dest):
    """Detached, ASCII-armored OpenPGP signature, then verify it."""
    asc = dest + ".asc"
    if os.path.exists(asc):
        os.remove(asc)
    args = ["gpg", "--batch", "--yes", "--armor", "--detach-sign"]
    if GPG_KEY_ID:
        args += ["--local-user", GPG_KEY_ID]
    if subprocess.run(args + ["--output", asc, dest]).returncode != 0:
        die(f"gpg could not sign {dest}")
    v = subprocess.run(["gpg", "--batch", "--verify", asc, dest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in v.stdout.splitlines():
        print("  " + line)
    if v.returncode != 0:
        die(f"signature on {dest} does not verify")


def publish(src, feed_arg):
    print(f"::group::Publishing {src}", flush=True)
    try:
        with open(src, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        die(f"{src}: can't read JSON ({e})")
    if not isinstance(doc, dict):
        die(f"{src}: not a CSAF document")

    id_ = require(doc, ("document", "tracking", "id"), src, "/document/tracking/id")
    title = require(doc, ("document", "title"), src, "/document/title")
    tlp = require(doc, ("document", "distribution", "tlp", "label"), src, "/document/distribution/tlp/label")
    initial = require(doc, ("document", "tracking", "initial_release_date"), src, "initial_release_date")
    current = require(doc, ("document", "tracking", "current_release_date"), src, "current_release_date")
    status = doc["document"]["tracking"].get("status") or ""

    # Which feed (IT/OT/VA)?
    feed = feed_arg
    if feed == "AUTO":
        if id_.startswith(("ICSA-", "ICSMA-")):
            feed = "OT"
        else:
            die(f"{src}: can't tell the feed from id '{id_}'; pass IT, OT or VA explicitly")
    if feed not in ("IT", "OT", "VA"):
        die(f"unknown feed '{feed}' (expected IT, OT or VA)")

    # VA ids (published in either the IT or the VA feed): VA-<digits>[-<digits>...],
    # e.g. VA-26-302-01 -> <feed>/white/<year>/va-26-302-01.json (file name is lowercased below)
    if id_.upper().startswith("VA-") and not re.fullmatch(r"VA-[0-9]+(-[0-9]+)*", id_.upper()):
        die(f"{src}: VA id '{id_}' must be 'VA-' followed by numbers separated by '-' (e.g. VA-26-302-01)")

    if tlp not in ALLOWED_TLP.split():
        die(f"{src}: TLP '{tlp}' is not in ALLOWED_TLP ({ALLOWED_TLP}); refusing to publish")
    if status == "draft":
        die(f"{src}: tracking.status is 'draft'; refusing to publish")

    # CSAF 2.0 §5.1 file name: lowercase id, anything outside [+-a-z0-9] -> '_'
    fname = re.sub(r"[^+a-z0-9-]", "_", id_.lower()) + ".json"
    tlp_lc, feed_lc = tlp.lower(), feed.lower()
    tlp_dir = os.path.join(CSAF_ROOT, feed, tlp_lc)
    year = initial[:4]
    rel = f"{year}/{fname}"
    dest = f"{tlp_dir}/{rel}"
    url_base = f"{RAW_BASE}/{feed}/{tlp_lc}/{rel}"
    rolie = f"{tlp_dir}/cisa-csaf-{feed_lc}-feed-tlp-{tlp_lc}.json"

    # Don't overwrite a published advisory unless the revision is newer.
    if os.path.isfile(dest):
        with open(dest, encoding="utf-8") as f:
            old = json.load(f)["document"]["tracking"]["current_release_date"]
        if epoch(current, "current_release_date") <= epoch(old, f"current_release_date in {dest}"):
            die(f"{src}: {dest} already exists with current_release_date {old} (incoming: {current}). "
                "Bump the revision before re-publishing.")
        print(f"Updating {dest} ({old} -> {current})")

    os.makedirs(f"{tlp_dir}/{year}", exist_ok=True)
    if os.path.realpath(src) != os.path.realpath(dest):
        shutil.copyfile(src, dest)

    # Hash: same format as the existing .sha512 files ("<hash>  <name>", no newline)
    with open(dest, "rb") as f:
        digest = hashlib.sha512(f.read()).hexdigest()
    with open(dest + ".sha512", "w", encoding="utf-8") as f:
        f.write(f"{digest}  {fname}")

    sign(dest)

    # >>> CHANGELOG-MD FEATURE >>>
    if os.environ.get("WRITE_CHANGELOG", "true") == "true":
        update_changelog(f"{tlp_dir}/CHANGELOG.md", doc, rel, feed, tlp)
        print(f"Updated {tlp_dir}/CHANGELOG.md")
    # <<< CHANGELOG-MD FEATURE <<<

    if WRITE_FEEDS != "true":
        print(f"Published {dest} (WRITE_FEEDS=false: index/changes/ROLIE left alone)")
        print("::endgroup::", flush=True)
        return

    update_index(f"{tlp_dir}/index.txt", rel)
    update_changes(f"{tlp_dir}/changes.csv", rel, current, feed)
    update_rolie(rolie, id_, title, initial, current, url_base, feed, tlp,
                 f"{RAW_BASE}/{feed}/{tlp_lc}/{os.path.basename(rolie)}")

    print(f"Published {dest}")
    print("::endgroup::", flush=True)


def main(argv):
    if len(argv) < 2:
        die(f"usage: {sys.argv[0]} <IT|OT|VA|auto> file.json [file.json ...]")
    if shutil.which("gpg") is None:
        die("gpg is required")
    feed_arg = argv[0].upper()
    for src in argv[1:]:
        publish(src, feed_arg)


if __name__ == "__main__":
    main(sys.argv[1:])
