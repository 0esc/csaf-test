#!/usr/bin/env python3
"""build_feeds.py: regenerate every shared feed file from the advisories in
csaf_files/. Run after each merge to develop (.github/workflows/csaf-feeds.yml).

Because these files are rebuilt from scratch from what is actually in the
tree, they never need to be edited in a pull request, the output is the same
whatever order PRs are merged in, and running it twice changes nothing.

For each csaf_files/<FEED>/<tlp>/ that holds advisories, writes:
  index.txt                          one path per line, reverse-sorted
  changes.csv                        <path>,<current_release_date>, newest first
                                     (IT unquoted, OT/VA quoted, as cisagov/CSAF)
  cisa-csaf-<feed>-feed-tlp-<tlp>.json   ROLIE feed, newest first
  CHANGELOG.md                       one row per revision_history entry
                                     (skipped when WRITE_CHANGELOG=false)
A folder with no advisories left gets those files removed.

Every advisory is checked first: file name and year folder match its id and
initial_release_date, TLP matches its folder, the .sha512 matches and the .asc
exists. Any problem stops the run before anything is written.

Usage:   python3 scripts/build_feeds.py           check, then write
         python3 scripts/build_feeds.py --check   check only (no RAW_BASE needed)

Environment:
  CSAF_ROOT        default csaf_files
  RAW_BASE         public URL of CSAF_ROOT used in ROLIE links (required to write)
  WRITE_CHANGELOG  "false" to skip CHANGELOG.md (default true)

Prints the paths it changed. Exit 0 = OK, 1 = a check failed.
"""
import datetime
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from publish_csaf import FEEDS, file_name, parse_time, sha512_line  # noqa: E402

CSAF_ROOT = os.environ.get("CSAF_ROOT", "csaf_files")
EPOCH = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
SCHEMA = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"


def generated_names(feed, tlp):
    return ("index.txt", "changes.csv", f"cisa-csaf-{feed.lower()}-feed-tlp-{tlp}.json", "CHANGELOG.md")


def is_generated(path):
    """True for the bot-owned files under csaf_files/<FEED>/<tlp>/."""
    parts = os.path.normpath(path).split(os.sep)
    if len(parts) != 4 or parts[0] != os.path.normpath(CSAF_ROOT) or parts[1] not in FEEDS:
        return False
    return parts[3] in generated_names(parts[1], parts[2])


def ts(value):
    return parse_time(value) or EPOCH


def load_advisories(tlp_dir, feed, tlp, errors):
    advisories = []
    for path in sorted(glob.glob(os.path.join(tlp_dir, "*", "*.json"))):
        rel = os.path.relpath(path, tlp_dir).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            d = doc["document"]
            tr = d["tracking"]
            id_, title = tr["id"], d["title"]
            initial, current = tr["initial_release_date"], tr["current_release_date"]
            label = d["distribution"]["tlp"]["label"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            errors.append(f"{path}: not a readable CSAF document ({e})")
            continue
        if rel != f"{initial[:4]}/{file_name(id_)}":
            errors.append(f"{path}: should be at {tlp_dir}/{initial[:4]}/{file_name(id_)} "
                          f"(id {id_}, initial_release_date {initial})")
        if label.lower() != tlp:
            errors.append(f"{path}: TLP {label} does not match folder '{tlp}'")
        if not os.path.isfile(path + ".asc"):
            errors.append(f"{path}: missing .asc signature")
        try:
            with open(path + ".sha512", encoding="utf-8") as f:
                if f.read().strip() != sha512_line(path):
                    errors.append(f"{path}: .sha512 does not match the file")
        except OSError:
            errors.append(f"{path}: missing .sha512")
        advisories.append({"rel": rel, "id": id_, "title": title, "initial": initial,
                           "current": current, "doc": doc})
    return advisories


def render_index(advs):
    return "".join(r + "\n" for r in sorted((a["rel"] for a in advs), reverse=True))


def render_changes(advs, feed):
    q = "" if feed == "IT" else '"'
    rows = sorted(advs, key=lambda a: (ts(a["current"]), a["rel"]), reverse=True)
    return "".join(f'{q}{a["rel"]}{q},{q}{a["current"]}{q}\n' for a in rows)


def render_rolie(advs, feed, tlp, raw_base):
    name = f"cisa-csaf-{feed.lower()}-feed-tlp-{tlp}"
    rows = sorted(advs, key=lambda a: (ts(a["current"]), a["id"]), reverse=True)
    entries = []
    for a in rows:
        url = f"{raw_base}/{feed}/{tlp}/{a['rel']}"
        entries.append({
            "id": a["id"],
            "title": a["title"],
            "link": [
                {"href": url, "rel": "self"},
                {"href": url + ".asc", "rel": "signature"},
                {"href": url + ".sha512", "rel": "hash"},
            ],
            "published": a["initial"],
            "updated": a["current"],
            "content": {"src": url, "type": "application/json"},
            "format": {"schema": SCHEMA, "version": "2.0"},
        })
    feed_doc = {"feed": {
        "id": name,
        "title": f"CISA CSAF {feed} feed (TLP:{tlp.upper()})",
        "link": [{"rel": "self", "href": f"{raw_base}/{feed}/{tlp}/{name}.json"}],
        "category": [{"scheme": "urn:ietf:params:rolie:category:information-type", "term": "csaf"}],
        # Newest advisory date, not "now": keeps the output identical on re-runs.
        "updated": rows[0]["current"],
        "entry": entries,
    }}
    return json.dumps(feed_doc, indent=2, ensure_ascii=False) + "\n"


def render_changelog(advs, feed, tlp):
    cell = lambda s: re.sub(r"\s+", " ", str(s)).replace("|", "\\|").strip()
    rows = []
    for a in advs:
        for r in a["doc"]["document"]["tracking"].get("revision_history") or []:
            rows.append((ts(r.get("date")), a["id"], str(r.get("number", "")),
                         "| {} | [{}]({}) | {} | {} | {} |".format(
                             cell(str(r.get("date", ""))[:10]), cell(a["id"]), a["rel"],
                             cell(a["title"]), cell(r.get("number", "")), cell(r.get("summary", "")))))
    rows.sort(key=lambda r: r[:3], reverse=True)
    header = [
        f"# CISA CSAF {feed} feed changelog (TLP:{tlp.upper()})", "",
        "Generated by `scripts/build_feeds.py` from each advisory's revision history. "
        "Newest first. Do not edit by hand.", "",
        "| Date | Advisory | Title | Version | Change |",
        "|---|---|---|---|---|",
    ]
    return "\n".join(header + [r[3] for r in rows]) + "\n"


def write_if_changed(path, text, changed):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            if f.read() == text:
                return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    changed.append(path)


def main(argv):
    check_only = argv == ["--check"]
    if argv and not check_only:
        sys.exit(f"usage: {sys.argv[0]} [--check]")
    raw_base = os.environ.get("RAW_BASE", "").rstrip("/")
    if not check_only and not raw_base:
        print("::error::RAW_BASE (public URL of csaf_files/) must be set", file=sys.stderr)
        sys.exit(1)
    write_changelog = os.environ.get("WRITE_CHANGELOG", "true") != "false"

    errors, plans = [], []
    for feed in FEEDS:
        for tlp_dir in sorted(glob.glob(os.path.join(CSAF_ROOT, feed, "*/"))):
            tlp_dir = tlp_dir.rstrip("/" + os.sep)
            tlp = os.path.basename(tlp_dir)
            plans.append((feed, tlp, tlp_dir, load_advisories(tlp_dir, feed, tlp, errors)))
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    if errors:
        sys.exit(1)
    n = sum(len(p[3]) for p in plans)
    if check_only:
        print(f"OK: {n} advisories checked")
        return

    changed = []
    for feed, tlp, tlp_dir, advs in plans:
        names = generated_names(feed, tlp)
        paths = {name: os.path.join(tlp_dir, name) for name in names}
        if not advs:
            for p in paths.values():
                if os.path.exists(p):
                    os.remove(p)
                    changed.append(p)
            continue
        write_if_changed(paths["index.txt"], render_index(advs), changed)
        write_if_changed(paths["changes.csv"], render_changes(advs, feed), changed)
        write_if_changed(paths[names[2]], render_rolie(advs, feed, tlp, raw_base), changed)
        if write_changelog:
            write_if_changed(paths["CHANGELOG.md"], render_changelog(advs, feed, tlp), changed)
        elif os.path.exists(paths["CHANGELOG.md"]):
            os.remove(paths["CHANGELOG.md"])
            changed.append(paths["CHANGELOG.md"])
    for p in changed:
        print(f"updated {p}")
    print(f"{n} advisories, {len(changed)} feed file(s) changed")


if __name__ == "__main__":
    main(sys.argv[1:])
