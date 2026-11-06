#!/usr/bin/env python3
"""publish_csaf.py: place validated CSAF documents into this repo's layout,
then sign and hash them. This is what the old "black box" did after validation.

It does NOT touch the shared files (index.txt, changes.csv, the ROLIE feed,
CHANGELOG.md). Those are regenerated from csaf_files/ by build_feeds.py after
each merge to develop, so pull requests for different advisories never
conflict and can be approved and merged in any order.

Usage:   python3 scripts/publish_csaf.py <FEED> advisory.json [more.json ...]
         FEED = IT | OT | VA | auto   (auto: ICSA-/ICSMA- ids -> OT)

Environment:
  CSAF_ROOT      repo folder holding the feeds  (default: csaf_files)
  ALLOWED_TLP    space-separated TLP labels     (default: WHITE)
  GPG_KEY_ID     key/fingerprint to sign with   (default: gpg's default key)
  CSAF_MANIFEST  if set, append one JSON line per input file describing what
                 happened (read by `ingest.py commit`)

Produces:
  csaf_files/<FEED>/<tlp>/<year>/<id>.json  (+ .asc, .sha512)

An input that is byte-identical to the advisory already at that path is
reported as "unchanged" and nothing is re-signed (so re-running the pipeline,
or a file left behind in incoming/, is harmless). A different file with the
same or an older current_release_date is refused: bump the revision.

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
ALLOWED_TLP = os.environ.get("ALLOWED_TLP", "WHITE")
GPG_KEY_ID = os.environ.get("GPG_KEY_ID", "")
FEEDS = ("IT", "OT", "VA")


def die(msg):
    print(f"::error::{msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def require(doc, path, src, label):
    """The value must exist and not be null/false."""
    cur = doc
    for key in path:
        cur = cur.get(key) if isinstance(cur, dict) else None
    if cur is None or cur is False:
        die(f"{src}: missing {label}")
    return cur if isinstance(cur, str) else json.dumps(cur, ensure_ascii=False)


def parse_time(ts):
    """ISO 8601 -> aware datetime (naive values are taken as UTC), or None."""
    try:
        t = datetime.datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def file_name(id_):
    """CSAF 2.0 §5.1 file name: lowercase id, anything outside [+-a-z0-9] -> '_'."""
    return re.sub(r"[^+a-z0-9-]", "_", id_.lower()) + ".json"


def sha512_line(path):
    """Same format as cisagov/CSAF .sha512 files: "<hash>  <name>", no newline."""
    with open(path, "rb") as f:
        return f"{hashlib.sha512(f.read()).hexdigest()}  {os.path.basename(path)}"


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


def record(entry):
    path = os.environ.get("CSAF_MANIFEST")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def publish(src, feed_arg):
    print(f"::group::Publishing {src}", flush=True)
    try:
        with open(src, "rb") as f:
            raw = f.read()
        doc = json.loads(raw)
    except (OSError, ValueError) as e:
        die(f"{src}: can't read JSON ({e})")
    if not isinstance(doc, dict):
        die(f"{src}: not a CSAF document")

    id_ = require(doc, ("document", "tracking", "id"), src, "/document/tracking/id")
    require(doc, ("document", "title"), src, "/document/title")
    tlp = require(doc, ("document", "distribution", "tlp", "label"), src, "/document/distribution/tlp/label")
    initial = require(doc, ("document", "tracking", "initial_release_date"), src, "initial_release_date")
    current = require(doc, ("document", "tracking", "current_release_date"), src, "current_release_date")
    status = doc["document"]["tracking"].get("status") or ""
    if parse_time(initial) is None or parse_time(current) is None:
        die(f"{src}: initial_release_date / current_release_date must be ISO 8601 date-times")

    # Which feed (IT/OT/VA)?
    feed = feed_arg
    if feed == "AUTO":
        if id_.upper().startswith(("ICSA-", "ICSMA-")):
            feed = "OT"
        else:
            die(f"{src}: can't tell the feed from id '{id_}'; pass IT, OT or VA explicitly")
    if feed not in FEEDS:
        die(f"unknown feed '{feed}' (expected IT, OT or VA)")

    # VA ids (published in either the IT or the VA feed): VA-<digits>[-<digits>...],
    # e.g. VA-26-302-01 -> <feed>/white/<year>/va-26-302-01.json
    if id_.upper().startswith("VA-") and not re.fullmatch(r"VA-[0-9]+(-[0-9]+)*", id_.upper()):
        die(f"{src}: VA id '{id_}' must be 'VA-' followed by numbers separated by '-' (e.g. VA-26-302-01)")

    if tlp not in ALLOWED_TLP.split():
        die(f"{src}: TLP '{tlp}' is not in ALLOWED_TLP ({ALLOWED_TLP}); refusing to publish")
    if status == "draft":
        die(f"{src}: tracking.status is 'draft'; refusing to publish")

    fname = file_name(id_)
    year = initial[:4]
    dest = os.path.join(CSAF_ROOT, feed, tlp.lower(), year, fname)
    files = [dest, dest + ".asc", dest + ".sha512"]
    entry = {"src": src, "id": id_, "feed": feed, "dest": dest, "files": files}

    if os.path.isfile(dest):
        with open(dest, "rb") as f:
            old_raw = f.read()
        if old_raw == raw:
            print(f"{dest} is already published with identical content; nothing to do")
            record({**entry, "status": "unchanged"})
            print("::endgroup::", flush=True)
            return
        old = parse_time(json.loads(old_raw)["document"]["tracking"].get("current_release_date"))
        if old is not None and parse_time(current) <= old:
            die(f"{src}: {dest} already exists with current_release_date {old.isoformat()} "
                f"(incoming: {current}). Bump the revision before re-publishing.")
        print(f"Updating {dest} (-> {current})")

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.realpath(src) != os.path.realpath(dest):
        shutil.copyfile(src, dest)
    with open(dest + ".sha512", "w", encoding="utf-8") as f:
        f.write(sha512_line(dest))
    sign(dest)
    record({**entry, "status": "published"})
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
