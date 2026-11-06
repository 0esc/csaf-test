#!/usr/bin/env python3
"""ingest.py: the steps of .github/workflows/csaf-ingest.yml (and the
"validate incoming" step of test.yml), one subcommand per workflow step.

Usage:  python3 scripts/ingest.py <command>

  fetch     Download SRC_URL into incoming/[<FEED>/]fetched-<run id>.json.
            Env: SRC_URL, FEED (IT|OT|VA|auto), COORDINATOR_HOST,
                 COORDINATOR_TOKEN (optional), GITHUB_RUN_ID.
            The URL must be https (redirects too) on COORDINATOR_HOST;
            at most 50 MiB; must be JSON.
  collect   List the files waiting in incoming/ and write count=<n> to
            $GITHUB_OUTPUT.
  validate  Run scripts/validate_csaf.mjs on everything in incoming/
            (schema + mandatory tests). Nothing waiting = success.
  publish   Run publish_csaf.py on incoming/*.json (feed auto-detected)
            and incoming/<IT|OT|VA>/*.json.
  commit    Remove the processed incoming/ files, stage csaf_files/ and
            either push to BASE_BRANCH (PUBLISH_MODE=push) or push a new
            branch and open a pull request (PUBLISH_MODE=pr, the default).
            Env: BASE_BRANCH, PUBLISH_MODE, GH_TOKEN, GITHUB_* (set by Actions).

Run from the repo root. Needs Python 3.11+, plus git/gh/gpg/node for the
steps that use them.
"""
import datetime
import glob
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

FEEDS = ("IT", "OT", "VA")
MAX_BYTES = 50 * 1024 * 1024  # 50 MiB
SCRIPTS = os.path.dirname(os.path.abspath(__file__))


def die(msg):
    print(f"::error::{msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def env(name, default=""):
    return os.environ.get(name) or default


def incoming_files(subdirs=FEEDS):
    """incoming/*.json, then incoming/<FEED>/*.json, in that order."""
    files = sorted(glob.glob("incoming/*.json"))
    for d in subdirs:
        files += sorted(glob.glob(f"incoming/{d}/*.json"))
    return files


def run(cmd, **kw):
    """Run a command, echoing nothing extra; fail the step if it fails."""
    r = subprocess.run(cmd, **kw)
    if r.returncode != 0:
        sys.exit(r.returncode)
    return r


# ---- fetch -----------------------------------------------------------------
class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs (like curl --proto '=https'), and
    drop the Authorization header if a redirect leaves the original host."""

    def __init__(self, host):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.parse.urlsplit(newurl)
        if new.scheme != "https":
            die(f"redirect to non-https URL refused: {newurl}")
        r = super().redirect_request(req, fp, code, msg, headers, newurl)
        if r is not None and new.hostname != self.host:
            r.remove_header("Authorization")
        return r


def download(url, token, dest):
    host = urllib.parse.urlsplit(url).hostname
    opener = urllib.request.build_opener(_HttpsOnlyRedirects(host))
    req = urllib.request.Request(url, headers={"User-Agent": "csaf-ingest"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with opener.open(req, timeout=120) as resp:
            if int(resp.headers.get("Content-Length") or 0) > MAX_BYTES:
                die(f"file is larger than {MAX_BYTES} bytes")
            data = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        die(f"download failed: HTTP {e.code} from {url}")
    except (urllib.error.URLError, OSError) as e:
        die(f"download failed: {e}")
    if len(data) > MAX_BYTES:
        die(f"file is larger than {MAX_BYTES} bytes")
    with open(dest, "wb") as f:
        f.write(data)
    return data


def cmd_fetch():
    url = env("SRC_URL")
    feed = env("FEED", "auto").upper()
    allowed_host = env("COORDINATOR_HOST")

    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        die("URL must be https")
    host = parts.hostname or ""
    if not allowed_host or host != allowed_host.lower():
        die(f"Host '{host}' is not COORDINATOR_HOST ('{allowed_host}')")
    if feed in FEEDS:
        directory = f"incoming/{feed}"
    elif feed == "AUTO":
        directory = "incoming"
    else:
        die(f"bad feed {feed}")

    os.makedirs(directory, exist_ok=True)
    dest = f"{directory}/fetched-{env('GITHUB_RUN_ID', 'local')}.json"
    data = download(url, env("COORDINATOR_TOKEN"), dest)
    try:
        json.loads(data)
    except ValueError:
        die("Not valid JSON")
    print(f"Saved {dest}")


# ---- collect / validate / publish -------------------------------------------
def cmd_collect():
    files = incoming_files()
    for f in files:
        print(f)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"count={len(files)}\n")
    if not files:
        print("::notice::Nothing in incoming/")


def cmd_validate():
    files = incoming_files()
    if not files:
        print("Nothing in incoming/")
        return
    run(["node", os.path.join(SCRIPTS, "validate_csaf.mjs"), *files])


def cmd_publish():
    publish = [sys.executable, os.path.join(SCRIPTS, "publish_csaf.py")]
    for f in sorted(glob.glob("incoming/*.json")):
        run(publish + ["auto", f])
    for feed in FEEDS:
        for f in sorted(glob.glob(f"incoming/{feed}/*.json")):
            run(publish + [feed, f])


# ---- commit ------------------------------------------------------------------
def git(*args, capture=False):
    r = run(["git", *args], stdout=subprocess.PIPE if capture else None, text=True)
    return r.stdout if capture else None


def cmd_commit():
    base = env("BASE_BRANCH", "develop")
    mode = env("PUBLISH_MODE", "pr")
    run_url = f"{env('GITHUB_SERVER_URL')}/{env('GITHUB_REPOSITORY')}/actions/runs/{env('GITHUB_RUN_ID')}"

    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")

    done = sorted(glob.glob("incoming/*.json") + glob.glob("incoming/*/*.json"))
    if done:
        git("rm", "-q", "--cached", "--ignore-unmatch", "--", *done, capture=True)
        for f in done:
            os.remove(f)
    git("add", "-A", "csaf_files")
    if subprocess.run(["git", "diff", "--cached", "--quiet"]).returncode == 0:
        print("No changes.")
        return

    changed = git("diff", "--cached", "--name-only", "--diff-filter=AM", "--", "csaf_files", capture=True)
    ids = [os.path.basename(p)[:-5].upper()
           for p in changed.splitlines() if re.search(r"/[0-9]{4}/[^/]+\.json$", p)]
    msg = "Publish CSAF: " + " ".join(ids)

    if mode == "push":
        git("commit", "-q", "-m", msg, "-m", f"Run: {run_url}")
        git("push", "origin", f"HEAD:{base}")
    else:
        branch = f"csaf/{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-{env('GITHUB_RUN_ID', 'local')}"
        git("switch", "-q", "-c", branch)
        git("commit", "-q", "-m", msg, "-m", f"Run: {run_url}")
        git("push", "-q", "origin", branch)
        run(["gh", "pr", "create", "--base", base, "--head", branch, "--title", msg,
             "--body", f"Validated (schema + mandatory tests), signed and indexed by [workflow run]({run_url})."])


COMMANDS = {
    "fetch": cmd_fetch,
    "collect": cmd_collect,
    "validate": cmd_validate,
    "publish": cmd_publish,
    "commit": cmd_commit,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        die(f"usage: {sys.argv[0]} {{{'|'.join(COMMANDS)}}}")
    COMMANDS[sys.argv[1]]()
