#!/usr/bin/env python3
"""ingest.py: the steps of the CSAF workflows, one subcommand per step.

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
            and incoming/<IT|OT|VA>/*.json; records what it did in
            $CSAF_MANIFEST (default .csaf-manifest.jsonl).
  commit    Turn the manifest into git changes. Env: BASE_BRANCH,
            PUBLISH_MODE, GH_TOKEN, GITHUB_* (set by Actions).
            pr (default): one branch and pull request PER ADVISORY,
              csaf/<file name>, holding only that advisory's .json/.asc/
              .sha512 plus the removal of its incoming/ source if that was
              committed to BASE_BRANCH. If an open PR for that advisory
              already holds exactly this, it is left alone; a newer
              revision updates the same branch and PR.
            push: one commit straight to BASE_BRANCH (rebased and retried
              if someone else pushed first), then dispatch csaf-feeds.yml.
            Only the files publish actually processed are removed from
            incoming/; anything else there is left alone.
  feeds     Rebuild index.txt / changes.csv / ROLIE / CHANGELOG.md with
            build_feeds.py and push the result to BASE_BRANCH, rebuilding
            and retrying if BASE_BRANCH moved meanwhile. Env: RAW_BASE,
            WRITE_CHANGELOG, BASE_BRANCH.
  check-pr  Pull request check. Validates every advisory JSON the PR adds or
            changes (incoming/ and csaf_files/), runs build_feeds.py --check
            on the whole tree, and fails if the PR edits a generated feed
            file. Env: BASE_REF (e.g. origin/develop).

Run from the repo root. Needs Python 3.11+, plus git/gh/gpg/node for the
steps that use them.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

FEEDS = ("IT", "OT", "VA")
MAX_BYTES = 50 * 1024 * 1024  # 50 MiB
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
PUSH_ATTEMPTS = 5
FEEDS_WORKFLOW = "csaf-feeds.yml"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

sys.path.insert(0, SCRIPTS)
import build_feeds  # noqa: E402


def die(msg):
    print(f"::error::{msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def env(name, default=""):
    return os.environ.get(name) or default


def incoming_files():
    """incoming/*.json, then incoming/<FEED>/*.json, in that order."""
    files = sorted(glob.glob("incoming/*.json"))
    for d in FEEDS:
        files += sorted(glob.glob(f"incoming/{d}/*.json"))
    return files


def run(cmd, **kw):
    """Run a command; fail the step if it fails."""
    r = subprocess.run(cmd, **kw)
    if r.returncode != 0:
        sys.exit(r.returncode)
    return r


def git(*args, capture=False, check=True, env_extra=None):
    e = dict(os.environ, **env_extra) if env_extra else None
    r = subprocess.run(["git", *args], stdout=subprocess.PIPE if capture else None, text=True, env=e)
    if check and r.returncode != 0:
        sys.exit(r.returncode)
    return r.stdout.strip() if capture else r.returncode


def gh_api(*args):
    """REST call through the gh CLI; returns parsed JSON (or None)."""
    r = subprocess.run(["gh", "api", *args], stdout=subprocess.PIPE, text=True)
    if r.returncode != 0:
        die(f"gh api {' '.join(args)} failed")
    return json.loads(r.stdout) if r.stdout.strip() else None


def bot_identity():
    git("config", "user.name", BOT_NAME)
    git("config", "user.email", BOT_EMAIL)


def run_url():
    return f"{env('GITHUB_SERVER_URL')}/{env('GITHUB_REPOSITORY')}/actions/runs/{env('GITHUB_RUN_ID')}"


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
        os.remove(dest)
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


def manifest_path():
    return env("CSAF_MANIFEST", ".csaf-manifest.jsonl")


def cmd_publish():
    manifest = manifest_path()
    open(manifest, "w").close()
    e = dict(os.environ, CSAF_MANIFEST=manifest)
    publish = [sys.executable, os.path.join(SCRIPTS, "publish_csaf.py")]
    for f in sorted(glob.glob("incoming/*.json")):
        run(publish + ["auto", f], env=e)
    for feed in FEEDS:
        for f in sorted(glob.glob(f"incoming/{feed}/*.json")):
            run(publish + [feed, f], env=e)


# ---- commit ------------------------------------------------------------------
def read_manifest():
    path = manifest_path()
    if not os.path.exists(path):
        die(f"{path} not found; run 'publish' first")
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def tracked(path, ref="HEAD"):
    return subprocess.run(["git", "cat-file", "-e", f"{ref}:{path}"], stderr=subprocess.DEVNULL).returncode == 0


def blob_of(ref, path):
    r = subprocess.run(["git", "rev-parse", "-q", "--verify", f"{ref}:{path}"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def already_waiting(ref, g, remove):
    """Does branch `ref` already hold this exact advisory JSON (and its .asc /
    .sha512) with the same incoming/ files removed? Compared on the JSON, not
    the signature, which differs every time it is made."""
    local = git("hash-object", "--", g["dest"], capture=True)
    return (blob_of(ref, g["dest"]) == local
            and all(blob_of(ref, g["dest"] + x) for x in (".asc", ".sha512"))
            and all(blob_of(ref, s) is None for s in remove))


def remote_branch(branch):
    """Fetch origin/<branch> if it exists; return its commit or None."""
    out = git("ls-remote", "origin", f"refs/heads/{branch}", capture=True)
    if not out:
        return None
    git("fetch", "-q", "--depth=1", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}")
    return git("rev-parse", f"refs/remotes/origin/{branch}", capture=True)


def tree_with(base, add, remove):
    """Tree of `base` plus working-tree files `add`, minus paths `remove`,
    built in a throwaway index so the checkout is never switched."""
    with tempfile.TemporaryDirectory() as d:
        idx = {"GIT_INDEX_FILE": os.path.join(d, "index")}
        git("read-tree", base, env_extra=idx)
        if add:
            git("add", "-f", "--", *add, env_extra=idx)
        if remove:
            git("rm", "-q", "--cached", "--ignore-unmatch", "--", *remove, env_extra=idx, capture=True)
        return git("write-tree", capture=True, env_extra=idx)


def group_by_advisory(entries):
    groups = {}
    for e in entries:
        g = groups.setdefault(e["dest"], {"id": e["id"], "dest": e["dest"], "add": [], "srcs": []})
        if e["status"] == "published":
            g["add"] = e["files"]
        g["srcs"].append(e["src"])
    return list(groups.values())


def open_pr(repo, base, branch):
    owner = repo.split("/")[0]
    prs = gh_api(f"repos/{repo}/pulls?head={owner}:{branch}&base={base}&state=open")
    return prs[0]["number"] if prs else None


def commit_pr(base, groups):
    repo = env("GITHUB_REPOSITORY")
    base_sha = git("rev-parse", "HEAD", capture=True)
    base_tree = git("rev-parse", "HEAD^{tree}", capture=True)
    for g in groups:
        branch = "csaf/" + os.path.basename(g["dest"])[:-5]
        remove = [s for s in g["srcs"] if tracked(s)]
        if tree_with("HEAD", g["add"], remove) == base_tree:
            print(f"{g['id']}: already on {base}, nothing to do")
            continue
        what = "Publish" if g["add"] else "Remove already-published incoming file for"
        title = f"{what} CSAF {g['id']}"

        # Already waiting in an open PR (an earlier run, or an incoming/ file that
        # stays on the base branch until its PR is merged)? If that PR's branch
        # already holds exactly this, leave it alone: no re-signing, no churn.
        number = open_pr(repo, base, branch)
        remote = remote_branch(branch) if number else None
        if remote and already_waiting(remote, g, remove):
            print(f"{g['id']}: identical advisory already waiting in PR #{number} ({branch}); leaving it")
            continue

        # Fresh commit on top of the current base. The branch belongs to the
        # pipeline: a newer revision replaces what was there and its PR updates.
        tree = tree_with("HEAD", g["add"], remove)
        commit = git("commit-tree", tree, "-p", base_sha, "-m", title, "-m", f"Run: {run_url()}", capture=True)
        git("push", "-q", "--force", "origin", f"{commit}:refs/heads/{branch}")
        if number:
            print(f"{g['id']}: updated PR #{number} ({branch})")
            continue
        body = (f"{what} `{g['id']}`.\n\nValidated (schema + mandatory tests), signed and hashed by "
                f"[workflow run]({run_url()}).\n\nOnly this advisory's files are in this PR. "
                "`index.txt`, `changes.csv`, the ROLIE feed and `CHANGELOG.md` are rebuilt "
                "automatically after merge, so this PR can be merged in any order with other "
                "advisory PRs.")
        pr = gh_api("-X", "POST", f"repos/{repo}/pulls", "-f", f"title={title}", "-f", f"head={branch}",
                    "-f", f"base={base}", "-f", f"body={body}")
        print(f"{g['id']}: opened PR #{pr['number']} ({branch}) {pr.get('html_url', '')}")


def push_with_retry(base, rebuild=None):
    """Push HEAD to base. If base moved, rebase (or, for generated files,
    reset and rebuild) and try again."""
    for attempt in range(1, PUSH_ATTEMPTS + 1):
        if git("push", "-q", "origin", f"HEAD:refs/heads/{base}", check=False) == 0:
            return True
        print(f"::notice::{base} moved; retrying ({attempt}/{PUSH_ATTEMPTS})")
        time.sleep(attempt - 1)
        git("fetch", "-q", "origin", f"+refs/heads/{base}:refs/remotes/origin/{base}")
        if rebuild:
            if not rebuild(f"origin/{base}"):
                return False
        elif git("rebase", "-q", f"origin/{base}", check=False) != 0:
            git("rebase", "--abort", check=False)
            die(f"could not rebase onto {base}: the same files were changed there")
    die(f"could not push to {base} after {PUSH_ATTEMPTS} attempts")


def commit_push(base, groups):
    add = [f for g in groups for f in g["add"]]
    remove = [s for g in groups for s in g["srcs"] if tracked(s)]
    if add:
        git("add", "-f", "--", *add)
    if remove:
        git("rm", "-q", "--ignore-unmatch", "--", *remove, capture=True)
    if git("diff", "--cached", "--quiet", check=False) == 0:
        print("No changes.")
        return
    ids = " ".join(g["id"] for g in groups if g["add"]) or "remove published incoming files"
    git("commit", "-q", "-m", f"Publish CSAF: {ids}", "-m", f"Run: {run_url()}")
    push_with_retry(base)
    # Pushes made with GITHUB_TOKEN don't trigger workflows; dispatch the feed rebuild.
    gh_api("-X", "POST", f"repos/{env('GITHUB_REPOSITORY')}/actions/workflows/{FEEDS_WORKFLOW}/dispatches",
           "-f", f"ref={base}")
    print(f"Pushed to {base}; requested {FEEDS_WORKFLOW}")


def cmd_commit():
    base = env("BASE_BRANCH", "develop")
    mode = env("PUBLISH_MODE", "pr")
    if mode not in ("pr", "push"):
        die(f"PUBLISH_MODE must be 'pr' or 'push', not '{mode}'")
    bot_identity()
    groups = group_by_advisory(read_manifest())
    if not groups:
        print("No changes.")
        return
    (commit_pr if mode == "pr" else commit_push)(base, groups)


# ---- feeds -------------------------------------------------------------------
def build(check_only=False):
    args = [sys.executable, os.path.join(SCRIPTS, "build_feeds.py")] + (["--check"] if check_only else [])
    return subprocess.run(args).returncode == 0


def stage_feeds():
    git("add", "-A", "--", build_feeds.CSAF_ROOT)
    return git("diff", "--cached", "--quiet", check=False) != 0


def cmd_feeds():
    base = env("BASE_BRANCH", "develop")
    if git("status", "--porcelain", capture=True):
        die("working tree is not clean; run 'feeds' on a fresh checkout")
    bot_identity()

    def rebuild(ref):
        git("reset", "-q", "--hard", ref)
        if not build():
            die("feed rebuild failed")
        if not stage_feeds():
            print("Feeds already up to date.")
            return False
        git("commit", "-q", "-m", "Rebuild CSAF feed indexes", "-m", f"Run: {run_url()}")
        return True

    if not rebuild("HEAD"):
        return
    if push_with_retry(base, rebuild=rebuild):
        print(f"Pushed feed indexes to {base}")


# ---- check-pr ----------------------------------------------------------------
def cmd_check_pr():
    base_ref = env("BASE_REF", "origin/develop")
    diff = git("diff", "--name-status", "--no-renames", f"{base_ref}...HEAD", capture=True)
    entries = [line.split("\t", 1) for line in diff.splitlines() if "\t" in line]
    ok = True
    for status, path in entries:
        if build_feeds.is_generated(path):
            print(f"::error file={path}::{path} is generated after merge by build_feeds.py; "
                  "drop this change from the PR")
            ok = False
    advisories = [p for s, p in entries if s in ("A", "M") and p.endswith(".json")
                  and not build_feeds.is_generated(p)
                  and (p.startswith("incoming/") or p.startswith(build_feeds.CSAF_ROOT + "/"))]
    if advisories:
        ok = run_ok(["node", os.path.join(SCRIPTS, "validate_csaf.mjs"), *advisories]) and ok
    else:
        print("No advisory JSON changed.")
    ok = build(check_only=True) and ok
    if not ok:
        sys.exit(1)


def run_ok(cmd):
    return subprocess.run(cmd).returncode == 0


COMMANDS = {
    "fetch": cmd_fetch,
    "collect": cmd_collect,
    "validate": cmd_validate,
    "publish": cmd_publish,
    "commit": cmd_commit,
    "feeds": cmd_feeds,
    "check-pr": cmd_check_pr,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        die(f"usage: {sys.argv[0]} {{{'|'.join(COMMANDS)}}}")
    COMMANDS[sys.argv[1]]()
