#!/usr/bin/env python3
"""test_publish.py: end-to-end tests for validate_csaf.mjs, publish_csaf.py,
build_feeds.py and the ingest.py workflow steps.

Fully local: works in a temp folder with a throwaway GPG key in a temp
GNUPGHOME, a local bare git repo standing in for GitHub and a stub `gh` that
records API calls. It never touches your real keyring, your csaf_files/, the
network or any external host. All advisories are synthetic and generated
here (ids ICSA-00-000-xx / VA-00-000-xx). Needs: python3 (3.11+), gpg, git,
node, and `npm ci` run once in the repo (openssl for the fetch tests).

Usage:  python3 scripts/test_publish.py        (or: npm test)
Exit:   0 if every check passes, 1 otherwise.
"""
import copy
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
passed = failed = 0


# ---- helpers ------------------------------------------------------------------
def ok(name):
    global passed
    print(f"  PASS  {name}")
    passed += 1


def bad(name, detail=""):
    global failed
    print(f"  FAIL  {name}")
    for line in detail.splitlines()[-40:]:
        print(f"        {line}")
    failed += 1


def check(name, cond, detail=""):
    ok(name) if cond else bad(name, detail)


def run(cmd, extra=None, cwd=None):
    e = dict(os.environ, **(extra or {}))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=e, cwd=cwd)
    return p.returncode, p.stdout


def expect_ok(name, cmd, extra=None):
    rc, out = run(cmd, extra)
    check(name, rc == 0, out)
    return out


def expect_fail(name, cmd, extra=None):
    rc, out = run(cmd, extra)
    if rc == 0:
        bad(f"{name} (should have failed)", out)
    else:
        ok(name)
    return out


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(doc, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def sh(*cmd, cwd=None):
    """Run a setup command that must succeed; return stdout."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
    if p.returncode != 0:
        raise SystemExit(f"setup command failed: {' '.join(cmd)}\n{p.stdout}{p.stderr}")
    return p.stdout.strip()


def git(*args, cwd=None):
    return sh("git", *args, cwd=cwd)


# ---- synthetic fixtures ------------------------------------------------------
def advisory(id_, ts="2026-01-02T00:00:00.000Z", title="Synthetic test advisory"):
    """A minimal CSAF 2.0 security advisory that passes every mandatory test."""
    return {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "distribution": {"tlp": {"label": "WHITE", "url": "https://www.first.org/tlp/"}},
            "lang": "en-US",
            "notes": [{"category": "summary", "title": "Summary",
                       "text": "Synthetic test advisory. Not a real vulnerability."}],
            "publisher": {"category": "coordinator", "name": "Example Test Publisher",
                          "namespace": "https://example.invalid"},
            "references": [{"category": "self", "summary": "Self", "url": "https://example.invalid/t.json"}],
            "title": title,
            "tracking": {
                "current_release_date": ts, "id": id_, "initial_release_date": ts,
                "revision_history": [{"date": ts, "number": "1", "summary": "Initial test publication"}],
                "status": "final", "version": "1",
            },
        },
        "product_tree": {"branches": [{"category": "vendor", "name": "Example Vendor", "branches": [
            {"category": "product_name", "name": "Example Product", "branches": [
                {"category": "product_version", "name": "1.0",
                 "product": {"name": "Example Vendor Example Product 1.0", "product_id": "CSAFPID-0001"}}]}]}]},
        "vulnerabilities": [{
            "title": "Synthetic weakness",
            "cwe": {"id": "CWE-20", "name": "Improper Input Validation"},
            "notes": [{"category": "summary", "title": "Description", "text": "Synthetic."}],
            "product_status": {"known_affected": ["CSAFPID-0001"]},
            "remediations": [{"category": "no_fix_planned", "details": "Synthetic test data.",
                              "product_ids": ["CSAFPID-0001"]}],
        }],
    }


def revise(doc, ts, number, summary="Test update"):
    d = copy.deepcopy(doc)
    tr = d["document"]["tracking"]
    tr.update(current_release_date=ts, version=number)
    tr["revision_history"].append({"date": ts, "number": number, "summary": summary})
    return d


GH_STUB = r'''#!/usr/bin/env python3
# Stand-in for the gh CLI: records REST calls and keeps PR state in $GH_STATE.
import json, os, sys, urllib.parse
path = os.environ["GH_STATE"]
state = json.load(open(path)) if os.path.exists(path) else {"prs": [], "dispatches": [], "calls": []}
a = sys.argv[1:]
state["calls"].append(a)
assert a[0] == "api", a
method = "GET"
if a[1] == "-X":
    method, a = a[2], [a[0]] + a[3:]
endpoint = a[1]
fields = dict(x.split("=", 1) for x in a[3::2]) if len(a) > 2 else {}
out = None
if method == "GET" and "/pulls?" in endpoint:
    q = urllib.parse.parse_qs(endpoint.split("?", 1)[1])
    head = q["head"][0].split(":", 1)[1]
    out = [p for p in state["prs"] if p["head"] == head and p["state"] == "open"]
elif method == "POST" and endpoint.endswith("/pulls"):
    pr = {"number": len(state["prs"]) + 1, "head": fields["head"], "base": fields["base"],
          "title": fields["title"], "state": "open", "html_url": "https://github.example/pr"}
    state["prs"].append(pr)
    out = pr
elif method == "POST" and endpoint.endswith("/dispatches"):
    state["dispatches"].append({"endpoint": endpoint, **fields})
else:
    sys.exit(f"gh stub: unexpected call {sys.argv[1:]}")
json.dump(state, open(path, "w"))
if out is not None:
    print(json.dumps(out))
'''


def start_https_server(work):
    """Local HTTPS server (self-signed cert for localhost + 127.0.0.1) used to
    test `ingest.py fetch` without touching the network. Returns (port, ca_file)
    or None if openssl isn't installed."""
    if shutil.which("openssl") is None:
        return None
    import http.server
    import ssl
    import threading
    cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", key, "-out", cert], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body=b"", headers=()):
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            if not any(k == "Content-Length" for k, _ in headers):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            port = self.server.server_address[1]
            auth = json.dumps({"auth": self.headers.get("Authorization")}).encode()
            routes = {
                "/ok.json": lambda: self.send(200, b'{"document": {}}'),
                "/auth.json": lambda: self.send(200, auth),
                "/notjson": lambda: self.send(200, b"<html>"),
                "/missing": lambda: self.send(404, b"nope"),
                "/big": lambda: self.send(200, b"", [("Content-Length", str(60 * 1024 * 1024))]),
                "/to-http": lambda: self.send(302, headers=[("Location", f"http://localhost:{port}/ok.json")]),
                "/to-same": lambda: self.send(302, headers=[("Location", f"https://localhost:{port}/auth.json")]),
                "/to-other": lambda: self.send(302, headers=[("Location", f"https://127.0.0.1:{port}/auth.json")]),
            }
            routes.get(self.path, lambda: self.send(404))()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], cert


# ---- 1. validation, publish_csaf.py, build_feeds.py ----------------------------
def test_scripts(work, F, raw_base):
    repo = os.path.join(work, "repo")
    os.makedirs(os.path.join(repo, "csaf_files"))
    shutil.copytree(os.path.join(REPO, "scripts"), os.path.join(repo, "scripts"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    os.symlink(os.path.join(REPO, "node_modules"), os.path.join(repo, "node_modules"))
    os.chdir(repo)
    validate = lambda *files: ["node", "scripts/validate_csaf.mjs", *files]
    publish = lambda feed, *files: [sys.executable, "scripts/publish_csaf.py", feed, *files]
    feeds = lambda *a: [sys.executable, "scripts/build_feeds.py", *a]

    print("Validation (schema + mandatory tests, offline)")
    expect_ok("valid VA advisory passes", validate(F("va.json")))
    expect_ok("valid ICSA advisory passes", validate(F("icsa.json")))
    expect_fail("missing /document/title is rejected", validate(F("no-title.json")))
    expect_fail("undefined product id is rejected", validate(F("bad-pid.json")))
    expect_fail("non-JSON file is rejected", validate(F("garbage.json")))

    print("Publish: sign, hash, place (no shared files)")
    manifest = os.path.join(work, "manifest.jsonl")
    expect_ok("VA-00-000-01 publishes to IT", publish("IT", F("va.json")), {"CSAF_MANIFEST": manifest})
    d = "csaf_files/IT/white"
    adv = f"{d}/2000/va-00-000-01.json"
    check("advisory, .asc and .sha512 placed under <year of initial_release_date>",
          all(os.path.isfile(adv + x) for x in ("", ".asc", ".sha512")))
    check("no index/changes/ROLIE/CHANGELOG written by publish",
          sorted(os.listdir(d)) == ["2000"], str(os.listdir(d)))
    expect_ok("signature verifies", ["gpg", "--batch", "--verify", adv + ".asc", adv])
    with open(adv, "rb") as f:
        digest = hashlib.sha512(f.read()).hexdigest()
    check(".sha512 matches file", read(adv + ".sha512") == f"{digest}  va-00-000-01.json")
    m = [json.loads(line) for line in read(manifest).splitlines()]
    check("manifest records the publish", len(m) == 1 and m[0]["status"] == "published"
          and m[0]["dest"] == adv and m[0]["id"] == "VA-00-000-01", str(m))

    print("Publish: revisions and guards")
    asc_before = read(adv + ".asc")
    out = expect_ok("identical re-publish is a no-op, not an error", publish("IT", F("va.json")),
                    {"CSAF_MANIFEST": manifest})
    check("... and is reported 'unchanged' without re-signing",
          json.loads(read(manifest).splitlines()[-1])["status"] == "unchanged" and read(adv + ".asc") == asc_before, out)
    expect_fail("different content with the same date is refused", publish("IT", F("va-same-date.json")))
    expect_ok("newer revision replaces it", publish("IT", F("va-v2.json")))
    expect_fail("older revision after a newer one is refused", publish("IT", F("va-same-date.json")))
    expect_fail("malformed VA id is refused", publish("IT", F("va-badid.json")))
    expect_fail("unknown id with feed=auto is refused", publish("auto", F("unknown-auto.json")))
    routed = {"CSAF_ROOT": "routing"}   # kept apart from csaf_files/, whose feed contents are asserted below
    expect_ok("VA id with feed=auto routes to IT", publish("auto", F("va-auto.json")), routed)
    check("... placed under IT/white", os.path.isfile("routing/IT/white/2000/va-00-000-99.json"))
    expect_fail("TLP:AMBER is refused", publish("IT", F("va-amber.json")))
    expect_fail("draft status is refused", publish("IT", F("va-draft.json")))
    expect_ok("VA id requested for the VA feed still goes to IT", publish("VA", F("va-vafeed.json")), routed)
    check("... placed under IT/white, not VA/white", os.path.isfile("routing/IT/white/2000/va-00-000-03.json")
          and not os.path.exists("routing/VA"))
    expect_ok("ICSA id auto-routes to OT", publish("auto", F("icsa.json")))
    expect_ok("second ICSA (later date) publishes", publish("auto", F("icsa2.json")))
    expect_ok("published file still validates", validate(adv))

    print("Feeds: rebuilt from csaf_files/ by build_feeds.py")
    expect_fail("RAW_BASE is required to write feeds", feeds(), {"RAW_BASE": ""})
    out = expect_ok("build_feeds writes every feed", feeds(), {"RAW_BASE": raw_base})
    for f in ("index.txt", "changes.csv", "CHANGELOG.md", "cisa-csaf-it-feed-tlp-white.json"):
        check(f"IT/white/{f} written", os.path.isfile(f"{d}/{f}"))
    check("IT changes.csv unquoted", read(f"{d}/changes.csv") ==
          "2000/va-00-000-01.json,2026-01-03T00:00:00.000Z\n", read(f"{d}/changes.csv"))
    ot = "csaf_files/OT/white"
    check("OT index.txt reverse-sorted",
          read(f"{ot}/index.txt") == "2000/icsa-00-000-02.json\n2000/icsa-00-000-01.json\n", read(f"{ot}/index.txt"))
    check("OT changes.csv newest first by real time, not text (+05:00 offset)",
          read(f"{ot}/changes.csv").startswith('"2000/icsa-00-000-01.json"'), read(f"{ot}/changes.csv"))
    rolie = load(f"{ot}/cisa-csaf-ot-feed-tlp-white.json")["feed"]
    check("ROLIE entries newest first, links use RAW_BASE",
          [e["id"] for e in rolie["entry"]] == ["ICSA-00-000-01", "ICSA-00-000-02"]
          and rolie["entry"][0]["content"]["src"] == f"{raw_base}/OT/white/2000/icsa-00-000-01.json"
          and rolie["link"][0]["href"] == f"{raw_base}/OT/white/cisa-csaf-ot-feed-tlp-white.json", json.dumps(rolie)[:500])
    check("ROLIE feed.updated is the newest advisory date (deterministic)",
          rolie["updated"] == "2026-01-04T23:00:00.000Z", rolie["updated"])
    cl = [line for line in read(f"{d}/CHANGELOG.md").splitlines() if "VA-00-000-01" in line]
    check("CHANGELOG.md has one row per revision, newest first",
          len(cl) == 2 and "| 2 |" in cl[0] and "| 1 |" in cl[1], "\n".join(cl))
    snapshot = {p: read(p) for p in glob.glob("csaf_files/*/*/*") if os.path.isfile(p)}
    out = expect_ok("second build_feeds run", feeds(), {"RAW_BASE": raw_base})
    check("... changes nothing (idempotent)", "0 feed file(s) changed" in out and
          snapshot == {p: read(p) for p in glob.glob("csaf_files/*/*/*") if os.path.isfile(p)}, out)
    expect_ok("WRITE_CHANGELOG=false", feeds(), {"RAW_BASE": raw_base, "WRITE_CHANGELOG": "false"})
    check("... removes CHANGELOG.md", not os.path.exists(f"{d}/CHANGELOG.md"))
    expect_ok("build_feeds --check passes on a good tree", feeds("--check"), {"RAW_BASE": ""})

    with open(adv, "a") as f:
        f.write(" ")
    expect_fail("--check catches a .sha512 that doesn't match", feeds("--check"))
    expect_fail("... and a normal build refuses to write", feeds(), {"RAW_BASE": raw_base})
    shutil.copy(F("va-v2.json"), adv)
    os.makedirs("csaf_files/IT/white/1999")
    shutil.move(adv, "csaf_files/IT/white/1999/va-00-000-01.json")
    expect_fail("--check catches an advisory in the wrong year folder", feeds("--check"))
    shutil.rmtree("csaf_files/IT")
    os.makedirs("csaf_files/IT/white")
    for f in ("index.txt", "changes.csv", "cisa-csaf-it-feed-tlp-white.json"):
        open(f"csaf_files/IT/white/{f}", "w").close()
    expect_ok("feed folder with no advisories left", feeds(), {"RAW_BASE": raw_base})
    check("... gets its generated files removed", os.listdir("csaf_files/IT/white") == [])


# ---- 2. ingest.py: the workflow steps against a local "GitHub" ----------------
def test_ingest(work, F, raw_base):
    remote = os.path.join(work, "remote.git")
    seed = os.path.join(work, "seed")
    ci = os.path.join(work, "ci")          # the Actions checkout of develop
    other = os.path.join(work, "other")    # someone else pushing/merging meanwhile
    bindir = os.path.join(work, "bin")
    os.makedirs(bindir)
    with open(os.path.join(bindir, "gh"), "w") as f:
        f.write(GH_STUB)
    os.chmod(os.path.join(bindir, "gh"), 0o755)
    state_file = os.path.join(work, "gh_state.json")
    gh_state = lambda: load(state_file) if os.path.exists(state_file) else {"prs": [], "dispatches": []}

    # develop: scripts + empty csaf_files/ + incoming/ with .gitkeeps
    os.makedirs(seed)
    shutil.copytree(os.path.join(REPO, "scripts"), os.path.join(seed, "scripts"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    for p in ("csaf_files/.gitkeep", "incoming/.gitkeep", "incoming/IT/.gitkeep",
              "incoming/OT/.gitkeep", "incoming/VA/.gitkeep"):
        os.makedirs(os.path.dirname(os.path.join(seed, p)), exist_ok=True)
        open(os.path.join(seed, p), "w").close()
    shutil.copy(os.path.join(REPO, ".gitignore"), seed)
    # Two organisations' submissions sit committed in incoming/ (they stay on
    # develop until their PR merges), plus a stray file in a non-feed folder.
    shutil.copy(F("icsa.json"), os.path.join(seed, "incoming/OT/icsa.json"))
    os.makedirs(os.path.join(seed, "incoming/misc"))
    shutil.copy(F("icsa2.json"), os.path.join(seed, "incoming/misc/stray.json"))
    git("init", "-q", "--bare", "-b", "develop", remote)
    git("init", "-q", "-b", "develop", cwd=seed)
    for cmd in (["config", "user.name", "t"], ["config", "user.email", "t@x.invalid"], ["add", "-A"],
                ["commit", "-q", "-m", "base"], ["remote", "add", "origin", remote], ["push", "-q", "origin", "develop"]):
        git(*cmd, cwd=seed)

    def fresh_checkout(path):
        """A new Actions job: clean clone of develop."""
        os.chdir(work)
        shutil.rmtree(path, ignore_errors=True)
        git("clone", "-q", "-b", "develop", remote, path)
        git("config", "user.name", "t", cwd=path)
        git("config", "user.email", "t@x.invalid", cwd=path)
        os.symlink(os.path.join(REPO, "node_modules"), os.path.join(path, "node_modules"))
        os.chdir(path)

    def remote_files(ref):
        return set(sh("git", "--git-dir", remote, "ls-tree", "-r", "--name-only", ref).splitlines())

    def remote_sha(ref):
        return sh("git", "--git-dir", remote, "rev-parse", ref)

    gh = {"GITHUB_REPOSITORY": "o/r", "GITHUB_SERVER_URL": "https://github.example", "GITHUB_RUN_ID": "42",
          "BASE_BRANCH": "develop", "GH_STATE": state_file, "PATH": bindir + os.pathsep + os.environ["PATH"],
          "RAW_BASE": raw_base}
    ingest = lambda cmd: [sys.executable, "scripts/ingest.py", cmd]
    step = lambda cmd, **extra: run(ingest(cmd), {**gh, **extra})

    fresh_checkout(ci)
    print("Ingest: fetch (local HTTPS server, no network)")
    base = {"COORDINATOR_HOST": "localhost", "GITHUB_RUN_ID": "1", "FEED": "auto"}
    for name, extra in (
        ("http URL is refused", {"SRC_URL": "http://localhost/ok.json"}),
        ("host other than COORDINATOR_HOST is refused", {"SRC_URL": "https://evil.example/ok.json"}),
        ("look-alike host is refused", {"SRC_URL": "https://localhost.evil.example/ok.json"}),
        ("unset COORDINATOR_HOST is refused", {"SRC_URL": "https://localhost/ok.json", "COORDINATOR_HOST": ""}),
        ("unknown feed is refused", {"SRC_URL": "https://localhost/ok.json", "FEED": "XX"}),
    ):
        rc, out = run(ingest("fetch"), {**base, **extra})
        check(name, rc != 0, out)
    server = start_https_server(work)
    if server is None:
        print("  SKIP  download tests (openssl not installed)")
    else:
        port, ca = server
        url = lambda path, host="localhost": f"https://{host}:{port}{path}"
        net = {**base, "SSL_CERT_FILE": ca, "NO_PROXY": "*", "no_proxy": "*", "COORDINATOR_TOKEN": "s3cret"}
        rc, out = run(ingest("fetch"), {**net, "SRC_URL": url("/ok.json"), "FEED": "ot", "GITHUB_RUN_ID": "7"})
        check("downloads into incoming/OT/fetched-<run id>.json",
              rc == 0 and os.path.isfile("incoming/OT/fetched-7.json"), out)
        rc, out = run(ingest("fetch"), {**net, "SRC_URL": url("/auth.json"), "GITHUB_RUN_ID": "8"})
        check("sends the coordinator token", rc == 0 and load("incoming/fetched-8.json")["auth"] == "Bearer s3cret", out)
        rc, out = run(ingest("fetch"), {**net, "SRC_URL": url("/to-same"), "GITHUB_RUN_ID": "9"})
        check("follows https redirect on the same host, keeping the token",
              rc == 0 and load("incoming/fetched-9.json")["auth"] == "Bearer s3cret", out)
        rc, out = run(ingest("fetch"), {**net, "SRC_URL": url("/to-other"), "GITHUB_RUN_ID": "10"})
        check("drops the token when a redirect leaves the host",
              rc == 0 and load("incoming/fetched-10.json")["auth"] is None, out)
        for name, path in (("redirect to http is refused", "/to-http"), ("HTTP 404 fails", "/missing"),
                           ("file over 50 MiB is refused", "/big"), ("non-JSON download is refused", "/notjson")):
            rc, out = run(ingest("fetch"), {**net, "SRC_URL": url(path), "GITHUB_RUN_ID": "11"})
            check(name, rc != 0, out)
        check("a refused non-JSON download leaves nothing behind", not os.path.exists("incoming/fetched-11.json"))

    print("Ingest (pr mode): two advisories in flight at once -> one PR each")
    fresh_checkout(ci)
    shutil.copy(F("va.json"), "incoming/IT/fetched-42.json")     # fetched by this run (untracked)
    gh_out = os.path.join(work, "gh_output")
    open(gh_out, "w").close()
    rc, out = step("collect", GITHUB_OUTPUT=gh_out)
    check("collect lists both feed files (not incoming/misc/) and writes count=2",
          rc == 0 and read(gh_out) == "count=2\n"
          and out.split() == ["incoming/IT/fetched-42.json", "incoming/OT/icsa.json"], out)
    rc, out = step("validate")
    check("validate passes good advisories", rc == 0, out)
    shutil.copy(F("no-title.json"), "incoming/bad.json")
    rc, out = step("validate")
    check("validate fails if any advisory is bad", rc != 0, out)
    os.remove("incoming/bad.json")
    rc, out = step("publish")
    check("publish signs and places both", rc == 0, out)
    develop_before = remote_sha("develop")
    rc, out = step("commit")
    check("commit succeeds", rc == 0, out)
    b_icsa, b_va = "csaf/icsa-00-000-01", "csaf/va-00-000-01"
    st = gh_state()
    check("one PR per advisory", sorted(p["head"] for p in st["prs"]) == [b_icsa, b_va], json.dumps(st["prs"]))
    check("develop itself is untouched in pr mode", remote_sha("develop") == develop_before)
    diff = lambda b: set(sh("git", "--git-dir", remote, "diff", "--no-renames", "--name-status", "develop", b).splitlines())
    check("ICSA PR = its 3 files + removal of its incoming/ source", diff(b_icsa) == {
        "A\tcsaf_files/OT/white/2000/icsa-00-000-01.json", "A\tcsaf_files/OT/white/2000/icsa-00-000-01.json.asc",
        "A\tcsaf_files/OT/white/2000/icsa-00-000-01.json.sha512", "D\tincoming/OT/icsa.json"}, str(diff(b_icsa)))
    check("VA PR = only its 3 files (fetched file was never committed)", diff(b_va) == {
        "A\tcsaf_files/IT/white/2000/va-00-000-01.json", "A\tcsaf_files/IT/white/2000/va-00-000-01.json.asc",
        "A\tcsaf_files/IT/white/2000/va-00-000-01.json.sha512"}, str(diff(b_va)))
    check("unprocessed incoming/misc/stray.json is not deleted anywhere",
          all("incoming/misc/stray.json" in remote_files(r) for r in ("develop", b_icsa, b_va)))

    print("Check-pr: the required PR check")
    fresh_checkout(ci)
    for b in (b_icsa, b_va):
        git("fetch", "-q", "origin", b, cwd=ci)
        git("checkout", "-q", "FETCH_HEAD", cwd=ci)
        rc, out = step("check-pr", BASE_REF="origin/develop")
        check(f"{b} passes check-pr", rc == 0, out)
    git("checkout", "-q", "-b", "edits-index", cwd=ci)
    os.makedirs("csaf_files/OT/white", exist_ok=True)
    with open("csaf_files/OT/white/index.txt", "w") as f:
        f.write("2000/icsa-00-000-01.json\n")
    git("add", "-A", "csaf_files", cwd=ci)
    git("commit", "-q", "-m", "hand-edit index", cwd=ci)
    rc, out = step("check-pr", BASE_REF="origin/develop")
    check("a PR that edits a generated feed file fails", rc != 0 and "generated after merge" in out, out)
    git("reset", "-q", "--hard", "HEAD~1", cwd=ci)
    with open("csaf_files/IT/white/index.txt", "w") as f:
        f.write("2000/va-00-000-01.json\n")
    git("add", "-A", "csaf_files", cwd=ci)
    git("commit", "-qm", "pretend develop has a feed index", cwd=ci)
    git("push", "-q", "origin", "HEAD:refs/heads/with-index", cwd=ci)
    git("fetch", "-q", "origin", "+refs/heads/with-index:refs/remotes/origin/with-index", cwd=ci)
    git("rm", "-q", "csaf_files/IT/white/index.txt", cwd=ci)
    git("commit", "-qm", "delete index only", cwd=ci)
    rc, out = step("check-pr", BASE_REF="origin/with-index")
    check("deleting a feed file while its advisories remain fails", rc != 0 and "generated after merge" in out, out)
    git("rm", "-rq", "csaf_files/IT", cwd=ci)
    git("commit", "-qm", "withdraw every IT advisory", cwd=ci)
    rc, out = step("check-pr", BASE_REF="origin/with-index")
    check("deleting a feed's files together with all its advisories passes", rc == 0, out)
    git("reset", "-q", "--hard", "HEAD~3", cwd=ci)
    with open("csaf_files/IT/white/2000/va-00-000-01.json.sha512", "w") as f:
        f.write("0" * 128 + "  va-00-000-01.json")
    git("commit", "-qam", "tamper", cwd=ci)
    rc, out = step("check-pr", BASE_REF="origin/develop")
    check("a PR with a wrong .sha512 fails", rc != 0 and ".sha512 does not match" in out, out)
    git("reset", "-q", "--hard", "HEAD~1", cwd=ci)
    save(advisory("ICSA-00-000-09", title=""), "csaf_files/OT/white/2000/icsa-00-000-09.json")
    git("add", "-A", "csaf_files", cwd=ci)
    git("commit", "-qm", "invalid advisory", cwd=ci)
    rc, out = step("check-pr", BASE_REF="origin/develop")
    check("a PR with an invalid advisory fails", rc != 0, out)

    print("Ingest (pr mode): re-runs and revisions while PRs are open")
    fresh_checkout(ci)                       # next run: develop still has incoming/OT/icsa.json
    shas = (remote_sha(b_icsa), remote_sha(b_va))
    rc, out = step("publish")
    rc2, out2 = step("commit")
    check("re-run while the PR is open leaves it alone (no re-sign, no new PR)",
          rc == rc2 == 0 and remote_sha(b_icsa) == shas[0] and len(gh_state()["prs"]) == 2
          and "already waiting in PR #" in out2, out + out2)
    fresh_checkout(ci)
    shutil.copy(F("va-v2.json"), "incoming/IT/fetched-43.json")
    step("publish")
    rc, out = step("commit")
    check("newer revision updates the same branch and PR",
          rc == 0 and remote_sha(b_va) != shas[1] and len(gh_state()["prs"]) == 2 and "updated PR #" in out, out)

    print("Merge in any order, then the feed rebuild")
    fresh_checkout(other)
    for b in (b_va, b_icsa):                 # opposite order to how they were opened
        git("fetch", "-q", "origin", b, cwd=other)
        rc, out = run(["git", "merge", "-q", "--no-ff", "-m", f"Merge {b}", "FETCH_HEAD"], cwd=other)
        check(f"{b} merges without conflicts", rc == 0, out)
    git("push", "-q", "origin", "develop", cwd=other)
    st = gh_state()
    for p in st["prs"]:
        p["state"] = "closed"
    json.dump(st, open(state_file, "w"))
    check("incoming/OT/icsa.json is gone from develop after merge", "incoming/OT/icsa.json" not in remote_files("develop"))

    fresh_checkout(ci)
    rc, out = step("feeds")
    files = remote_files("develop")
    check("feeds builds and pushes index/changes/ROLIE/CHANGELOG for both feeds", rc == 0 and {
        "csaf_files/OT/white/index.txt", "csaf_files/OT/white/changes.csv", "csaf_files/OT/white/CHANGELOG.md",
        "csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json", "csaf_files/IT/white/index.txt",
        "csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"} <= files, out)
    head = remote_sha("develop")
    fresh_checkout(ci)
    rc, out = step("feeds")
    check("feeds again with nothing new: no commit", rc == 0 and remote_sha("develop") == head
          and "already up to date" in out, out)

    print("Feeds race: develop moves while a rebuild is running")
    def merge_advisory(id_, ts):
        """Someone merges an advisory PR to develop (from the `other` clone)."""
        fresh_checkout(other)
        save(advisory(id_, ts=ts), "incoming/OT/x.json")
        rc, out = run([sys.executable, "scripts/publish_csaf.py", "OT", "incoming/OT/x.json"])
        assert rc == 0, out
        os.remove("incoming/OT/x.json")
        git("add", "-A", "csaf_files", cwd=other)
        git("commit", "-qm", f"merge {id_}", cwd=other)
        git("push", "-q", "origin", "develop", cwd=other)
    merge_advisory("ICSA-00-000-05", "2026-02-01T00:00:00.000Z")
    fresh_checkout(ci)                       # the rebuild for that merge checks out develop ...
    merge_advisory("ICSA-00-000-06", "2026-02-02T00:00:00.000Z")   # ... and another merge lands
    os.chdir(ci)
    rc, out = step("feeds")
    idx = sh("git", "--git-dir", remote, "show", "develop:csaf_files/OT/white/index.txt").splitlines()
    check("rebuild retries on the new develop and includes both advisories",
          rc == 0 and "retrying" in out and {"2026/icsa-00-000-05.json", "2026/icsa-00-000-06.json"} <= set(idx),
          out + "\n".join(idx))

    print("Ingest: a file left in incoming/ after it was already published")
    fresh_checkout(other)
    shutil.copy(F("va-v2.json"), "incoming/IT/left.json")
    git("add", "-A", "incoming", cwd=other)
    git("commit", "-qm", "leftover", cwd=other)
    git("push", "-q", "origin", "develop", cwd=other)
    fresh_checkout(ci)
    rc, out = step("publish")
    check("publish treats it as unchanged instead of failing the run", rc == 0 and "identical content" in out, out)
    rc, out = step("commit")
    check("commit opens a PR that only removes the leftover file",
          rc == 0 and diff(b_va) == {"D\tincoming/IT/left.json"} and gh_state()["prs"][-1]["head"] == b_va
          and gh_state()["prs"][-1]["state"] == "open", out + str(diff(b_va)))

    print("Ingest (push mode)")
    fresh_checkout(ci)
    shutil.copy(F("icsa2.json"), "incoming/fetched-50.json")
    step("publish")
    fresh_checkout(other)                    # someone else pushes to develop first
    with open("note.txt", "w") as f:
        f.write("unrelated\n")
    git("add", "note.txt", cwd=other)
    git("commit", "-qm", "unrelated", cwd=other)
    git("push", "-q", "origin", "develop", cwd=other)
    os.chdir(ci)
    rc, out = step("commit", PUBLISH_MODE="push")
    files = remote_files("develop")
    check("push mode rebases onto the moved develop and pushes",
          rc == 0 and "csaf_files/OT/white/2000/icsa-00-000-02.json" in files and "note.txt" in files, out)
    check("push mode dispatches csaf-feeds.yml",
          any(d["endpoint"].endswith("/csaf-feeds.yml/dispatches") and d["ref"] == "develop"
              for d in gh_state()["dispatches"]), json.dumps(gh_state()["dispatches"]))
    rc, out = step("commit", PUBLISH_MODE="sideways")
    check("unknown PUBLISH_MODE fails", rc != 0, out)
    rc, out = step("bogus")
    check("unknown subcommand fails", rc != 0, out)


def main():
    for t in ("gpg", "node", "git"):
        if shutil.which(t) is None:
            sys.exit(f"missing: {t}")
    if not os.path.isdir(os.path.join(REPO, "node_modules/@secvisogram/csaf-validator-lib")):
        sys.exit("run 'npm ci' first")

    with tempfile.TemporaryDirectory() as work:
        gnupg = os.path.join(work, "gnupg")
        os.mkdir(gnupg, 0o700)
        os.environ["GNUPGHOME"] = gnupg
        subprocess.run(["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-gen-key",
                        "CSAF test <test@example.invalid>", "rsa2048", "sign", "never"],
                       stderr=subprocess.DEVNULL, check=True)
        for k in ("CSAF_ROOT", "RAW_BASE", "CSAF_MANIFEST", "WRITE_CHANGELOG", "PUBLISH_MODE", "GITHUB_OUTPUT"):
            os.environ.pop(k, None)
        raw_base = "https://example.invalid/csaf_files"

        # Synthetic fixtures. initial_release_date year 2000 -> <feed>/white/2000/.
        fx = os.path.join(work, "fx")
        os.mkdir(fx)
        F = lambda name: os.path.join(fx, name)
        t0 = "2000-01-02T00:00:00.000Z"
        va = advisory("VA-00-000-01", ts=t0)
        va["document"]["tracking"]["current_release_date"] = "2026-01-02T00:00:00.000Z"
        va["document"]["tracking"]["revision_history"][0]["date"] = "2026-01-02T00:00:00.000Z"
        save(va, F("va.json"))
        save(revise(va, "2026-01-03T00:00:00.000Z", "2"), F("va-v2.json"))
        same = copy.deepcopy(va)
        same["document"]["title"] = "Same date, different content"
        save(same, F("va-same-date.json"))
        icsa = advisory("ICSA-00-000-01", ts=t0)
        icsa["document"]["tracking"]["current_release_date"] = "2026-01-04T23:00:00.000Z"
        icsa["document"]["tracking"]["revision_history"][0]["date"] = "2026-01-04T23:00:00.000Z"
        save(icsa, F("icsa.json"))
        # Sorts AFTER icsa as text but is EARLIER in real time:
        # 2026-01-05T00:00+05:00 == 2026-01-04T19:00Z, before icsa's 2026-01-04T23:00Z.
        icsa2 = advisory("ICSA-00-000-02", ts=t0)
        icsa2["document"]["tracking"]["current_release_date"] = "2026-01-05T00:00:00+05:00"
        icsa2["document"]["tracking"]["revision_history"][0]["date"] = "2026-01-05T00:00:00+05:00"
        save(icsa2, F("icsa2.json"))
        bad = copy.deepcopy(va)
        bad["document"].pop("title")
        save(bad, F("no-title.json"))
        bad = copy.deepcopy(va)
        bad["vulnerabilities"][0]["product_status"]["known_affected"].append("CSAFPID-NOPE")
        save(bad, F("bad-pid.json"))
        for name, change in (("va-badid.json", {"id": "VA-ABC"}), ("va-auto.json", {"id": "VA-00-000-99"}),
                             ("va-vafeed.json", {"id": "VA-00-000-03"}),
                             ("unknown-auto.json", {"id": "TEST-00-000-99"}),
                             ("va-draft.json", {"id": "VA-00-000-06", "status": "draft"})):
            d = copy.deepcopy(va)
            d["document"]["tracking"].update(change)
            save(d, F(name))
        d = copy.deepcopy(va)
        d["document"]["tracking"]["id"] = "VA-00-000-05"
        d["document"]["distribution"]["tlp"]["label"] = "AMBER"
        save(d, F("va-amber.json"))
        with open(F("garbage.json"), "w") as f:
            f.write("not json")

        test_scripts(work, F, raw_base)
        test_ingest(work, F, raw_base)
        os.chdir(REPO)

    print()
    print(f"{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
