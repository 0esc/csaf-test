#!/usr/bin/env python3
"""test_publish.py: end-to-end tests for validate_csaf.mjs and publish_csaf.py.

Fully local: works on a throwaway copy of the repo with a throwaway GPG key
in a temp GNUPGHOME. It never touches your real keyring, your csaf_files/,
the network or any external host. Needs: python3 (3.11+), gpg, node, and
`npm ci` run once in the repo.

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


def ok(name):
    global passed
    print(f"  PASS  {name}")
    passed += 1


def bad(name, detail=""):
    global failed
    print(f"  FAIL  {name}")
    for line in detail.splitlines():
        print(f"        {line}")
    failed += 1


def check(name, cond, detail=""):
    ok(name) if cond else bad(name, detail)


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def expect_ok(name, cmd):
    rc, out = run(cmd)
    check(name, rc == 0, out)


def expect_fail(name, cmd):
    rc, out = run(cmd)
    if rc == 0:
        bad(f"{name} (should have failed)", out)
    else:
        ok(name)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(doc, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_env(cmd, extra):
    e = dict(os.environ, **extra)
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=e)
    return p.returncode, p.stdout


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


def test_ingest(work, F):
    """The workflow steps in scripts/ingest.py, on a fresh copy of the repo
    that is a git repo with a local bare remote standing in for GitHub."""
    repo = os.path.join(work, "ingest-repo")
    remote = os.path.join(work, "remote.git")
    os.makedirs(repo)
    for d in ("scripts", "csaf_files", "incoming"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(repo, d))
    os.symlink(os.path.join(REPO, "node_modules"), os.path.join(repo, "node_modules"))
    os.chdir(repo)
    for f in glob.glob("incoming/**/*.json", recursive=True):   # start from an empty incoming/
        os.remove(f)
    quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["git", "init", "-q", "--bare", "-b", "develop", remote], **quiet)
    for cmd in (["init", "-q", "-b", "develop"], ["config", "user.name", "t"], ["config", "user.email", "t@x.invalid"],
                ["add", "-A"], ["commit", "-q", "-m", "base"], ["remote", "add", "origin", remote],
                ["push", "-q", "origin", "develop"]):
        subprocess.run(["git", *cmd], **quiet)
    ingest = lambda cmd: [sys.executable, "scripts/ingest.py", cmd]

    print("Ingest: fetch (local HTTPS server, no network)")
    base = {"COORDINATOR_HOST": "localhost", "GITHUB_RUN_ID": "1", "FEED": "auto"}
    for name, extra in (
        ("http URL is refused", {"SRC_URL": "http://localhost/ok.json"}),
        ("host other than COORDINATOR_HOST is refused", {"SRC_URL": "https://evil.example/ok.json"}),
        ("look-alike host is refused", {"SRC_URL": "https://localhost.evil.example/ok.json"}),
        ("unset COORDINATOR_HOST is refused", {"SRC_URL": "https://localhost/ok.json", "COORDINATOR_HOST": ""}),
        ("unknown feed is refused", {"SRC_URL": "https://localhost/ok.json", "FEED": "XX"}),
    ):
        rc, out = run_env(ingest("fetch"), {**base, **extra})
        check(name, rc != 0, out)

    server = start_https_server(work)
    if server is None:
        print("  SKIP  download tests (openssl not installed)")
    else:
        port, ca = server
        url = lambda path, host="localhost": f"https://{host}:{port}{path}"
        net = {**base, "SSL_CERT_FILE": ca, "NO_PROXY": "*", "no_proxy": "*", "COORDINATOR_TOKEN": "s3cret"}
        rc, out = run_env(ingest("fetch"), {**net, "SRC_URL": url("/ok.json"), "FEED": "ot", "GITHUB_RUN_ID": "7"})
        check("downloads into incoming/OT/fetched-<run id>.json",
              rc == 0 and os.path.isfile("incoming/OT/fetched-7.json"), out)
        rc, out = run_env(ingest("fetch"), {**net, "SRC_URL": url("/auth.json"), "GITHUB_RUN_ID": "8"})
        check("sends the coordinator token",
              rc == 0 and load("incoming/fetched-8.json")["auth"] == "Bearer s3cret", out)
        rc, out = run_env(ingest("fetch"), {**net, "SRC_URL": url("/to-same"), "GITHUB_RUN_ID": "9"})
        check("follows https redirect on the same host, keeping the token",
              rc == 0 and load("incoming/fetched-9.json")["auth"] == "Bearer s3cret", out)
        rc, out = run_env(ingest("fetch"), {**net, "SRC_URL": url("/to-other"), "GITHUB_RUN_ID": "10"})
        check("drops the token when a redirect leaves the host",
              rc == 0 and load("incoming/fetched-10.json")["auth"] is None, out)
        for name, path in (("redirect to http is refused", "/to-http"), ("HTTP 404 fails", "/missing"),
                           ("file over 50 MiB is refused", "/big"), ("non-JSON download is refused", "/notjson")):
            rc, out = run_env(ingest("fetch"), {**net, "SRC_URL": url(path)})
            check(name, rc != 0, out)
        for f in glob.glob("incoming/**/*.json", recursive=True):
            os.remove(f)

    print("Ingest: collect -> validate -> publish -> commit")
    gh_out = os.path.join(work, "gh_output")
    open(gh_out, "w").close()
    rc, out = run_env(ingest("collect"), {"GITHUB_OUTPUT": gh_out})
    check("collect with nothing waiting writes count=0", rc == 0 and read(gh_out) == "count=0\n", out)
    rc, out = run_env(ingest("validate"), {})
    check("validate with nothing waiting succeeds", rc == 0, out)

    os.makedirs("incoming/IT", exist_ok=True)
    shutil.copy(F("va.json"), "incoming/IT/va.json")
    shutil.copy(F("icsa.json"), "incoming/icsa.json")
    open(gh_out, "w").close()
    rc, out = run_env(ingest("collect"), {"GITHUB_OUTPUT": gh_out})
    check("collect lists both files and writes count=2",
          rc == 0 and read(gh_out) == "count=2\n" and out.split() == ["incoming/icsa.json", "incoming/IT/va.json"], out)
    rc, out = run_env(ingest("validate"), {})
    check("validate passes good advisories", rc == 0, out)
    shutil.copy(F("no-title.json"), "incoming/OT-bad.json")
    rc, out = run_env(ingest("validate"), {})
    check("validate fails if any advisory is bad", rc != 0, out)
    os.remove("incoming/OT-bad.json")

    rc, out = run_env(ingest("publish"), {"RAW_BASE": "https://example.invalid/csaf_files"})
    check("publish places both advisories",
          rc == 0 and os.path.isfile("csaf_files/IT/white/2026/va-26-309-91.json")
          and os.path.isfile("csaf_files/OT/white/2026/icsa-26-309-02.json"), out)

    gh = {"PUBLISH_MODE": "push", "BASE_BRANCH": "develop", "GITHUB_SERVER_URL": "https://github.example",
          "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "42"}
    rc, out = run_env(ingest("commit"), gh)
    log = subprocess.run(["git", "--git-dir", remote, "log", "-1", "--format=%s%n%b", "develop"],
                         stdout=subprocess.PIPE, text=True).stdout
    check("commit pushes to develop (push mode)", rc == 0 and log.startswith("Publish CSAF: "), out + log)
    check("commit message lists both ids", "ICSA-26-309-02" in log and "VA-26-309-91" in log, log)
    check("commit message links the run", "https://github.example/o/r/actions/runs/42" in log, log)
    check("incoming/ is emptied", not glob.glob("incoming/**/*.json", recursive=True))
    files = subprocess.run(["git", "--git-dir", remote, "ls-tree", "-r", "--name-only", "develop"],
                           stdout=subprocess.PIPE, text=True).stdout.splitlines()
    check("pushed tree has the advisory, .asc and .sha512, and no incoming JSON",
          {"csaf_files/IT/white/2026/va-26-309-91.json", "csaf_files/IT/white/2026/va-26-309-91.json.asc",
           "csaf_files/IT/white/2026/va-26-309-91.json.sha512"} <= set(files)
          and not any(f.startswith("incoming/") and f.endswith(".json") for f in files))
    rc, out = run_env(ingest("commit"), gh)
    check("commit with nothing new says 'No changes.'", rc == 0 and "No changes." in out, out)
    rc, out = run_env(ingest("bogus"), {})
    check("unknown subcommand fails", rc != 0, out)


def main():
    for t in ("gpg", "node"):
        if shutil.which(t) is None:
            sys.exit(f"missing: {t}")
    if not os.path.isdir(os.path.join(REPO, "node_modules/@secvisogram/csaf-validator-lib")):
        sys.exit("run 'npm ci' first")

    with tempfile.TemporaryDirectory() as work:
        # ---- sandbox: copy of the repo + throwaway signing key ---------------
        repo = os.path.join(work, "repo")
        os.makedirs(repo)
        shutil.copytree(os.path.join(REPO, "scripts"), os.path.join(repo, "scripts"))
        shutil.copytree(os.path.join(REPO, "csaf_files"), os.path.join(repo, "csaf_files"))
        os.symlink(os.path.join(REPO, "node_modules"), os.path.join(repo, "node_modules"))
        shutil.copy(os.path.join(REPO, "package.json"), repo)
        gnupg = os.path.join(work, "gnupg")
        os.mkdir(gnupg, 0o700)
        os.environ["GNUPGHOME"] = gnupg
        subprocess.run(["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-gen-key",
                        "CSAF test <test@example.invalid>", "rsa2048", "sign", "never"],
                       stderr=subprocess.DEVNULL, check=True)
        raw_base = os.environ["RAW_BASE"] = "https://example.invalid/csaf_files"
        os.chdir(repo)
        validate = lambda *files: ["node", "scripts/validate_csaf.mjs", *files]
        publish = lambda feed, *files: [sys.executable, "scripts/publish_csaf.py", feed, *files]

        # ---- fixtures: built from the published OT advisory ------------------
        # The CWE-78 name is set to the current catalogue name (see CSAF-AUTOMATION.md "Known issues").
        # Test VA ids use 9x numbers so they never collide with real advisories in csaf_files/.
        sample = load("csaf_files/OT/white/2026/icsa-26-302-03.json")
        for v in sample.get("vulnerabilities") or []:
            cwe = v.get("cwe")
            if isinstance(cwe, dict) and cwe.get("id") == "CWE-78":
                cwe["name"] = "Improper Neutralization of Special Elements used in an OS Command"
        fx = os.path.join(work, "fx")
        os.mkdir(fx)
        F = lambda name: os.path.join(fx, name)

        def mk(name, edit, base=sample):
            doc = copy.deepcopy(base)
            edit(doc)
            save(doc, F(name))
            return doc

        def tracking(doc):
            return doc["document"]["tracking"]

        ts = "2026-11-05T12:00:00.000Z"

        def va_edit(d):
            tr = tracking(d)
            d["document"]["title"] = "Test VA advisory"
            tr.update(id="VA-26-309-91", initial_release_date=ts, current_release_date=ts)
            tr["revision_history"][-1]["date"] = ts
        va = mk("va.json", va_edit)

        def v3_edit(d):
            tr = tracking(d)
            tr.update(current_release_date="2026-11-06T12:00:00.000Z", version="3")
            tr["revision_history"].append({"date": "2026-11-06T12:00:00.000Z", "number": "3", "summary": "Test update"})
        mk("va-v3.json", v3_edit, va)

        def icsa_edit(d):
            tr = tracking(d)
            tr.update(id="ICSA-26-309-02", current_release_date="2026-11-07T00:00:00.000Z", version="3")
            tr["revision_history"].append({"date": "2026-11-07T00:00:00.000Z", "number": "3", "summary": "x"})
        mk("icsa.json", icsa_edit)
        mk("no-title.json", lambda d: d["document"].pop("title", None))

        def bad_pid(d):
            ps = d["vulnerabilities"][0].setdefault("product_status", {})
            ps["known_affected"] = (ps.get("known_affected") or []) + ["CSAFPID-NOPE"]
        mk("bad-pid.json", bad_pid)
        mk("va-badid.json", lambda d: tracking(d).update(id="VA-ABC"), va)
        mk("va-auto.json", lambda d: tracking(d).update(id="VA-26-309-99"), va)
        mk("va-vafeed.json", lambda d: tracking(d).update(id="VA-26-309-93"), va)

        def amber(d):
            tracking(d)["id"] = "VA-26-309-95"
            d["document"]["distribution"]["tlp"]["label"] = "AMBER"
        mk("va-amber.json", amber, va)
        mk("va-draft.json", lambda d: tracking(d).update(id="VA-26-309-96", status="draft"), va)
        with open(F("garbage.json"), "w") as f:
            f.write("not json")

        print("Validation (schema + mandatory tests, offline)")
        expect_ok("valid VA advisory passes", validate(F("va.json")))
        expect_ok("valid ICSA advisory passes", validate(F("icsa.json")))
        expect_fail("missing /document/title is rejected", validate(F("no-title.json")))
        expect_fail("undefined product id is rejected", validate(F("bad-pid.json")))
        expect_fail("non-JSON file is rejected", validate(F("garbage.json")))

        print("Publish: VA advisory into IT/white")
        expect_ok("VA-26-309-91 publishes to IT", publish("IT", F("va.json")))
        d = "csaf_files/IT/white"
        adv = f"{d}/2026/va-26-309-91.json"
        rolie_it = f"{d}/cisa-csaf-it-feed-tlp-white.json"
        for name in ("2026/va-26-309-91.json", "2026/va-26-309-91.json.asc", "2026/va-26-309-91.json.sha512",
                     "index.txt", "changes.csv", "CHANGELOG.md", "cisa-csaf-it-feed-tlp-white.json"):
            check(f"created IT/white/{name}" if os.path.isfile(f"{d}/{name}") else f"missing IT/white/{name}",
                  os.path.isfile(f"{d}/{name}"))
        expect_ok("signature verifies", ["gpg", "--batch", "--verify", adv + ".asc", adv])
        with open(adv, "rb") as f:
            digest = hashlib.sha512(f.read()).hexdigest()
        check(".sha512 matches file", read(adv + ".sha512") == f"{digest}  va-26-309-91.json")
        check("index.txt lists it", "2026/va-26-309-91.json" in read(f"{d}/index.txt").splitlines())
        changes = read(f"{d}/changes.csv")
        check("changes.csv row (IT style: unquoted)",
              f"2026/va-26-309-91.json,{ts}" in changes.splitlines(), changes)
        entry = next((e for e in load(rolie_it)["feed"]["entry"] if e["id"] == "VA-26-309-91"), None)
        check("ROLIE entry added", entry is not None)
        check("ROLIE link uses RAW_BASE",
              entry is not None and entry["content"]["src"] == f"{raw_base}/IT/white/2026/va-26-309-91.json")
        expect_ok("published file still validates", validate(adv))

        print("Publish: revisions and guards")
        expect_fail("same revision is not overwritten", publish("IT", F("va.json")))
        expect_ok("newer revision replaces it", publish("IT", F("va-v3.json")))
        check("changes.csv keeps one row per advisory", read(f"{d}/changes.csv").count("va-26-309-91") == 1)
        check("ROLIE keeps one entry",
              sum(e["id"] == "VA-26-309-91" for e in load(rolie_it)["feed"]["entry"]) == 1)
        check("CHANGELOG.md has one row per version",
              sum("VA-26-309-91" in l for l in read(f"{d}/CHANGELOG.md").splitlines()) == 2)
        expect_fail("malformed VA id is refused", publish("IT", F("va-badid.json")))
        expect_fail("VA id with feed=auto is refused", publish("auto", F("va-auto.json")))
        expect_fail("TLP:AMBER is refused", publish("IT", F("va-amber.json")))
        expect_fail("draft status is refused", publish("IT", F("va-draft.json")))
        expect_ok("VA advisory publishes to VA feed", publish("VA", F("va-vafeed.json")))
        check("VA/white file placed", os.path.isfile("csaf_files/VA/white/2026/va-26-309-93.json"))
        check("VA changes.csv row (quoted)",
              f'"2026/va-26-309-93.json","{ts}"' in read("csaf_files/VA/white/changes.csv").splitlines())

        print("Publish: OT feed auto-detection")
        expect_ok("ICSA id auto-routes to OT", publish("auto", F("icsa.json")))
        check("OT index.txt updated",
              read("csaf_files/OT/white/index.txt").splitlines()[0] == "2026/icsa-26-309-02.json")
        check("OT changes.csv newest first, quoted",
              read("csaf_files/OT/white/changes.csv").startswith('"2026/icsa-26-309-02.json",'))

        test_ingest(work, F)
        os.chdir(REPO)

    print()
    print(f"{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
