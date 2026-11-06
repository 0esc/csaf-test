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

        os.chdir(REPO)

    print()
    print(f"{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
