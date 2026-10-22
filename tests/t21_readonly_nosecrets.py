#!/usr/bin/env python3
"""T-21 -- read-only by construction, and no leaked credentials. E1 Task 1.8, AC1.

WHAT THE CONOPS CLAIMS
----------------------
§6's ARB justification principles include "read-only by construction"
and "token-misuse reduction". Both are asserted in the document and
neither has evidence. T-21 is the two measurements that would support
them:

  A. A write attempted against the shared surface fails.
  B. No credential content is present in anything that would ship.

WHY HALF A IS NOT THE TEST IT LOOKS LIKE
----------------------------------------
"The write failed" is §12.9's silent negative wearing a different hat.
The Delta Sharing open protocol, as published, defines **no mutation
verb at all** -- there is no PUT, no POST-to-insert, no DELETE on a
share, a schema or a table. So a 404 or a 405 on a write attempt is
exactly what an endpoint that was never asked to support writes
returns, and exactly what an endpoint that refused a write would
return. From the client the two are the same observation.

That matters because "read-only by CONSTRUCTION" and "read-only by
ENFORCEMENT" are different claims with different failure modes, and §6
leans on the first while most readers will hear the second. A control
that is enforced can be misconfigured. A verb that does not exist
cannot. The honest finding is the stronger one, but only if the test
says which it measured, so this half grades into three outcomes rather
than pass/fail:

  NO_WRITE_VERB_ON_THE_SHARING_SURFACE   every mutation verb is
                                         rejected at the protocol
                                         layer, and a read on the same
                                         host with the same credential
                                         succeeds -- so the rejection
                                         is not a dead endpoint
  WRITE_VERB_PRESENT_AND_REFUSED         a mutation verb is recognised
                                         (401/403, or a 400 that
                                         complains about the BODY
                                         rather than the method) and
                                         then denied -- weaker, and the
                                         §6 wording would need changing
  WRITE_ACCEPTED                         the alarming one. A 2xx on any
                                         mutation is a finding that
                                         outranks this whole epic

The positive control is what makes any of those attributable. Before a
single mutation is attempted, this test performs a plain read through
the same credential against the same host. If the read fails, nothing
is concluded from the mutations and the verdict is CANNOT_SEE, because
a host that refuses everything tells us nothing about writes
specifically. See docs/11 §11.7 B-33b: the before-picture is what makes
a later absence attributable.

WHY HALF B SCANS FOR A SHAPE AND NOT FOR A VALUE
------------------------------------------------
Task 1.8 is explicit that the scan must look for the *shape* of a
credential rather than for a specific secret value, for two reasons:
a value-based scan stops working the moment a token is rotated, and a
value-based scan has to contain the token, which makes the test itself
the leak it is looking for. So the patterns here are structural -- a
`bearerToken` key, a `shareCredentialsVersion`/`endpoint` pairing, a
sharing host sitting next to a long opaque string -- and this file
contains no secret of any kind.

Half B also carries its own positive control, for the same reason half
A does. A scanner that is silently broken -- a bad regex, a path root
that resolves somewhere empty, an exclusion list that excludes
everything -- reports "clean", which is indistinguishable from a
repository that is actually clean. So before reporting clean, this test
writes a deliberately fake credential-shaped file into the scan root,
confirms the scanner flags it, and removes it in a `finally`. If the
synthetic is NOT flagged, the clean result is withdrawn and the verdict
is SCANNER_UNPROVEN, because at that point we know only that the
scanner found nothing, not that there was nothing to find.

RELATIONSHIP TO scripts/check_secret_hygiene.py
-----------------------------------------------
They are not the same instrument and neither replaces the other. The
hygiene script is a pre-commit gate over the working tree, and it
excludes `_secrets/` because that directory is where credentials are
SUPPOSED to live. T-21's scan asks a different question -- would a
credential leave this repository -- so it scans what git tracks plus
`evidence/`, which is the directory whose whole purpose is to be handed
to other people. A token in `_secrets/raw-credential.json` is correct.
The same token in `evidence/t20-ingress-d2o.json` is the incident §6's
"token-misuse reduction" principle exists to prevent.

OUTPUT
------
  evidence/t21-readonly-nosecrets.json   the Report rows
  evidence/t21-report.json               the full observation record
"""
import argparse
import importlib.util
import json
import random
import re
import string
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from common import Report, load_env  # noqa: E402

CONFIG = ROOT / "iac" / "config" / "recipients.yaml"
SECRETS = ROOT / "_secrets"
EVIDENCE = ROOT / "evidence" / "t21-readonly-nosecrets.json"
REPORT = ROOT / "evidence" / "t21-report.json"

# The synthetic probe file for half B's positive control. The name is
# deliberately loud: if a crash ever leaves it behind, nobody should
# spend a minute wondering whether it is real.
SYNTHETIC = ROOT / "evidence" / "_t21_synthetic_probe_DELETE_ME.json"


def load_probe(filename, modname):
    """Import a numbered script as a module. Same trick as scripts/28."""
    path = ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_test_module(filename, modname):
    path = ROOT / "tests" / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "t21_probe14")
T02 = load_test_module("t02_ip_access_list.py", "t21_t02")

redact = P14.redact
sharing_get = T02.sharing_get
scrub = T02.scrub
now = T02.now


# =====================================================================
# Choosing which credential to read through
# =====================================================================

def pick_recipient(explicit=None):
    """The recipient with the longest-lived credential and NO IP list.

    Both halves of that matter. An IP access list on the recipient would
    make every refusal ambiguous -- an allow-list denial and a
    protocol-level method rejection are the same 403-shaped event from
    here, which is the §12.9 trap this test is specifically trying not
    to fall into. And the longest-lived credential is chosen because one
    of the activated credentials expires tomorrow (docs/11 §11.7 B-34a,
    rotation inherits the birth lifetime), and a test that silently
    picks the expiring one will start failing for a reason that has
    nothing to do with what it measures.
    """
    try:
        import yaml
        cfg = yaml.safe_load(CONFIG.read_text())
    except Exception as exc:  # noqa: BLE001
        return None, {"verdict": "CANNOT_SEE",
                      "reason": f"could not read {CONFIG.name}: {exc}"}

    candidates = []
    for decl in cfg.get("recipients") or []:
        name = decl.get("name")
        mode = (decl.get("ip_access_list") or {}).get("mode")
        cred_path = SECRETS / f"credential-{name}.json"
        rec = {"recipient": name, "ip_access_list_mode": mode,
               "credential_on_disk": cred_path.exists()}
        if explicit and name != explicit:
            continue
        if not cred_path.exists():
            rec["excluded_because"] = "no activated credential on disk"
            candidates.append(rec)
            continue
        try:
            cred = json.loads(cred_path.read_text())
        except Exception as exc:  # noqa: BLE001
            rec["excluded_because"] = f"credential unparsable: {exc}"
            candidates.append(rec)
            continue
        rec["expiration_time"] = cred.get("expirationTime")
        if mode == "APPLIED" and not explicit:
            rec["excluded_because"] = (
                "an applied IP access list would make every refusal "
                "ambiguous between the network and the protocol")
            candidates.append(rec)
            continue
        rec["usable"] = True
        rec["_cred"] = cred
        candidates.append(rec)

    usable = [c for c in candidates if c.get("usable")]
    if not usable:
        return None, {"verdict": "CANNOT_SEE",
                      "reason": "no usable credential without an applied IP list",
                      "considered": [{k: v for k, v in c.items()
                                      if not k.startswith("_")}
                                     for c in candidates]}
    usable.sort(key=lambda c: c.get("expiration_time") or "", reverse=True)
    chosen = usable[0]
    return chosen, {"considered": [{k: v for k, v in c.items()
                                    if not k.startswith("_")}
                                   for c in candidates],
                    "chosen": chosen["recipient"],
                    "chosen_because": "longest-lived credential with no applied IP list"}


# =====================================================================
# HALF A -- read-only by construction
# =====================================================================

# Each attempt is (verb, path-template, body, what a 2xx would mean).
# The paths are the real objects the recipient can see, because a
# mutation against a path that does not exist proves nothing: a 404 for
# "no such share" and a 404 for "no such method" are the same code.
MUTATIONS = [
    ("POST",   "/shares", {"name": "awoz1227-t21-should-never-exist"},
     "a recipient can create a share on the provider's metastore"),
    ("DELETE", "/shares/{share}", None,
     "a recipient can delete the share it was granted"),
    ("PUT",    "/shares/{share}", {"comment": "awoz1227-t21 write probe"},
     "a recipient can rewrite the share object"),
    ("PATCH",  "/shares/{share}", {"comment": "awoz1227-t21 write probe"},
     "a recipient can amend the share object"),
    ("POST",   "/shares/{share}/schemas/{schema}/tables", {"name": "t21_probe"},
     "a recipient can add a table to the shared schema"),
    ("DELETE", "/shares/{share}/schemas/{schema}/tables/{table}", None,
     "a recipient can remove a table from the share"),
    ("PUT",    "/shares/{share}/schemas/{schema}/tables/{table}/metadata",
     {"comment": "awoz1227-t21 write probe"},
     "a recipient can rewrite the shared table's metadata"),
]

# A 2xx is the alarming outcome. Everything else has to be sorted into
# "the method is not part of this surface" versus "the method exists and
# was denied", and the HTTP code alone does not settle it -- which is
# the whole reason for the body inspection below.
METHOD_ABSENT_CODES = {404, 405, 501}
AUTH_REFUSAL_CODES = {401, 403}

# A 400 is genuinely ambiguous. "Malformed JSON" means the verb was
# parsed and the request got as far as the body, which is evidence the
# verb EXISTS. "Unsupported method" in a 400 means the opposite. So the
# body is read for which, and when it says neither, the attempt is
# recorded UNCLASSIFIED rather than being guessed into a bucket -- B-20,
# a verdict vocabulary too coarse to name the cause fails toward blaming
# the nearest thing.
VERB_RECOGNISED_HINTS = re.compile(
    r"malformed|invalid.{0,20}(json|body|payload|request)|"
    r"missing.{0,20}(field|parameter)|required|deserializ",
    re.IGNORECASE)
VERB_UNKNOWN_HINTS = re.compile(
    r"not.{0,10}(supported|implemented|allowed|found)|"
    r"unsupported|no.{0,10}(such|route|handler)|method",
    re.IGNORECASE)


def classify_mutation(status, body):
    if 200 <= status < 300:
        return "WRITE_ACCEPTED"
    if status == 0:
        return "CANNOT_SEE_LOCAL_NETWORK_ERROR"
    if status in METHOD_ABSENT_CODES:
        return "METHOD_ABSENT"
    if status in AUTH_REFUSAL_CODES:
        return "REFUSED_BY_AUTHZ"
    if status == 400:
        if VERB_UNKNOWN_HINTS.search(body or ""):
            return "METHOD_ABSENT"
        if VERB_RECOGNISED_HINTS.search(body or ""):
            return "VERB_RECOGNISED_BODY_REJECTED"
        return "UNCLASSIFIED_400"
    return f"UNCLASSIFIED_HTTP_{status}"


def discover_readable_target(endpoint, bearer):
    """Walk the recipient's OWN grants down to a readable table.

    B-40, and this function is the fix for it. The first version of this
    test took the share, schema and table from command-line defaults and
    mutated whatever they named. The recipient the credential selector
    chose was granted a DIFFERENT share, so all seven mutations went to
    a share the recipient cannot see, every one returned 404, and 404
    was classified METHOD_ABSENT -- so T-21a reported
    NO_WRITE_VERB_ON_THE_SHARING_SURFACE on the strength of seven
    "no such share for you" responses. The test passed without touching
    the mechanism it names.

    The old control did not catch it because `read_as_recipient` grades
    `/shares` answering as DISCOVERY_ONLY, and DISCOVERY_ONLY was
    accepted. But `/shares` answering says nothing about the path being
    mutated. A control has to be the SAME PATH, not the same host.

    So the target is discovered rather than declared: list the shares
    the recipient actually holds, descend to a schema and a table, and
    confirm with a GET on the exact object. Only then is a 404 on a
    mutation at that path attributable to the VERB, because the GET
    proves the NOUN resolves.
    """
    out = {"steps": {}}

    st, raw = sharing_get(endpoint, bearer, "/shares")
    out["steps"]["shares"] = {"status": st}
    if st != 200:
        out["verdict"] = "CANNOT_SEE_NO_SHARES"
        return out
    try:
        shares = [s.get("name") for s in (json.loads(raw).get("items") or [])]
    except Exception as exc:  # noqa: BLE001
        out["verdict"] = "CANNOT_SEE_SHARES_UNPARSABLE"
        out["error"] = str(exc)
        return out
    out["steps"]["shares"]["granted"] = shares
    if not shares:
        out["verdict"] = "CANNOT_SEE_NO_GRANTS"
        return out

    for share in shares:
        st, raw = sharing_get(endpoint, bearer, f"/shares/{share}/schemas")
        if st != 200:
            continue
        try:
            schemas = [s.get("name")
                       for s in (json.loads(raw).get("items") or [])]
        except Exception:  # noqa: BLE001
            continue
        for schema in schemas:
            st, raw = sharing_get(
                endpoint, bearer, f"/shares/{share}/schemas/{schema}/tables")
            if st != 200:
                continue
            try:
                tables = [t.get("name")
                          for t in (json.loads(raw).get("items") or [])]
            except Exception:  # noqa: BLE001
                continue
            for table in tables:
                path = (f"/shares/{share}/schemas/{schema}/tables/"
                        f"{table}/metadata")
                m_st, _ = sharing_get(endpoint, bearer, path)
                out["steps"]["object_get"] = {"path": path, "status": m_st}
                if m_st == 200:
                    out.update({"verdict": "TARGET_READABLE",
                                "share": share, "schema": schema,
                                "table": table,
                                "control_path": path})
                    return out
    out["verdict"] = "CANNOT_SEE_NO_READABLE_OBJECT"
    return out


def half_a(endpoint, bearer, share=None, schema=None, table=None):
    res = {"half": "A -- read-only by construction", "run_at": now()}

    # The positive control FIRST, and it must be the SAME PATH the
    # mutations will target -- not merely the same host. See
    # discover_readable_target's docstring for what accepting a
    # same-host control cost on the first run.
    target = discover_readable_target(endpoint, bearer)
    res["target_discovery"] = target
    if target.get("verdict") != "TARGET_READABLE":
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"no object this recipient can read was found "
            f"({target.get('verdict')}), so a 404 on a mutation would be "
            f"indistinguishable from a 404 on a path the recipient has no "
            f"grant for. Nothing was attempted.")
        res["attempts"] = []
        return res

    # Operator overrides are honoured, but only when they name something
    # the recipient can actually read -- otherwise the override would
    # reintroduce exactly the defect above.
    if share and share != target["share"]:
        st, _ = sharing_get(
            endpoint, bearer,
            f"/shares/{share}/schemas/{schema}/tables/{table}/metadata")
        res["override_requested"] = {"share": share, "schema": schema,
                                     "table": table, "object_get_status": st}
        if st != 200:
            res["override_rejected_because"] = (
                f"--share/--schema/--table named an object this recipient "
                f"cannot read (HTTP {st}). Falling back to the discovered "
                f"target, because mutating an unreadable path is how "
                f"T-21a passed for the wrong reason on 2026-10-21.")
        else:
            target = dict(target, share=share, schema=schema, table=table)

    share, schema, table = target["share"], target["schema"], target["table"]
    res.update({"share": share, "schema": schema, "table": table,
                "control_path": target.get("control_path"),
                "control_status": (target.get("steps", {})
                                   .get("object_get", {}).get("status"))})

    attempts = []
    for verb, template, body, what_2xx_means in MUTATIONS:
        path = template.format(share=share, schema=schema, table=table)
        status, raw = sharing_get(endpoint, bearer, path, method=verb, body=body)
        cls = classify_mutation(status, raw)
        attempts.append({
            "verb": verb, "path": path, "sent_body": body is not None,
            "http_status": status, "classification": cls,
            "a_2xx_would_mean": what_2xx_means,
            # Bounded, scrubbed, and kept because the classification
            # above is a reading of this text and a reader must be able
            # to check the reading.
            "response_excerpt": scrub(raw or "")[:400],
        })
    res["attempts"] = attempts

    classes = {a["classification"] for a in attempts}
    if "WRITE_ACCEPTED" in classes:
        res["verdict"] = "WRITE_ACCEPTED"
        res["accepted"] = [a for a in attempts
                           if a["classification"] == "WRITE_ACCEPTED"]
    elif "VERB_RECOGNISED_BODY_REJECTED" in classes or "REFUSED_BY_AUTHZ" in classes:
        res["verdict"] = "WRITE_VERB_PRESENT_AND_REFUSED"
        res["conops_implication"] = (
            "§6's 'read-only by construction' overstates what was "
            "measured here. At least one mutation verb is recognised by "
            "the surface and then denied, which is read-only by "
            "ENFORCEMENT -- a control that can be misconfigured. v1.6 "
            "should say enforcement, or say construction only for the "
            "verbs that are genuinely absent.")
    elif classes and classes <= {"METHOD_ABSENT"}:
        res["verdict"] = "NO_WRITE_VERB_ON_THE_SHARING_SURFACE"
        res["conops_implication"] = (
            "§6's 'read-only by construction' is supported, and by the "
            "stronger of the two available readings: no mutation verb is "
            "part of this surface, so there is no write control to "
            "misconfigure. The positive control is what makes this "
            "attributable rather than a dead-endpoint artefact.")
    else:
        res["verdict"] = "PARTIAL_SOME_ATTEMPTS_UNCLASSIFIED"
        res["unclassified"] = [a for a in attempts
                               if a["classification"].startswith("UNCLASSIFIED")
                               or a["classification"].startswith("CANNOT_SEE")]
        res["conops_implication"] = (
            "Some attempts returned a shape this test cannot sort into "
            "'verb absent' or 'verb refused'. Recorded as unclassified "
            "rather than assigned to the nearer bucket -- see §11.7 B-20.")
    return res


# =====================================================================
# HALF B -- would a credential leave this repository
# =====================================================================

# Structural, not literal. Nothing below contains a secret.
SHAPE_PATTERNS = [
    ("bearer_token_key", re.compile(r'"bearerToken"\s*:\s*"[^"]{12,}"')),
    ("share_credentials_profile", re.compile(
        r'"shareCredentialsVersion"\s*[\s\S]{0,400}?"endpoint"\s*:\s*"[^"]+"')),
    ("sharing_host_with_opaque_neighbour", re.compile(
        r'[\w.-]+\.(?:opensharing|cloud)\.[\w.-]*databricks\.com'
        r'[\s\S]{0,200}?["\s][A-Za-z0-9_\-]{40,}["\s]')),
    ("databricks_pat_shape", re.compile(r'\bdapi[0-9a-f]{24,}\b')),
    ("authorization_bearer_literal", re.compile(
        r'Authorization["\s:]+Bearer\s+[A-Za-z0-9_\-.]{20,}')),
]

# A placeholder is not a leak, but "it looked like a placeholder" is
# exactly the excuse a real leak would hide behind, so the exemption is
# an allow-list of explicit markers rather than a judgement call.
#
# The first run of this scanner reported four hits, every one of them a
# declared placeholder or a pattern definition rather than a secret:
# `"bearerToken": "dummy-not-a-real-token"` in scripts/14 and in the
# hygiene script's own explanatory comment, and a
# `dbc-REPLACE.cloud.databricks.com` / `REPLACE_FROM_YOUR_SECRET_STORE`
# pair in the Terraform tfvars template. Nothing was leaking. What the
# four hits actually showed is that this repository had grown TWO
# exemption vocabularies -- scripts/check_secret_hygiene.py's
# DECLARED_PLACEHOLDER and the markers below -- and a string declared
# safe in one was a violation in the other.
#
# Two vocabularies is the defect, so the fix is to have one. The hygiene
# script's pattern is IMPORTED rather than copied: a copy would drift,
# and drift between two scanners means every future placeholder has to
# be declared twice in two syntaxes by somebody who has to discover both
# the hard way. The markers below are now only the ADDITIONS this test
# needs -- template fillers like REPLACE, which the hygiene script never
# had to recognise because it matches whole values and these appear
# inside longer strings.
HYGIENE = load_probe("check_secret_hygiene.py", "t21_hygiene")
DECLARED_PLACEHOLDER = HYGIENE.DECLARED_PLACEHOLDER

PLACEHOLDER_MARKERS = re.compile(
    r"<[^>]*>|REDACTED|PLACEHOLDER|EXAMPLE|CHANGEME|\.\.\.|xxxx|"
    r"your[-_]?token|consumed-by-scripts|sha12|"
    # Additions, each because a real file in this repository needs it.
    r"REPLACE|DUMMY|FAKE|SYNTHETIC|SAMPLE|SECRET_STORE|"
    r"not[-_]a[-_]real|test[-_]?only|__[A-Z0-9_]+__",
    re.IGNORECASE)


def is_declared_placeholder(fragment):
    """True when the fragment is declared safe by EITHER vocabulary.

    The hygiene script's pattern is anchored and tests a VALUE, so it is
    applied to the quoted strings inside the fragment rather than to the
    fragment as a whole; the markers are substring tests and apply to
    the fragment directly.
    """
    if PLACEHOLDER_MARKERS.search(fragment):
        return True
    for value in re.findall(r'"([^"]{8,})"', fragment):
        if DECLARED_PLACEHOLDER.match(value):
            return True
    return False

# What would actually leave: whatever git tracks, plus evidence/, whose
# entire purpose is to be handed to other people. `_secrets/` is
# excluded on purpose -- a credential there is correct, and treating it
# as a violation would train the reader to ignore this test.
SCAN_EXTENSIONS = {".py", ".json", ".yaml", ".yml", ".md", ".sh", ".tf",
                   ".txt", ".csv", ".log", ".ndjson", ".tsv", ".ini", ".cfg"}
SCAN_EXCLUDE_DIRS = {".git", "_secrets", "__pycache__", ".terraform",
                     "node_modules", ".venv", "venv"}


def tracked_files():
    """git-tracked files, plus evidence/, minus _secrets/.

    git is asked rather than the filesystem walked, because the question
    is "would this leave the repository" and git's index is the closest
    available answer to that. If git is unavailable the walk is the
    fallback and the evidence record says which was used, because a
    narrower scan reporting clean is a weaker claim and the reader is
    entitled to know which one they got.
    """
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                             capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            paths = [ROOT / p for p in out.stdout.split("\0") if p]
            extra = [p for p in (ROOT / "evidence").rglob("*") if p.is_file()]
            allp = {p.resolve() for p in paths + extra}
            return sorted(allp), "GIT_INDEX_PLUS_EVIDENCE"
    except Exception:  # noqa: BLE001
        pass
    allp = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SCAN_EXCLUDE_DIRS for part in p.parts):
            continue
        allp.append(p.resolve())
    return sorted(allp), "FILESYSTEM_WALK_FALLBACK"


def scan_once(files):
    """Return the list of credential-shaped hits. No secret is emitted."""
    hits = []
    for path in files:
        try:
            if SECRETS.resolve() in path.parents:
                continue
            if any(part in SCAN_EXCLUDE_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            if path.stat().st_size > 8 * 1024 * 1024:
                continue
            text = path.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for label, pattern in SHAPE_PATTERNS:
            for m in pattern.finditer(text):
                frag = m.group(0)
                if is_declared_placeholder(frag):
                    continue
                hits.append({
                    "file": str(path.relative_to(ROOT)),
                    "line": text.count("\n", 0, m.start()) + 1,
                    "pattern": label,
                    # The matched text is NEVER written out. Only its
                    # length and a note that it matched, so that this
                    # evidence file cannot itself become the leak.
                    "match_length": len(frag),
                    "match_emitted": False,
                })
    return hits


# The token value here satisfies scripts/check_secret_hygiene.py's
# DECLARED_PLACEHOLDER exemption (`...not-a-real-token...`) while still
# THE POSITIVE CONTROL'S CREDENTIAL IS GENERATED, NOT WRITTEN DOWN, AND
# THAT IS NOT FASTIDIOUSNESS -- IT IS THE ONLY SHAPE THAT WORKS.
#
# The control has to satisfy two requirements that pull in opposite
# directions:
#
#   * This test's scanner MUST flag it. So it must NOT carry any
#     declared-placeholder marker -- the very markers the scanner was
#     just taught to honour. A control that is exempt proves nothing.
#   * The hygiene gate must NOT flag it. The first draft put a
#     token-shaped literal in this source file and the gate correctly
#     reported "Delta Sharing bearer token found in
#     tests/t21_readonly_nosecrets.py". T-21's positive control was a
#     violation to its sibling gate.
#
# Marking the literal as a declared placeholder satisfies the second
# requirement and destroys the first. The way out is to notice that the
# two scanners look at different things: the hygiene gate scans FILES ON
# DISK, and this file is only ever a `.py` source. So the token must not
# exist as a literal in the source, and must exist in the written JSON.
# Generated at call time, it is both. The written file lives for the
# duration of one scan and is removed in a `finally`.
#
# The reflex on finding the collision is to call one of the two scanners
# wrong. Neither is. They ask different questions of the same string --
# the gate asks "is a real secret committed here", T-21 asks "can my
# scanner see credential shape at all" -- and the correct answers for
# one placeholder are NO and YES respectively. Recorded in docs/11
# §11.7, along with the two-vocabularies defect it exposed.
SYNTHETIC_HOST = ("awoz1227-t21-probe.opensharing.us-east-2"
                  ".cloud.databricks.com")


def synthetic_body():
    """A credential-shaped document carrying no literal from this source.

    The token is random so that no token-shaped string is ever committed
    in this file, and the explanatory note is kept OUT of the region the
    patterns match, because a note containing the word "probe" or
    "synthetic" inside a matched fragment would exempt the control under
    the very markers above.
    """
    alphabet = string.ascii_letters + string.digits
    token = "".join(random.choice(alphabet) for _ in range(48))
    return {
        "shareCredentialsVersion": 1,
        "endpoint": f"https://{SYNTHETIC_HOST}/delta-sharing",
        "bearerToken": token,
        "expirationTime": "2000-01-01T00:00:00.000Z",
    }


SYNTHETIC_NOTE = (
    "This file was written by tests/t21_readonly_nosecrets.py as a "
    "positive control for its own credential scanner and is deleted in "
    "the same run. The token in it is random and was never issued by "
    "anything. If you are reading this, the run crashed -- delete the "
    "file.")


def half_b():
    res = {"half": "B -- would a credential leave this repository",
           "run_at": now()}
    files, source = tracked_files()
    res["scan_source"] = source
    res["files_scanned"] = len(files)

    real_hits = scan_once(files)
    res["hits"] = real_hits

    # The positive control. A scanner that found nothing and a scanner
    # that cannot see are the same report, so prove it can see before
    # believing the nothing.
    control = {}
    try:
        SYNTHETIC.parent.mkdir(parents=True, exist_ok=True)
        body = synthetic_body()
        # The note goes LAST on purpose: every pattern's match ends
        # before this key, so the note cannot exempt the control.
        body["_README"] = SYNTHETIC_NOTE
        SYNTHETIC.write_text(json.dumps(body, indent=2))
        probe_hits = scan_once([SYNTHETIC.resolve()])
        control = {
            "synthetic_written": str(SYNTHETIC.relative_to(ROOT)),
            "patterns_fired": sorted({h["pattern"] for h in probe_hits}),
            "verdict": "SCANNER_PROVEN" if probe_hits else "SCANNER_UNPROVEN",
        }
    except Exception as exc:  # noqa: BLE001
        control = {"verdict": "SCANNER_UNPROVEN",
                   "error": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            if SYNTHETIC.exists():
                SYNTHETIC.unlink()
            control["synthetic_removed"] = not SYNTHETIC.exists()
        except Exception as exc:  # noqa: BLE001
            control["synthetic_removed"] = False
            control["removal_error"] = str(exc)
    res["positive_control"] = control

    if control.get("verdict") != "SCANNER_PROVEN":
        res["verdict"] = "SCANNER_UNPROVEN"
        res["cannot_see_because"] = (
            "The synthetic credential-shaped file was not flagged by this "
            "test's own scanner, so a clean result would mean only that "
            "nothing was found -- not that nothing is there. The clean "
            "result is withdrawn rather than reported.")
    elif real_hits:
        res["verdict"] = "CREDENTIAL_SHAPE_PRESENT_IN_SHIPPABLE_FILES"
        res["files"] = sorted({h["file"] for h in real_hits})
    else:
        res["verdict"] = "NO_CREDENTIAL_SHAPE_IN_SHIPPABLE_FILES"
    if not control.get("synthetic_removed", True):
        res["warning"] = (
            f"The synthetic probe file {SYNTHETIC.name} was NOT removed. "
            f"Delete it before committing.")
    return res


# =====================================================================
# main
# =====================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipient", help="override the credential chosen for half A")
    # No defaults. The target is DISCOVERED from the recipient's own
    # grants; a default here is what let the first run mutate a share
    # the recipient could not see. Overrides are still accepted and are
    # verified readable before use.
    ap.add_argument("--share")
    ap.add_argument("--schema")
    ap.add_argument("--table")
    ap.add_argument("--skip-write-probe", action="store_true",
                    help="run half B only")
    args = ap.parse_args()

    print("T-21 -- read-only by construction, and no leaked credentials")
    print("=" * 68)
    load_env()

    out = {"test": "T-21", "epic": "E1", "task": "1.8", "ac": "AC1",
           "run_at": now(),
           "conops_claims_under_test": [
               "§6 ARB principle: read-only by construction",
               "§6 ARB principle: token-misuse reduction"],
           # B-19: a retracted claim is labelled in place, never erased.
           # This block survives every re-run of this test on purpose.
           "defect_history": [{
               "finding": "B-40",
               "retracted_verdict": "NO_WRITE_VERB_ON_THE_SHARING_SURFACE",
               "retracted_on": "2026-10-21",
               "first_reported": "2026-10-21, first run of this test",
               "what_was_wrong": (
                   "The share, schema and table were taken from "
                   "command-line DEFAULTS naming awoz1227-psp7-demo-share, "
                   "while the credential selector chose "
                   "awoz1227-psp7-t2-us-recipient, which is granted "
                   "awoz1227-psp7-t2-us-share instead. All seven mutations "
                   "went to a share the recipient holds no grant on, all "
                   "seven returned 404, and 404 was classified "
                   "METHOD_ABSENT. The verdict therefore rested on seven "
                   "'no such share for you' responses."),
               "why_the_control_missed_it": (
                   "The control was read_as_recipient, which grades "
                   "/shares answering as DISCOVERY_ONLY, and DISCOVERY_ONLY "
                   "was accepted. /shares answering proves the host and the "
                   "credential work; it proves nothing about the path being "
                   "mutated. A control has to be the SAME PATH, not the "
                   "same host."),
               "fix": (
                   "discover_readable_target() descends the recipient's own "
                   "grants to an object whose GET returns 200, and the "
                   "mutations target that object. Defaults were removed; an "
                   "explicit override is verified readable before use."),
               "class": "§12.9's silent negative with the sign flipped -- a "
                        "test passing without touching the mechanism it names",
           }],
           "halves": {}}
    rep = Report()

    # ---- half A ----
    if args.skip_write_probe:
        out["halves"]["A"] = {"verdict": "NOT_RUN",
                              "not_run_because": "--skip-write-probe"}
        print("\nHALF A -- skipped (--skip-write-probe)")
    else:
        chosen, selection = pick_recipient(args.recipient)
        out["credential_selection"] = selection
        if not chosen:
            out["halves"]["A"] = {"verdict": "CANNOT_SEE",
                                  "cannot_see_because": selection.get("reason")}
            print(f"\nHALF A -- CANNOT_SEE: {selection.get('reason')}")
        else:
            cred = chosen["_cred"]
            endpoint, bearer = cred.get("endpoint"), cred.get("bearerToken")
            print("\nHALF A -- write attempts against the sharing surface")
            print(f"  recipient: {chosen['recipient']}  "
                  f"(expires {chosen.get('expiration_time')})")
            a = half_a(endpoint, bearer, args.share, args.schema, args.table)
            out["halves"]["A"] = a
            print(f"  target:  {a.get('share')} / {a.get('schema')} / "
                  f"{a.get('table')}")
            print(f"  same-path control: GET {a.get('control_path')} -> "
                  f"{a.get('control_status')}")
            for att in a.get("attempts", []):
                print(f"    {att['verb']:7s} {att['path']:58s} "
                      f"{att['http_status']:>4}  {att['classification']}")
            print(f"  verdict: {a['verdict']}")

    # ---- half B ----
    print("\nHALF B -- credential shape in anything that would ship")
    b = half_b()
    out["halves"]["B"] = b
    print(f"  scan source: {b['scan_source']}  files: {b['files_scanned']}")
    print(f"  scanner positive control: "
          f"{(b.get('positive_control') or {}).get('verdict')} "
          f"(fired: {(b.get('positive_control') or {}).get('patterns_fired')})")
    for h in b.get("hits", [])[:20]:
        print(f"    HIT {h['file']}:{h['line']}  {h['pattern']}")
    print(f"  verdict: {b['verdict']}")
    if b.get("warning"):
        print(f"  WARNING: {b['warning']}")

    # ---- grading ----
    a_v = out["halves"]["A"].get("verdict")
    b_v = b["verdict"]

    a_pass = a_v in ("NO_WRITE_VERB_ON_THE_SHARING_SURFACE",
                     "WRITE_VERB_PRESENT_AND_REFUSED")
    rep.record(
        "T-21a", "A write attempted against the shared surface does not succeed",
        "no mutation verb accepts a request from the recipient credential, "
        "with a 200 GET on the SAME PATH as the positive control -- not "
        "merely on the same host, which is what B-40 retracted",
        a_v, a_pass, "evidence/t21-report.json")

    b_pass = b_v == "NO_CREDENTIAL_SHAPE_IN_SHIPPABLE_FILES"
    rep.record(
        "T-21b", "No credential content is present in anything that would ship",
        "zero credential-shaped matches across git-tracked files and "
        "evidence/, with the scanner proven by a synthetic positive control",
        b_v, b_pass, "evidence/t21-report.json")

    if a_v == "WRITE_ACCEPTED":
        out["verdict"] = "READ_ONLY_CLAIM_FALSIFIED"
    elif a_pass and b_pass:
        out["verdict"] = ("READ_ONLY_AND_NO_LEAK_BOTH_MEASURED"
                          if a_v == "NO_WRITE_VERB_ON_THE_SHARING_SURFACE"
                          else "READ_ONLY_BY_ENFORCEMENT_AND_NO_LEAK")
    elif a_v == "CANNOT_SEE" or b_v == "SCANNER_UNPROVEN":
        out["verdict"] = "CANNOT_SEE"
    else:
        out["verdict"] = "PARTIAL"

    rep.write(EVIDENCE)
    REPORT.write_text(json.dumps(out, indent=2, default=str))
    print("\n" + "=" * 68)
    print(f"T-21 VERDICT: {out['verdict']}")
    print(f"\nWrote {REPORT.relative_to(ROOT)}")
    return 0 if (a_pass or args.skip_write_probe) and b_pass else 1


if __name__ == "__main__":
    sys.exit(main())
