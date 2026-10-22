#!/usr/bin/env python3
"""T-19 capability baseline: what the D2D INGRESS direction actually permits.

Run before tests/t19_ingress_d2d.py. Answers capability questions only,
creates nothing it does not delete, and reaches no conclusion about
T-19 itself.

WHY THIS EXISTS WHEN A D2D BASELINE ALREADY DOES
------------------------------------------------
evidence/capability-baseline-d2d.json settled two questions on
2026-10-18: the two metastores are distinct, and a recipient with
`authentication_type = DATABRICKS` is permitted. The second result was
then carried into docs/epics/E1 as clearing T-19.

Read the direction of that probe. The recipient it created was created
on the PRIMARY workspace, owned by temari.app@gmail.com, naming
`aws:us-east-2:8875961b-...` -- glovashu -- as the data recipient. A
recipient object lives on the PROVIDER side and names the consumer. So
what was demonstrated is that **the primary can act as provider to
glovashu**, which is channel E-2, egress.

T-19 is the other direction. It needs glovashu as provider, which means
a recipient object on GLOVASHU naming the primary's sharing identifier,
plus a share, a table in that share, and a grant. None of that was
probed. The two accounts are both Free Edition so it will very likely
transfer, but "both are Free Edition so it transfers" is an assumption
of exactly the kind this exercise keeps catching (B-11, B-14, 12.9), and
the epic's own carried-forward rule for T-19 is blunt about it: if a
capability is missing, name it and mark NOT_RUN -- do not simulate it.

THE QUESTION THAT DECIDES T-19'S HEADLINE CLAIM
-----------------------------------------------
docs/12's T-19 row requires "entitled group reads; other group denied",
and CONOPS 2.4.1 step 6 grants USE CATALOG, USE SCHEMA and SELECT with
default deny. There are two different denials behind that wording and
they prove different things:

  (A) An object NOT IN THE SHARE is unreachable, even by a locally
      fully-privileged principal. This tests the PROVIDER's control
      surface. One identity is enough, so it is always runnable.

  (B) A local principal WITHOUT GRANTS cannot read a shared object.
      This tests the RECIPIENT's control surface -- step 6's default
      deny -- and it is what the matrix row demands.

(B) cannot be done with our own identity. We are metastore admin and
catalog owner, so revoking SELECT from ourselves does not deny us; the
read would succeed and the honest reading of that is "the control was
not tested", not "default deny failed". Using the same principal with a
narrower grant is precisely defect D-2, where T-04 tested a column that
was inside the grant it claimed to be excluded from.

So (B) needs a second principal, and needs it in two separable steps:

  1. The identity can be CREATED.
  2. We can AUTHENTICATE AS it.

Only (2) makes (B) runnable, and the two are distinct capabilities on
Free Edition. Check 5 keeps them apart rather than reporting one verdict
for both -- a probe that collapses them would have T-19 marked runnable
on the strength of a service principal nobody can log in as.

WHAT A FAILURE HERE MEANS
-------------------------
Nothing in this file decides whether T-19 passes. A refusal here
decides which HALF of T-19 is evidence and which is NOT_RUN with a named
missing capability. That distinction is the whole point of running it
separately.
"""

import argparse
import datetime
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "evidence" / "capability-baseline-d2d-ingress.json"

# A prefix nothing else in the repo uses, so cleanup can never match a
# real object and a leftover is identifiable as this probe's litter.
TAG = "awoz1227_p15"

# Bound for the provider-visibility poll. Short on purpose: the point is
# to exclude sub-minute propagation as an explanation for an empty list,
# not to wait out an arbitrarily slow backend. The bound is recorded in
# the evidence so the negative is reported WITH its limit (B-21).
POLL_ATTEMPTS = 4
POLL_SLEEP_S = 5


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def probe14():
    """Borrow `call` from the D2O probe instead of writing a second one.

    Same reasoning as tests/t20_ingress_d2o.py: one HTTP helper means one
    set of error-handling semantics. A second copy that raised on 4xx
    instead of returning the body would silently turn the evidence --
    which is the error body -- into a traceback.
    """
    path = REPO / "scripts" / "14_probe_d2o_provider_import.py"
    if not path.exists():
        sys.exit(f"Missing {path}; this probe reuses its HTTP helper.")
    spec = importlib.util.spec_from_file_location("probe14", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit("No .env found.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # setdefault: the FIRST occurrence wins. .env currently repeats
        # its opening block, so a value edited in the second copy is
        # silently ignored. Flagged rather than worked around.
        os.environ.setdefault(k.strip(), v.strip())


def err(payload):
    if isinstance(payload, dict):
        return (payload.get("error_code") or "",
                str(payload.get("message") or payload.get("detail") or ""))
    return "", str(payload)[:300]


# =====================================================================
# Verdict vocabulary. Kept separate on purpose -- see probe 14's note on
# why three BLOCKED verdicts are not one verdict.
# =====================================================================
PERMITTED = "PERMITTED"
REFUSED_BY_TIER = "REFUSED_BY_TIER"
REFUSED_PENDING_CONFIGURATION = "REFUSED_PENDING_CONFIGURATION"
REFUSED_BY_PRIVILEGE = "REFUSED_BY_PRIVILEGE"
REFUSED_UNCLASSIFIED = "REFUSED_UNCLASSIFIED"
ABSENT = "ABSENT"
ABSENT_NOT_REFUSED = "ABSENT_NOT_REFUSED"
PROBE_DEFECT = "PROBE_DEFECT_NOT_A_REFUSAL"
NOT_ATTEMPTED = "NOT_ATTEMPTED"

# B-20. Every verdict above except NOT_ATTEMPTED used to be a REFUSED_*
# bucket, so the probe had no way to say anything except "the platform
# declined". Three different negatives were landing in one vocabulary:
#
#   the platform declined          -> a real refusal, theirs
#   the thing was never there      -> an absence, nobody's fault
#   we called the wrong thing      -> a defect, ours
#
# Run 2 produced one of each and printed all three as [REF] REFUSED_*.
# That matters more than it looks: a refusal in the evidence record is a
# claim about the PLATFORM, so filing our own bug as a refusal attributes
# our mistake to Databricks and would carry into the CONOPS as a
# constraint on the product. B-18 was one instance of this (configuration
# read as tier); this is the general shape -- a verdict vocabulary too
# coarse to name the cause, which fails toward blaming the far side.
ABSENT_HINTS = ("does not exist", "not found", "no such",
                "table_does_not_exist", "schema_does_not_exist",
                "catalog_does_not_exist")

# Names this run created with a 2xx. If a later 404 says one of these
# "does not exist", the object is not missing -- our call looked for it
# somewhere it never was. The record cross-checks itself.
CREATED_THIS_RUN = set()


def register_created(name):
    if name:
        CREATED_THIS_RUN.add(str(name))

# A SETTING somebody can switch on, as distinct from a capability the
# tier does not sell. Checked FIRST, because the two vocabularies
# overlap on the word "enabled" and the first run of this probe
# therefore reported a configuration gap as a tier ceiling -- see B-18.
# The distinction is not cosmetic: a tier limit goes into the CONOPS as
# a constraint and starts a procurement conversation, a configuration
# gap goes in as one line of a prerequisites runbook.
CONFIG_HINTS = ("is not enabled on the metastore", "contact the metastore",
                "contact your metastore", "enable external delta sharing",
                "not enabled on this metastore", "metastore admin to enable",
                "is disabled for this metastore")
TIER_HINTS = ("not available", "unsupported", "not supported",
              "upgrade", "tier", "edition", "entitlement",
              "requires premium", "not included")
PRIV_HINTS = ("permission", "does not have", "not authorized",
              "unauthorized", "forbidden", "privilege", "admin")


def classify_refusal(status, payload):
    """Configuration vs tier vs privilege vs unknown, never a guess.

    Four buckets, ordered by how specific the evidence for them is.
    Anything that does not clearly match returns REFUSED_UNCLASSIFIED
    and keeps the body for a human, because a confident wrong bucket is
    worse than an honest unknown: it goes into a CONOPS as a fact.

    REFUSED_PENDING_CONFIGURATION is checked before REFUSED_BY_TIER
    because a message can satisfy both vocabularies at once. "External
    Delta Sharing is not enabled on the metastore. Please contact the
    metastore admin to enable External Delta Sharing" contains the
    tier-ish phrase "not enabled" and the unambiguous configuration
    phrase "contact the metastore admin to enable". The first run of
    this probe matched the former and reported REFUSED_BY_TIER, which
    would have put a false Free Edition constraint into the CONOPS --
    the very outcome the previous version of this docstring said it
    existed to prevent. B-18.
    """
    code, msg = err(payload)
    blob = f"{code} {msg}".lower()

    # Ours before theirs. A 404 that names an object this run created
    # with a 2xx is not the platform declining; it means the call went to
    # an endpoint that resolves that name in a different namespace. Must
    # be checked before the absence and privilege buckets, both of which
    # this message also matches. B-20.
    if status == 404 or any(h in blob for h in ABSENT_HINTS):
        for name in CREATED_THIS_RUN:
            if name.lower() in blob:
                return PROBE_DEFECT
    if any(h in blob for h in CONFIG_HINTS):
        return REFUSED_PENDING_CONFIGURATION
    if any(h in blob for h in TIER_HINTS):
        return REFUSED_BY_TIER
    # Absence before privilege: "does not exist" also contains "does not".
    if any(h in blob for h in ABSENT_HINTS):
        return ABSENT_NOT_REFUSED
    if status in (401, 403) or any(h in blob for h in PRIV_HINTS):
        return REFUSED_BY_PRIVILEGE
    return REFUSED_UNCLASSIFIED


def step(result_bucket, name, status, payload, ok=(200, 201)):
    verdict = PERMITTED if status in ok else classify_refusal(status, payload)
    code, msg = err(payload)
    result_bucket[name] = {
        "status": status,
        "verdict": verdict,
        "error_code": code,
        "message": msg[:400],
    }
    flag = {PERMITTED: "ok ", PROBE_DEFECT: "BUG",
            ABSENT_NOT_REFUSED: "abs"}.get(verdict, "REF")
    print(f"    [{flag}] {name}: {verdict} ({status})")
    if verdict != PERMITTED and msg:
        print(f"          {code} {msg[:150]}")
    if verdict == PROBE_DEFECT:
        result_bucket[name]["attribution"] = (
            "OURS, NOT THE PLATFORM'S. The message names an object this "
            "run created with a 2xx, so the object exists; the call "
            "resolved its name in a namespace it does not live in. Do not "
            "record this as a capability limit (B-20).")
        print("          ^ ours, not the platform's -- object was "
              "created 2xx this run")
    return verdict == PERMITTED


# =====================================================================
# CHECK 1 and 2 -- is there a provider side at all on glovashu?
# =====================================================================

def check_glovashu_substrate(call, host, token, res):
    """A table to share, and compute to change it with.

    The table is needed for the share. The compute is needed for T-19's
    refresh half: the provider has to be able to APPEND to the table,
    or "recipient sees the new rows" cannot be tested from either side.
    Separated because they fail independently -- a table with no
    warehouse means T-19 runs without the refresh half, which is a
    partial result, not a blocked test.
    """
    cat = os.environ.get("GLOVASHU_CATALOG", "").strip()
    sch = os.environ.get("UC_SCHEMA_GLOVASHU", "default").strip()
    # GLOVASHU_TABLE first so the far side CAN be named independently,
    # UC_TABLE as the fallback so it does not have to be. Script 17
    # resolves it the same way; two scripts resolving one name by
    # different rules is how a probe ends up looking for a table nobody
    # created and reporting it absent.
    tbl = (os.environ.get("GLOVASHU_TABLE", "").strip()
           or os.environ.get("UC_TABLE", "").strip()
           or "test_dataset")
    full = f"{cat}.{sch}.{tbl}"
    res["share_source_table"] = {"full_name": full}

    if not cat:
        res["share_source_table"]["verdict"] = ABSENT
        res["share_source_table"]["means"] = "GLOVASHU_CATALOG is unset in .env"
        print("    [abs] share_source_table: ABSENT (GLOVASHU_CATALOG unset)")
        return None, None

    status, payload = call(host, token,
                           f"/api/2.1/unity-catalog/tables/{full}")
    ok = step(res["share_source_table"], "lookup", status, payload)
    if ok:
        res["share_source_table"]["table_type"] = payload.get("table_type")
        res["share_source_table"]["data_source_format"] = \
            payload.get("data_source_format")
        # A share can only carry certain table types. Recording it means
        # a later "share refused the table" has something to point at
        # instead of being mysterious.
        print(f"          {full} is {payload.get('table_type')} / "
              f"{payload.get('data_source_format')}")

    status, payload = call(host, token, "/api/2.0/sql/warehouses")
    wh = None
    if status == 200 and payload.get("warehouses"):
        wh = payload["warehouses"][0]
        res["provider_compute"] = {
            "verdict": PERMITTED,
            "warehouse_id": wh.get("id"),
            "warehouse_name": wh.get("name"),
            "state": wh.get("state"),
            "means": "The provider side can run SQL, so T-19's refresh "
                     "half (append rows, re-read as recipient) is runnable.",
        }
        print(f"    [ok ] provider_compute: {wh.get('name')} "
              f"({wh.get('state')})")
    else:
        res["provider_compute"] = {
            "verdict": ABSENT if status == 200 else
                       classify_refusal(status, payload),
            "status": status,
            "means": "No usable warehouse on the provider side. T-19's "
                     "refresh half becomes NOT_RUN with that named cause; "
                     "the share and read halves are unaffected.",
        }
        print(f"    [REF] provider_compute: {res['provider_compute']['verdict']}")
    return (full if ok else None), (wh.get("id") if wh else None)


# =====================================================================
# CHECK 3 -- can glovashu act as PROVIDER to the primary?
# This is the direction the existing baseline did not test.
# =====================================================================

def check_provider_role(call, g_host, g_token, primary_identifier, table_full,
                        res):
    """Build the minimum provider-side chain, observe, then tear it down.

    Four separable permissions, so four recorded steps. Collapsing them
    into "could we share a table" would lose the useful distinction: a
    tier that permits shares but refuses DATABRICKS-auth recipients
    needs a completely different CONOPS note from one that refuses
    shares outright.
    """
    share = f"{TAG}_share"
    recipient = f"{TAG}_recipient"
    res["steps"] = {}
    created = {"share": False, "recipient": False}

    status, payload = call(g_host, g_token, "/api/2.1/unity-catalog/shares",
                           "POST",
                           {"name": share,
                            "comment": "E1 T-19 capability probe -- "
                                       "safe to delete"})
    created["share"] = step(res["steps"], "create_share", status, payload)
    if created["share"]:
        register_created(share)

    if created["share"] and table_full:
        status, payload = call(
            g_host, g_token, f"/api/2.1/unity-catalog/shares/{share}", "PATCH",
            {"updates": [{"action": "ADD",
                          "data_object": {"name": table_full,
                                          "data_object_type": "TABLE"}}]})
        step(res["steps"], "add_table_to_share", status, payload)
    else:
        res["steps"]["add_table_to_share"] = {
            "verdict": NOT_ATTEMPTED,
            "means": "No share to add to, or no source table found. "
                     "NOT_ATTEMPTED rather than a verdict, because a step "
                     "that never ran must not read as a step that passed "
                     "(B-10a).",
        }
        print("    [--- ] add_table_to_share: NOT_ATTEMPTED")

    status, payload = call(g_host, g_token,
                           "/api/2.1/unity-catalog/recipients", "POST",
                           {"name": recipient,
                            "authentication_type": "DATABRICKS",
                            "data_recipient_global_metastore_id":
                                primary_identifier,
                            "comment": "E1 T-19 capability probe -- "
                                       "safe to delete"})
    created["recipient"] = step(res["steps"], "create_recipient_for_primary",
                                status, payload)
    if created["recipient"]:
        register_created(recipient)
    # This is the step the existing baseline proved only in the opposite
    # direction. Recorded explicitly so the asymmetry is visible.
    res["steps"]["create_recipient_for_primary"]["direction_note"] = (
        "Recipient created ON GLOVASHU naming the PRIMARY as consumer. "
        "capability-baseline-d2d.json proved the reverse direction only "
        "(recipient on primary naming glovashu), which is channel E-2.")

    if created["share"] and created["recipient"]:
        # B-20. Run 2 used /permissions/share/{share}, the generic
        # SECURABLE permissions endpoint, and got
        #   404 PRINCIPAL_DOES_NOT_EXIST
        #       Could not find principal with name awoz1227_p15_recipient
        # for a recipient created 200 seconds earlier in the same run.
        # The object existed. What did not exist was an ACCOUNT principal
        # by that name -- the generic endpoint resolves `principal`
        # against users, groups and service principals, and a share
        # recipient is in none of those. The share-scoped endpoint below
        # resolves it against the metastore's recipients. One word of
        # path separates "the far side cannot do this" from "we asked the
        # wrong registry", and the error text reads like the former.
        status, payload = call(
            g_host, g_token,
            f"/api/2.1/unity-catalog/shares/{share}/permissions", "PATCH",
            {"changes": [{"principal": recipient, "add": ["SELECT"]}]})
        step(res["steps"], "grant_share_to_recipient", status, payload)
        res["steps"]["grant_share_to_recipient"]["endpoint"] = (
            f"/api/2.1/unity-catalog/shares/{share}/permissions")
        res["steps"]["grant_share_to_recipient"]["namespace_note"] = (
            "Share-scoped permissions endpoint, which resolves `principal` "
            "against the metastore's RECIPIENTS. The generic "
            "/permissions/share/{name} endpoint resolves it against "
            "account identities and 404s on a valid recipient name.")

        # B-23. The grant returned 200 and was never read back. Script 16
        # had already established the rule for this repo: a 200 on a
        # mutation is not the finding, the re-read is. Run 4 granted
        # successfully, added a table successfully, and the primary still
        # saw no provider -- and we had no evidence that either the grant
        # or the table was actually IN EFFECT, only that two calls were
        # accepted. Two unverified 200s cannot be eliminated as the cause
        # of a downstream negative, so they get verified here.
        status, payload = call(
            g_host, g_token,
            f"/api/2.1/unity-catalog/shares/{share}/permissions")
        assignments = (payload or {}).get("privilege_assignments") or []
        granted_to = {a.get("principal"): a.get("privileges")
                      for a in assignments}
        res["steps"]["grant_readback"] = {
            "status": status,
            "privilege_assignments": assignments,
            "recipient_present": recipient in granted_to,
            "privileges": granted_to.get(recipient),
            "verdict": ("GRANT_IN_EFFECT"
                        if "SELECT" in (granted_to.get(recipient) or [])
                        else "GRANT_NOT_IN_EFFECT"),
            "means": ("Reads the share's permissions back from the "
                      "provider. GRANT_NOT_IN_EFFECT after a 200 PATCH "
                      "means the grant was accepted and not applied, "
                      "which would fully explain an empty provider list "
                      "on the recipient side."),
        }
        print(f"    [{'ok ' if res['steps']['grant_readback']['verdict'] == 'GRANT_IN_EFFECT' else 'REF'}] "
              f"grant_readback: "
              f"{res['steps']['grant_readback']['verdict']} "
              f"-> {granted_to.get(recipient) or 'recipient not listed'}")

        # Same treatment for the table: is the data object IN the share?
        status, payload = call(
            g_host, g_token,
            f"/api/2.1/unity-catalog/shares/{share}"
            f"?include_shared_data=true")
        objs = (payload or {}).get("objects") or []
        names = [o.get("name") for o in objs]
        res["steps"]["share_contents_readback"] = {
            "status": status,
            "objects": names,
            "statuses": [o.get("status") for o in objs],
            "verdict": "SHARE_NON_EMPTY" if names else "SHARE_EMPTY",
            "means": ("A share whose ADD returned 200 but which reads "
                      "back empty would explain the same negative. "
                      "Object status matters too: ACTIVE vs "
                      "PERMISSION_DENIED tells us whether the provider "
                      "can actually serve the object it listed."),
        }
        print(f"    [{'ok ' if names else 'REF'}] "
              f"share_contents_readback: "
              f"{res['steps']['share_contents_readback']['verdict']} "
              f"-> {names or 'no objects'} "
              f"{res['steps']['share_contents_readback']['statuses']}")

        # And the recipient: does its identifier actually match the
        # primary's? A typo here produces a valid recipient that names
        # nobody, grants fine, and is invisible to us forever.
        status, payload = call(
            g_host, g_token,
            f"/api/2.1/unity-catalog/recipients/{recipient}")
        got_id = (payload or {}).get(
            "data_recipient_global_metastore_id")
        res["steps"]["recipient_readback"] = {
            "status": status,
            "data_recipient_global_metastore_id": got_id,
            "expected": primary_identifier,
            "matches_primary": got_id == primary_identifier,
            "authentication_type": (payload or {}).get(
                "authentication_type"),
            "activated": (payload or {}).get("activated"),
            "means": ("A recipient whose global metastore id does not "
                      "match the primary's names a different metastore. "
                      "The grant would still succeed and the share would "
                      "still be invisible here -- indistinguishable from "
                      "a visibility failure without this check."),
        }
        print(f"    [{'ok ' if got_id == primary_identifier else 'REF'}] "
              f"recipient_readback: "
              f"{'identifier matches primary' if got_id == primary_identifier else f'MISMATCH {got_id!r}'}")
    else:
        res["steps"]["grant_share_to_recipient"] = {
            "verdict": NOT_ATTEMPTED,
            "means": "Needs both a share and a recipient.",
        }
        print("    [--- ] grant_share_to_recipient: NOT_ATTEMPTED")

    return share, recipient, created


def check_recipient_visibility(call, p_host, p_token, res,
                               provider_steps=None):
    """Does the primary now SEE the provider, and can it list its shares?

    These are 2.4.1's D2D confirming calls -- the two the D2O column
    omits, which is defect D-6. Running them here is what will let T-19
    show the contrast against T-20's Path A rather than assert it.
    """
    # B-21. Run 3 granted the share successfully and the primary still
    # listed no providers. An empty list one second after a grant has at
    # least three readings -- nothing was granted to us, it was granted
    # but has not propagated, or we cannot see it -- and a single
    # immediate call cannot tell them apart. Polling does not prove
    # visibility, but it DOES remove propagation as an explanation, which
    # turns "none" from ambiguous into "none after N polls over T
    # seconds". A negative with a stated bound is evidence; an
    # unbounded one is the 12.9 shape.
    polls, names, status, payload = 0, [], None, None
    started = time.time()
    while polls < POLL_ATTEMPTS:
        polls += 1
        status, payload = call(p_host, p_token,
                               "/api/2.1/unity-catalog/providers")
        if status == 200:
            names = [p.get("name") for p in (payload.get("providers") or [])]
            if names:
                break
        if polls < POLL_ATTEMPTS:
            time.sleep(POLL_SLEEP_S)
    elapsed = round(time.time() - started, 1)

    ok = step(res, "list_providers", status, payload)
    if ok:
        res["list_providers"]["providers_visible"] = names
        res["list_providers"]["polling"] = {
            "attempts": polls,
            "sleep_seconds": POLL_SLEEP_S,
            "elapsed_seconds": elapsed,
            "stopped_because": ("provider appeared" if names
                                else "attempts exhausted"),
        }
        print(f"          providers visible: {names or 'none'} "
              f"(after {polls} poll(s) over {elapsed}s)")
        if not names:
            # Worth its own field. An empty list is a legitimate answer
            # and must not be read as a failure to call the API -- that
            # ambiguity is the 12.9 shape.
            res["list_providers"]["empty_list_note"] = (
                f"The call succeeded and returned no providers after "
                f"{polls} polls over {elapsed}s. That is a real "
                f"observation, not a failed call, and propagation delay "
                f"under {elapsed}s is excluded. On D2D the provider "
                f"appears only once the far side has granted a share to a "
                f"recipient naming this metastore.")
            # B-23b. This note used to be a hard-coded sentence saying
            # the share was empty. It printed verbatim in a run where
            # add_table_to_share was PERMITTED, so the evidence file
            # asserted something the same file disproved four lines
            # earlier. An explanation has to be DERIVED from the run it
            # explains; one that is typed in advance is a claim about the
            # run the author imagined.
            steps = provider_steps or {}
            def verdict_of(name):
                return (steps.get(name) or {}).get("verdict")
            upstream = {
                "add_table_to_share": verdict_of("add_table_to_share"),
                "grant_share_to_recipient":
                    verdict_of("grant_share_to_recipient"),
                "grant_readback": verdict_of("grant_readback"),
                "share_contents_readback":
                    verdict_of("share_contents_readback"),
                "recipient_identifier_matches":
                    (steps.get("recipient_readback") or {}).get(
                        "matches_primary"),
            }
            res["list_providers"]["upstream_state"] = upstream
            confounds = []
            if upstream["share_contents_readback"] == "SHARE_EMPTY" or \
                    upstream["add_table_to_share"] != PERMITTED:
                confounds.append(
                    "the share had no objects, so there may have been "
                    "nothing to surface")
            if upstream["grant_readback"] == "GRANT_NOT_IN_EFFECT":
                confounds.append(
                    "the grant read back as not in effect, so the share "
                    "may never have been offered to this metastore")
            if upstream["recipient_identifier_matches"] is False:
                confounds.append(
                    "the recipient's global metastore id does not match "
                    "this metastore, so the share was offered elsewhere")
            if confounds:
                res["list_providers"]["remaining_confound"] = (
                    "This negative does NOT yet license a claim about D2D "
                    "visibility, because: " + "; ".join(confounds) + ".")
                print("          ^ confound remains: " + confounds[0])
            else:
                res["list_providers"]["remaining_confound"] = None
                res["list_providers"]["negative_is_clean"] = (
                    "Every upstream precondition verified by read-back: "
                    "the share holds the table, the grant is in effect, "
                    "and the recipient names THIS metastore. Propagation "
                    "under the polling bound is excluded. The provider "
                    "list is therefore empty for a reason that is not "
                    "explained by anything this probe controls -- which "
                    "makes it a finding to chase, not a step to retry.")
                print("          ^ upstream all verified -- this empty "
                      "list is a real finding")
    for name in names:
        status, payload = call(
            p_host, p_token,
            f"/api/2.1/unity-catalog/providers/{name}/shares")
        if step(res, f"shares_in_{name}", status, payload):
            res[f"shares_in_{name}"]["shares"] = [
                s.get("name") for s in (payload.get("shares") or [])]
            print(f"          shares in {name}: "
                  f"{res[f'shares_in_{name}']['shares']}")
    return names


# =====================================================================
# CHECK 5 -- the question that decides T-19's headline claim
# =====================================================================

def check_second_identity(call, p_host, p_token, res):
    """Can a second principal be CREATED, and can we AUTHENTICATE AS it?

    Two capabilities, two verdicts, never merged. Merging them is how
    T-19 would get marked runnable on the strength of a service
    principal that nobody can obtain a credential for -- and the denied
    read would then quietly fall back to testing our own identity
    against its own grant, which is defect D-2 exactly.
    """
    sp_name = f"{TAG}_denied_principal"
    group_name = f"{TAG}_entitled_group"
    res["steps"] = {}
    app_id, sp_id, group_id = None, None, None

    status, payload = call(
        p_host, p_token, "/api/2.0/preview/scim/v2/ServicePrincipals", "POST",
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal"],
         "displayName": sp_name, "active": True})
    if step(res["steps"], "create_service_principal", status, payload):
        app_id = payload.get("applicationId")
        sp_id = payload.get("id")
        res["steps"]["create_service_principal"]["application_id"] = app_id

    # Groups matter because 2.4.1 step 6 and docs/12's T-19 row are both
    # written in terms of GROUPS, not users. If groups are refused, the
    # grant can still be made to a principal directly -- a deviation to
    # record rather than hide.
    status, payload = call(
        p_host, p_token, "/api/2.0/preview/scim/v2/Groups", "POST",
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
         "displayName": group_name})
    if step(res["steps"], "create_group", status, payload):
        group_id = payload.get("id")

    # The credential. Without this, (B) is not runnable at all.
    if app_id:
        status, payload = call(
            p_host, p_token, "/api/2.0/token-management/on-behalf-of/tokens",
            "POST",
            {"application_id": app_id, "lifetime_seconds": 600,
             "comment": "E1 T-19 capability probe -- deleted immediately"})
        got = step(res["steps"], "obtain_credential_for_principal",
                   status, payload)
        if got:
            # DO NOT record the token. The probe only needs to know that
            # one can be obtained (B-15: a credential in an evidence
            # file is a leak regardless of its lifetime).
            tok_id = (payload.get("token_info") or {}).get("token_id")
            res["steps"]["obtain_credential_for_principal"]["token_recorded"] \
                = False
            res["steps"]["obtain_credential_for_principal"]["token_id"] = tok_id
            res["held_live_credential"] = True
            if tok_id:
                dstatus, dpayload = call(
                    p_host, p_token,
                    f"/api/2.0/token-management/tokens/{tok_id}", "DELETE")
                res["steps"]["revoke_probe_credential"] = {
                    "status": dstatus,
                    "verdict": PERMITTED if dstatus in (200, 204)
                               else REFUSED_UNCLASSIFIED,
                }
                res["held_live_credential"] = dstatus not in (200, 204)
                print(f"    [{'ok ' if dstatus in (200, 204) else 'REF'}] "
                      f"revoke_probe_credential: {dstatus}")
    else:
        res["steps"]["obtain_credential_for_principal"] = {
            "verdict": NOT_ATTEMPTED,
            "means": "No service principal was created, so there was "
                     "nothing to obtain a credential for.",
        }
        print("    [--- ] obtain_credential_for_principal: NOT_ATTEMPTED")

    # The account-level OAuth route is the other way to get a credential.
    # Recorded as NOT_ATTEMPTED with its reason rather than omitted: a
    # route nobody tried must not be absent from the record, or the
    # verdict reads as "no route exists" when it means "one route exists
    # and we lack the credential to try it".
    res["steps"]["account_oauth_secret_route"] = {
        "verdict": NOT_ATTEMPTED,
        "means": "Minting an OAuth M2M secret needs account-level "
                 "credentials against accounts.cloud.databricks.com. .env "
                 "holds workspace tokens only, so this route was not "
                 "tried. If the workspace route above is refused, this is "
                 "the next thing to test before declaring (B) impossible.",
    }

    identity = res["steps"]["create_service_principal"]["verdict"]
    credential = res["steps"]["obtain_credential_for_principal"]["verdict"]
    if identity == PERMITTED and credential == PERMITTED:
        verdict = "SECOND_IDENTITY_USABLE"
        means = ("T-19's denied read (B) is runnable as specified: a real "
                 "second principal, with its own credential, attempting a "
                 "read it has no grant for.")
    elif identity == PERMITTED:
        verdict = "IDENTITY_WITHOUT_CREDENTIAL"
        means = ("A second principal can be created but not authenticated "
                 "as from here. T-19's denial (B) must be reported NOT_RUN "
                 "with this named cause. Do NOT substitute our own "
                 "identity with a narrower grant -- that is defect D-2. "
                 "Denial (A), an object outside the share, remains "
                 "runnable and tests the provider's control surface.")
    else:
        verdict = "NO_SECOND_IDENTITY"
        means = ("Neither half available. T-19's (B) is NOT_RUN; (A) still "
                 "runs.")
    res["verdict"] = verdict
    res["means"] = means
    return sp_id, group_id


# =====================================================================
# CLEANUP
# =====================================================================

def attribute_external_sharing_refusal(recipient_step):
    """Is the recipient refusal a tier ceiling, or an unset switch?

    B-12's standing rule: a refusal is not evidence until a matching
    PERMITTED case has succeeded, differing in exactly one variable.
    The matching case for this one already exists in the repository and
    does not need to be re-run.

    evidence/capability-baseline-d2d.json recorded a recipient with
    authentication_type = DATABRICKS created HTTP 200 -- on the PRIMARY
    metastore, same tier (Free Edition), same region (aws:us-east-2),
    same API version and request shape. The single variable that differs
    from the refusal here is WHICH METASTORE received the call. So the
    capability is demonstrably sold at this tier, and the refusal is
    attributable to glovashu's metastore configuration.

    Without this, 'REFUSED' on one account reads as 'Free Edition cannot
    do D2D', which is false and would have gone into v1.6 as a
    constraint.
    """
    out = {
        "observed": recipient_step.get("verdict"),
        "message": recipient_step.get("message", "")[:300],
    }
    baseline = REPO / "evidence" / "capability-baseline-d2d.json"
    if not baseline.exists():
        out["attribution"] = "UNATTRIBUTED"
        out["means"] = ("No prior baseline to compare against, so this "
                        "refusal cannot yet be separated from a tier limit. "
                        "Run scripts/09 first.")
        return out
    b = json.loads(baseline.read_text())
    control = (b.get("probes", {}).get("databricks_auth_recipient") or {})
    if control.get("attempt_status") == 200:
        out["control"] = {
            "where": "primary metastore",
            "evidence": "evidence/capability-baseline-d2d.json",
            "status": control.get("attempt_status"),
            "sharing_identifier_used": control.get("sharing_identifier_used"),
            "differs_in": "which metastore received the request",
        }
        out["attribution"] = "CONFIGURATION_NOT_TIER"
        out["means"] = (
            "A DATABRICKS-auth recipient was created HTTP 200 on the primary "
            "metastore at this same tier and region. External Delta Sharing "
            "is therefore available on Free Edition, and glovashu's refusal "
            "is an unset metastore switch, not a tier ceiling. Remediation "
            "is delta_sharing_scope = INTERNAL_AND_EXTERNAL on the glovashu "
            "metastore; see scripts/16_enable_glovashu_external_sharing.py. "
            "T-19 is therefore BLOCKED-PENDING-CONFIGURATION, not NOT_RUN.")
    else:
        out["attribution"] = "UNATTRIBUTED"
        out["means"] = ("The prior baseline did not record a successful "
                        "recipient creation, so no one-variable control "
                        "exists and the tier reading cannot be excluded.")
    return out


def cleanup(call, label, host, token, items, res):
    """Delete, then VERIFY each deletion. A delete that returned 200 and
    left the object behind is the 12.9 shape with a 200 on it."""
    res[label] = {}
    for kind, path, verify in items:
        status, payload = call(host, token, path, "DELETE")
        entry = {"delete_status": status}
        if verify:
            vstatus, _ = call(host, token, verify)
            entry["verify_status"] = vstatus
            entry["verdict"] = ("DELETED" if vstatus == 404 else
                                "STILL_PRESENT" if vstatus == 200 else
                                "UNVERIFIED")
        else:
            entry["verdict"] = "DELETED" if status in (200, 204) else "FAILED"
        res[label][kind] = entry
        print(f"    {kind}: {entry['verdict']} "
              f"(delete {status}"
              f"{', verify ' + str(entry.get('verify_status')) if verify else ''})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="skip cleanup and leave the share, recipient and "
                         "grant in place. Use when a negative needs to be "
                         "inspected in the two consoles: a probe that "
                         "deletes its own subject leaves nothing for a "
                         "human to look at, and 'providers visible: none' "
                         "is exactly the finding where the UI is the next "
                         "instrument. Objects are named with the "
                         f"{TAG} prefix so they are easy to find and "
                         "remove by hand.")
    args = ap.parse_args()

    load_env()
    p14 = probe14()
    call = p14.call

    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN",
                "GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")

    p_host = os.environ["DATABRICKS_HOST"].strip().rstrip("/")
    p_token = os.environ["DATABRICKS_TOKEN"].strip()
    g_host = os.environ["GLOVASHU_HOST"].strip().rstrip("/")
    g_token = os.environ["GLOVASHU_TOKEN"].strip()

    baseline = REPO / "evidence" / "capability-baseline-d2d.json"
    primary_identifier = None
    if baseline.exists():
        b = json.loads(baseline.read_text())
        primary_identifier = ((b.get("probes", {})
                                .get("metastore_identity", {})
                                .get("primary", {}) or {})
                              .get("sharing_identifier"))
    if not primary_identifier:
        # Fetch it rather than guess. A wrong sharing identifier produces
        # a recipient that looks created and shares with nobody.
        status, payload = call(p_host, p_token,
                               "/api/2.1/unity-catalog/metastore_summary")
        if status != 200:
            sys.exit("Cannot determine the primary's sharing identifier "
                     f"(status {status}). Run scripts/09 first.")
        primary_identifier = payload.get("global_metastore_id")

    results = {
        "probe": "d2d-ingress-prereqs",
        "task": "E1 Task 1.10 -> T-19",
        "run_at": now(),
        "gates": ["T-19 (D2D ingress)"],
        "direction": {
            "provider": f"glovashu ({g_host})",
            "recipient": f"primary ({p_host})",
            "primary_sharing_identifier": primary_identifier,
            "correction": (
                "evidence/capability-baseline-d2d.json tested the OPPOSITE "
                "direction: its recipient was created on the primary naming "
                "glovashu, which demonstrates the primary as provider "
                "(channel E-2, egress). docs/epics/E1's gate table cites it "
                "as clearing T-19. This probe tests the ingress direction "
                "that T-19 actually needs."),
        },
        "checks": {},
    }

    print("T-19 capability baseline -- D2D INGRESS direction")
    print("=" * 68)
    print(f"Provider  (far side): {g_host}")
    print(f"Recipient (us):       {p_host}")
    print(f"Primary sharing identifier: {primary_identifier}")
    print()

    print("[1/4] Provider-side substrate on glovashu")
    results["checks"]["substrate"] = {}
    table_full, _wh = check_glovashu_substrate(
        call, g_host, g_token, results["checks"]["substrate"])
    print()

    print("[2/4] Can glovashu act as PROVIDER to the primary?")
    results["checks"]["provider_role"] = {}
    share, recipient, created = check_provider_role(
        call, g_host, g_token, primary_identifier, table_full,
        results["checks"]["provider_role"])
    print()

    print("[3/4] Can the primary SEE it? (2.4.1 D2D confirming calls)")
    results["checks"]["recipient_visibility"] = {}
    check_recipient_visibility(
        call, p_host, p_token,
        results["checks"]["recipient_visibility"],
        provider_steps=results["checks"]["provider_role"].get("steps"))
    print()

    print("[4/4] A second identity for the denied read")
    results["checks"]["second_identity"] = {}
    sp_id, group_id = check_second_identity(
        call, p_host, p_token, results["checks"]["second_identity"])
    print()

    print("Cleanup")
    results["cleanup"] = {}
    if args.keep:
        results["cleanup"] = {
            "verdict": "SKIPPED_BY_FLAG",
            "left_in_place": {
                "glovashu_share": share if created.get("share") else None,
                "glovashu_recipient": (recipient
                                       if created.get("recipient") else None),
                "primary_service_principal": sp_id,
                "primary_group": group_id,
            },
            "means": ("--keep was passed, so the probe's subjects survive "
                      "for inspection in the two consoles. These are live "
                      "objects in both workspaces and must be removed by "
                      "hand or by a run without --keep."),
        }
        print("    SKIPPED (--keep). Left in place:")
        for k, v in results["cleanup"]["left_in_place"].items():
            if v:
                print(f"      {k}: {v}")
        print("    Remove with a normal run, or by hand in each console.")
    else:
        g_items, p_items = [], []
        if created.get("share"):
            g_items.append(("share",
                            f"/api/2.1/unity-catalog/shares/{share}",
                            f"/api/2.1/unity-catalog/shares/{share}"))
        if created.get("recipient"):
            g_items.append(("recipient",
                            f"/api/2.1/unity-catalog/recipients/{recipient}",
                            f"/api/2.1/unity-catalog/recipients/{recipient}"))
        if g_items:
            cleanup(call, "glovashu", g_host, g_token, g_items,
                    results["cleanup"])
        if sp_id:
            p_items.append(
                ("service_principal",
                 f"/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}",
                 f"/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}"))
        if group_id:
            p_items.append(("group",
                            f"/api/2.0/preview/scim/v2/Groups/{group_id}",
                            f"/api/2.0/preview/scim/v2/Groups/{group_id}"))
        if p_items:
            cleanup(call, "primary", p_host, p_token, p_items,
                    results["cleanup"])
        if not g_items and not p_items:
            print("    nothing was created, so nothing to remove")

    # ---- what this licenses T-19 to claim ----
    steps = results["checks"]["provider_role"]["steps"]
    chain = [steps.get(k, {}).get("verdict") for k in
             ("create_share", "add_table_to_share",
              "create_recipient_for_primary", "grant_share_to_recipient")]
    ingress_ok = all(v == PERMITTED for v in chain)
    second = results["checks"]["second_identity"]["verdict"]

    recipient_step = steps.get("create_recipient_for_primary", {})
    attribution = None
    if recipient_step.get("verdict") in (REFUSED_PENDING_CONFIGURATION,
                                         REFUSED_BY_TIER,
                                         REFUSED_BY_PRIVILEGE,
                                         REFUSED_UNCLASSIFIED):
        attribution = attribute_external_sharing_refusal(recipient_step)
        results["checks"]["provider_role"]["refusal_attribution"] = attribution

    results["conclusion"] = {
        "ingress_provider_chain": "PERMITTED" if ingress_ok else (
            "BLOCKED_PENDING_CONFIGURATION"
            if attribution and attribution.get("attribution")
            == "CONFIGURATION_NOT_TIER" else "BLOCKED"),
        "ingress_chain_steps": dict(zip(
            ("create_share", "add_table_to_share",
             "create_recipient_for_primary", "grant_share_to_recipient"),
            chain)),
        "second_identity": second,
        "t19_runnable_halves": {
            "share_and_entitled_read": "RUNNABLE" if ingress_ok
                                       else "BLOCKED",
            "denial_A_object_outside_share": "RUNNABLE" if ingress_ok
                                             else "BLOCKED",
            "denial_B_principal_without_grant":
                "RUNNABLE" if second == "SECOND_IDENTITY_USABLE"
                else "NOT_RUN",
            "refresh": ("RUNNABLE" if ingress_ok and
                        results["checks"]["substrate"]
                        .get("provider_compute", {}).get("verdict")
                        == PERMITTED else "NOT_RUN"),
        },
        "means": ("Capability only. Nothing here is a T-19 result -- it "
                  "decides which halves of T-19 produce evidence and which "
                  "are reported NOT_RUN with a named missing capability."),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2))

    print()
    print("=" * 68)
    print(f"Ingress provider chain: "
          f"{results['conclusion']['ingress_provider_chain']}")
    for k, v in results["conclusion"]["ingress_chain_steps"].items():
        print(f"  {k}: {v}")
    if attribution:
        print(f"Refusal attribution:    {attribution['attribution']}")
        if attribution.get("control"):
            c = attribution["control"]
            print(f"  control: {c['where']} returned {c['status']}, "
                  f"differs in {c['differs_in']}")
    print(f"Second identity:        {second}")
    print("T-19 halves:")
    for k, v in results["conclusion"]["t19_runnable_halves"].items():
        print(f"  {k}: {v}")
    if results["checks"]["second_identity"].get("held_live_credential"):
        print()
        print("WARNING: a probe credential was created and NOT confirmed "
              "revoked. Revoke it in the workspace UI before continuing.")
    print()
    print(f"Wrote {OUT.relative_to(REPO)}")
    print("Then run: python3 scripts/check_secret_hygiene.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
