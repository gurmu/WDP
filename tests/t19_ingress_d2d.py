#!/usr/bin/env python3
"""
T-19 -- Channel I-1 ingress, D2D pull. CONOPS §2.4.1 (D2D column), §2.4.2.

WHY THIS TEST HAS A NATIVE HALF AND A SUBSTITUTE HALF
-----------------------------------------------------
§2.4.1's D2D column reads: the provider shares a table with the
consuming metastore; the consumer runs SHOW PROVIDERS and SHOW SHARES IN
PROVIDER, creates a catalog from the share, grants it to a group, the
entitled group reads, a non-entitled group is denied, and refresh
behaviour is recorded.

Five probes (scripts/15 through 19) established that one of those steps
does not happen on this tier, and established it with controls rather
than with a shrug:

  evidence/d2d-direction-symmetry.json   VISIBILITY_UNVERIFIED
      Complete, fully read-back chains built in BOTH directions, ~169s
      bounded polls, two agreeing instruments. No provider appeared
      either way, so DIRECTION is not the variable.
  evidence/d2d-vs-d2o-same-pair.json     D2D_SURFACING_ONLY
      The SAME table, from the SAME share, under the SAME SELECT grant,
      read 37 attributable rows when the recipient's credential mode was
      TOKEN. One variable changed; the data path works.

So the missing capability is named: with `authentication_type =
DATABRICKS`, no provider object appears on the consuming metastore. That
is not a licence to skip the native half. docs/epics/E1 Task 1.10 is
explicit -- *"if either probe had failed, mark NOT_RUN with the specific
capability named -- and do not simulate a metastore and call it T-19"* --
and the symmetrical obligation is that the step is RUN here, so this
record carries a measurement rather than a citation. Part 1 therefore
builds the ingress chain for real and polls for real. If a provider DOES
appear, this test retracts D2D_SURFACING_ONLY loudly and takes the
native path; that outcome is wired up, not just mentioned.

Part 2 then runs the same §2.4.1 sequence over the one surfacing
mechanism that works here, which is the open protocol. That is a
SUBSTITUTE PATH, labelled as one everywhere it appears. It is not
D2D and must never be read as D2D having passed.

WHAT EACH PART IS FOR
---------------------
  Part 1  Native D2D ingress: chain on glovashu, bounded poll on the
          primary. Expected NOT_RUN_CAPABILITY_NAMED; wired to flip.
  Part 2  Substitute ingress over the open protocol: import, SHOW
          SHARES IN PROVIDER, CREATE CATALOG, grant, entitled read,
          attributable by row count and origin stamp.
  Part 3  Denial. (A) an object outside the share, with a same-shape
          read of a shared table as the control. (B) a second identity
          with no grant -- which probe 15 reported NOT_RUN under
          IDENTITY_WITHOUT_CREDENTIAL, and whose own evidence named two
          UNEXHAUSTED routes. One of those routes is tried here, and if
          it opens, denial (B) is demonstrated with a two-state control
          instead of being declared impossible.
  Part 4  Refresh behaviour, measured: rows appended on the provider
          side, bounded polling on the consumer side, latency recorded.
  Part 5  The D-6 contrast, read from T-20's evidence rather than
          retyped.

WHY THE TOKEN RECIPIENT IS NOT RE-MINTED HERE
---------------------------------------------
Part 2 needs a credential for glovashu, and one is on disk from
scripts/19. Minting a fresh one is not a scripted step: the activation
URL is single-use and is opened by a human in a browser, which is the
same human-mediated seam that produced B-25 (a downloaded credential
arriving at the operator's umask rather than 0600, because CONOPS 3.4.1
step 3 names no mode). So this test GRANTS its own share to the existing
recipient rather than creating a new one, and records that dependency
instead of hiding it behind a re-mint the operator would have to
babysit.

The limit of that reuse is stated in the evidence: the credential's
binding to that recipient is corroborated by its endpoint and token
fingerprint, not proven. What IS proven is attributability of the data,
by row count and origin stamp, which is the claim the read actually
rests on.

Usage:
    python3 tests/t19_ingress_d2d.py
    python3 tests/t19_ingress_d2d.py --poll-seconds 180
    python3 tests/t19_ingress_d2d.py --cleanup

Writes: evidence/t19-ingress-d2d.json
"""
import argparse
import atexit
import datetime
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
EVIDENCE = REPO / "evidence" / "t19-ingress-d2d.json"
SECRETS = REPO / "_secrets"
CREDENTIAL = SECRETS / "glovashu-d2o-credential.json"

# Preconditions. Every one of these is READ, never retyped. A test that
# restates a verdict it depends on has two sources of truth for one
# fact, and they diverge the first time the probe is re-run.
BASE_D2D = REPO / "evidence" / "capability-baseline-d2d.json"
BASE_INGRESS = REPO / "evidence" / "capability-baseline-d2d-ingress.json"
SYMMETRY = REPO / "evidence" / "d2d-direction-symmetry.json"
SAME_PAIR = REPO / "evidence" / "d2d-vs-d2o-same-pair.json"
T20 = REPO / "evidence" / "t20-ingress-d2o.json"

UC = "/api/2.1/unity-catalog"
TAG = "awoz1227_t19"
D2D_SHARE = f"{TAG}_d2d_share"
D2D_RECIPIENT = f"{TAG}_d2d_recipient"
SUB_SHARE = f"{TAG}_sub_share"
PROVIDER_NAME = f"{TAG}_glovashu_provider"
CATALOG_NAME = f"{TAG}_glovashu_catalog"
GROUP_NAME = f"{TAG}_entitled"
SP_DISPLAY = f"{TAG}_denial_b_principal"

# Minted by scripts/19 --mint, activated by hand. See the module
# docstring for why this is a dependency rather than a step.
DEFAULT_TOKEN_RECIPIENT = "awoz1227_p19_token_recipient"

REFRESH_TABLE = "t19_refresh_probe"
DENIED_TABLE = "t19_unshared_control"

TRANSIENT = (429, 500, 502, 503, 504)


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this test reuses its helpers rather "
                 f"than restating them.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "t19_probe14")
P15 = load_probe("15_probe_d2d_prereqs.py", "t19_probe15")
P19 = load_probe("19_probe_token_path_same_pair.py", "t19_probe19")

call = P14.call
classify = P14.classify
redact = P14.redact
fingerprint = P14.fingerprint
profile_summary = P14.profile_summary
step = P15.step
register_created = P15.register_created
find_warehouse = P19.find_warehouse
run_sql = P19.run_sql
expected_fixture = P19.expected_fixture

NOT_RUN = "NOT_RUN"
NOT_ATTEMPTED = P15.NOT_ATTEMPTED


def sides():
    P19.load_env()
    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN",
                "GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")
    return {
        "p_host": os.environ["DATABRICKS_HOST"].strip().rstrip("/"),
        "p_token": os.environ["DATABRICKS_TOKEN"].strip(),
        "g_host": os.environ["GLOVASHU_HOST"].strip().rstrip("/"),
        "g_token": os.environ["GLOVASHU_TOKEN"].strip(),
    }


def read_json(path, produced_by):
    if not path.exists():
        sys.exit(f"Missing {path.relative_to(REPO)}. Run {produced_by} "
                 f"first. T-19 will not guess at a precondition: a test "
                 f"that supplies its own default for a measured fact "
                 f"reports the default.")
    return json.loads(path.read_text())


def preconditions():
    """Four gates, each read from the file that measured it.

    These do not decide whether T-19 passes. They decide which halves
    of T-19 produce evidence and which are reported NOT_RUN with a
    named cause -- which is the distinction §12.9's silent negative is
    about. A test that ran the halves it could and said nothing about
    the rest would look like a full pass.
    """
    d2d = read_json(BASE_D2D, "scripts/09_probe_metastore_identity.py")
    ingress = read_json(BASE_INGRESS, "scripts/15_probe_d2d_prereqs.py")
    sym = read_json(SYMMETRY, "scripts/18_probe_d2d_direction_symmetry.py "
                              "--direction both")
    pair = read_json(SAME_PAIR, "scripts/19_probe_token_path_same_pair.py "
                                "--verify")
    fixture = expected_fixture()

    identity = ((d2d.get("probes") or {}).get("metastore_identity") or {})
    # The verdict is at probes.metastore_identity.CONCLUSION.verdict, one
    # level deeper than it looks. The first version of this function read
    # it one level up, got None, and aborted with "the far side is not a
    # distinct metastore (None)" -- a claim about the PLATFORM generated
    # by a wrong key path in this file. That is B-20's attribution error
    # wearing a new coat, and it would have sent the operator to re-run
    # scripts/09 against two accounts that were never the problem.
    #
    # So ABSENCE is separated from DISAGREEMENT here rather than
    # collapsing into it: a key that cannot be found is ours, and says
    # so. Collapsing them is the silent negative (§12.9) appearing
    # inside the tooling built to detect it.
    conclusion = (identity.get("conclusion") or {})
    primary = (identity.get("primary") or {})
    glovashu = (identity.get("glovashu") or {})
    halves = ((ingress.get("conclusion") or {}).get("t19_runnable_halves")
              or {})
    second = ((ingress.get("checks") or {}).get("second_identity") or {})

    if "verdict" not in conclusion:
        sys.exit(
            f"Could not FIND the metastore-identity verdict in "
            f"{BASE_D2D.relative_to(REPO)} at "
            f"probes.metastore_identity.conclusion.verdict. That is a "
            f"defect in tests/t19_ingress_d2d.py or a schema change in "
            f"scripts/09 -- it is NOT a statement about the two "
            f"metastores. Do not re-run scripts/09 on the strength of "
            f"this message; fix the key path.")

    gates = {
        "distinct_metastores": {
            "verdict": conclusion.get("verdict"),
            "source": str(BASE_D2D.relative_to(REPO)),
            "primary_sharing_identifier": primary.get("sharing_identifier"),
            # Needed to tell a D2D-surfaced provider from one WE
            # imported. See part1_native's poll: without this id the
            # poll can only ask "is the list non-empty", which is a
            # different question and got answered wrongly once already.
            "glovashu_metastore_id": glovashu.get("metastore_id"),
            "glovashu_sharing_identifier": glovashu.get(
                "sharing_identifier"),
        },
        "ingress_chain_permitted": {
            "verdict": (ingress.get("conclusion") or {}).get(
                "ingress_provider_chain"),
            "source": str(BASE_INGRESS.relative_to(REPO)),
            "runnable_halves": halves,
        },
        "direction_excluded": {
            "verdict": (sym.get("comparison") or {}).get("verdict"),
            "source": str(SYMMETRY.relative_to(REPO)),
            "poll_bound_seconds": sym.get("poll_bound_seconds"),
        },
        "credential_mode_narrowed": {
            "verdict": (pair.get("comparison") or {}).get("verdict"),
            "source": str(SAME_PAIR.relative_to(REPO)),
        },
        "attributable_fixture": {
            "verdict": "CREATED_AND_VERIFIED",
            "source": fixture["fixture_source"],
            "row_count": fixture["row_count"],
            "origin_metastore": fixture["origin_metastore"],
            "table_full_name": fixture["table_full_name"],
        },
        "second_identity": {
            "verdict": second.get("verdict"),
            "source": str(BASE_INGRESS.relative_to(REPO)),
            "unexhausted_routes": [
                k for k, v in (second.get("steps") or {}).items()
                if (v or {}).get("verdict") == NOT_ATTEMPTED
            ],
        },
    }

    if gates["distinct_metastores"]["verdict"] != "DISTINCT_METASTORES":
        sys.exit("The far side is not a distinct metastore per "
                 f"{BASE_D2D.relative_to(REPO)} "
                 f"({gates['distinct_metastores']['verdict']!r}). Without "
                 "two metastores there is no D2D to test, and running "
                 "anyway would produce a record that looks like T-19.")
    if not gates["distinct_metastores"]["primary_sharing_identifier"]:
        sys.exit("No primary sharing identifier recorded. A wrong or "
                 "absent identifier produces a recipient that names "
                 "nobody, grants cleanly, and is invisible forever -- "
                 "indistinguishable from the visibility failure this "
                 "test is measuring.")
    if not gates["distinct_metastores"]["glovashu_metastore_id"]:
        sys.exit(
            f"No glovashu metastore id at "
            f"probes.metastore_identity.glovashu.metastore_id in "
            f"{BASE_D2D.relative_to(REPO)}. That is a defect in this "
            f"file or a schema change in scripts/09, NOT a fact about "
            f"glovashu. Part 1's provider poll cannot attribute a "
            f"provider without it, and an unattributable provider is "
            f"what produced the false retraction on the first run.")
    gates["means"] = (
        "Capability and prior findings only. Nothing here is a T-19 "
        "result. The verdicts are read from the files that measured "
        "them rather than restated, so this record cannot disagree "
        "with its own preconditions.")
    return gates, fixture


# =====================================================================
# PART 1 -- native D2D ingress, run for real
# =====================================================================

def part1_native(s, fixture, gates, poll_seconds, poll_interval):
    """Build the ingress chain on glovashu; poll the primary for it.

    Every mutation is read back. That rule came from B-23: a 200 on a
    mutation is not the finding, the re-read is. Four unverified 200s
    upstream of an empty provider list cannot be eliminated as the
    cause of it, so the negative below would mean nothing without the
    read-backs.

    Both halves of this part were wrong on the first run, in opposite
    directions, and both for the same underlying reason: a name was
    matched where an ATTRIBUTE should have been. The recipient create
    returned 400 naming a DIFFERENT object, so the adopt branch did not
    fire; the provider poll matched on "the list is non-empty", saw a
    leftover TOKEN provider from scripts/19, and retracted a sound
    finding. Both are now attribute checks with the names recorded.
    """
    res = {"role": "glovashu is PROVIDER, primary is CONSUMER (ingress)",
           "steps": {}}
    g_host, g_token = s["g_host"], s["g_token"]
    p_host, p_token = s["p_host"], s["p_token"]
    table_full = fixture["table_full_name"]
    primary_identifier = gates["distinct_metastores"][
        "primary_sharing_identifier"]
    glovashu_id = gates["distinct_metastores"]["glovashu_metastore_id"]

    print("\nPART 1 -- native D2D ingress (§2.4.1 D2D column, steps 5a/5b)")
    print("-" * 68)

    # --- provider side ------------------------------------------------
    status, payload = call(g_host, g_token, f"{UC}/shares", "POST",
                           {"name": D2D_SHARE,
                            "comment": "T-19 native D2D ingress"})
    made_share = step(res["steps"], "create_share", status, payload)
    pre_share = (not made_share and "already exists"
                 in json.dumps(payload or {}).lower())
    if made_share or pre_share:
        register_created(D2D_SHARE)
        if pre_share:
            res["steps"]["create_share"]["verdict"] = "PERMITTED_PREEXISTING"
            res["steps"]["create_share"]["means"] = (
                "Share left by an earlier run of this test. Adopted, and "
                "recorded as NOT created by this run, so a later 404 "
                "naming it is still cross-checked against "
                "CREATED_THIS_RUN (B-20).")
            # The console already printed REFUSED_UNCLASSIFIED above,
            # and the evidence file now says PERMITTED_PREEXISTING. Two
            # labels for one step, one of them on screen and wrong. The
            # correction is printed rather than left to the file,
            # because a reader of the console is the reader who decides
            # whether to stop the run.
            print("    [ok ] create_share: PERMITTED_PREEXISTING "
                  "(adopted; corrects the line above)")

    if made_share or pre_share:
        status, payload = call(
            g_host, g_token, f"{UC}/shares/{D2D_SHARE}", "PATCH",
            {"updates": [{"action": "ADD",
                          "data_object": {"name": table_full,
                                          "data_object_type": "TABLE"}}]})
        ok = status in (200, 201) or "already" in json.dumps(
            payload or {}).lower()
        step(res["steps"], "add_table_to_share", status, payload,
             ok=(200, 201))
        if ok and status not in (200, 201):
            res["steps"]["add_table_to_share"]["verdict"] = \
                "PERMITTED_PREEXISTING"
            print("    [ok ] add_table_to_share: PERMITTED_PREEXISTING "
                  "(already shared; corrects the line above)")
    else:
        res["steps"]["add_table_to_share"] = {
            "verdict": NOT_ATTEMPTED,
            "means": "No share to add to. NOT_ATTEMPTED rather than a "
                     "verdict: a step that never ran must not read as a "
                     "step that passed (B-10a)."}
        print("    [---] add_table_to_share: NOT_ATTEMPTED")

    # --- the recipient, and the constraint the first run found --------
    # Databricks permits ONE recipient per sharing identifier:
    #   400 RECIPIENT_ALREADY_EXISTS There is already a Recipient object
    #   'awoz1227_p18_glovashu_recipient' with the same sharing
    #   identifier
    # That message names an object we did not ask for -- probe 18's
    # leftover, pointing at the same primary -- so a substring match on
    # OUR name could never catch it, and the first run filed a platform
    # RULE as REFUSED_UNCLASSIFIED. The rule is a finding in its own
    # right (it constrains the CONOPS: one D2D recipient per
    # counterparty metastore, so §2.4.1 cannot assume a fresh recipient
    # per share), and the existing object is adoptable -- but only after
    # checking it points where ours would have. Adopting a recipient
    # aimed at a different metastore would reproduce exactly the
    # confound the recipient_identifier read-back exists to catch.
    recipient_name = D2D_RECIPIENT
    status, payload = call(g_host, g_token, f"{UC}/recipients", "POST",
                           {"name": D2D_RECIPIENT,
                            "authentication_type": "DATABRICKS",
                            "data_recipient_global_metastore_id":
                                primary_identifier,
                            "comment": "T-19 native D2D ingress"})
    made_rec = step(res["steps"], "create_recipient_for_primary",
                    status, payload)
    body = json.dumps(payload or {})
    pre_rec = False
    if made_rec:
        register_created(D2D_RECIPIENT)
    elif ("already exists" in body.lower()
            or "RECIPIENT_ALREADY_EXISTS" in body):
        named = re.search(r"Recipient object '([^']+)'", body)
        candidate = named.group(1) if named else D2D_RECIPIENT
        cstatus, cpayload = call(g_host, g_token,
                                 f"{UC}/recipients/{candidate}")
        cinfo = cpayload or {}
        c_target = cinfo.get("data_recipient_global_metastore_id")
        c_auth = cinfo.get("authentication_type")
        usable = (cstatus == 200 and c_auth == "DATABRICKS"
                  and c_target == primary_identifier)
        res["steps"]["create_recipient_for_primary"].update({
            "platform_constraint": (
                "RECIPIENT_ALREADY_EXISTS on the SHARING IDENTIFIER, not "
                "on the name. Databricks allows one D2D recipient per "
                "counterparty metastore per provider metastore. NEW "
                "BEHAVIOUR, discovered by the first run of this test."),
            "named_in_error": candidate,
            "named_is_ours": candidate == D2D_RECIPIENT,
            "existing_recipient": {
                "status": cstatus,
                "authentication_type": c_auth,
                "data_recipient_global_metastore_id": c_target,
                "activated": cinfo.get("activated"),
                "points_at_primary": c_target == primary_identifier},
            "adoption": "ADOPTED" if usable else "REFUSED_WRONG_TARGET",
        })
        if usable:
            pre_rec = True
            recipient_name = candidate
            res["steps"]["create_recipient_for_primary"]["verdict"] = (
                "PERMITTED_PREEXISTING_ADOPTED")
            res["steps"]["create_recipient_for_primary"]["means"] = (
                f"Adopted {candidate!r}, which already points at the "
                f"primary over DATABRICKS auth, because the platform "
                f"will not let a second one exist. NOT registered as "
                f"created by this run: a later 404 naming it must not "
                f"be attributed to T-19's cleanup (B-20). The grant and "
                f"all three read-backs below run against this name, so "
                f"the chain is measured on the object actually in use.")
            print(f"    [ok ] create_recipient_for_primary: "
                  f"ADOPTED {candidate} (one recipient per sharing "
                  f"identifier)")
        else:
            res["steps"]["create_recipient_for_primary"]["means"] = (
                f"The sharing identifier is taken by {candidate!r}, "
                f"which this run could not confirm points at the "
                f"primary over DATABRICKS auth (status={cstatus}, "
                f"auth={c_auth!r}, target={c_target!r}). NOT adopted: a "
                f"recipient aimed at another metastore grants cleanly "
                f"and is invisible forever, which is the exact confound "
                f"the recipient_identifier read-back exists to catch. "
                f"Delete {candidate!r} by hand, or re-run with it "
                f"removed, before reading anything into Part 1.")
            print(f"    [REF] create_recipient_for_primary: existing "
                  f"{candidate} not adoptable -- see evidence")

    if (made_share or pre_share) and (made_rec or pre_rec):
        # Share-scoped permissions endpoint. The generic
        # /permissions/share/{name} route resolves `principal` against
        # ACCOUNT identities and 404s PRINCIPAL_DOES_NOT_EXIST on a
        # perfectly valid recipient name -- one word of path between
        # "the far side cannot do this" and "we asked the wrong
        # registry". B-20.
        status, payload = call(
            g_host, g_token, f"{UC}/shares/{D2D_SHARE}/permissions",
            "PATCH", {"changes": [{"principal": recipient_name,
                                   "add": ["SELECT"]}]})
        step(res["steps"], "grant_share_to_recipient", status, payload)
        res["steps"]["grant_share_to_recipient"]["endpoint"] = (
            f"{UC}/shares/{D2D_SHARE}/permissions")
    else:
        res["steps"]["grant_share_to_recipient"] = {
            "verdict": NOT_ATTEMPTED,
            "means": "Needs both a share and a recipient."}
        print("    [---] grant_share_to_recipient: NOT_ATTEMPTED")

    # --- read-backs, all four ----------------------------------------
    readbacks = {}

    status, payload = call(g_host, g_token,
                           f"{UC}/shares/{D2D_SHARE}/permissions")
    assignments = (payload or {}).get("privilege_assignments") or []
    granted = {a.get("principal"): a.get("privileges") for a in assignments}
    readbacks["grant"] = {
        "status": status,
        "principal": recipient_name,
        "privileges": granted.get(recipient_name),
        "verdict": ("GRANT_IN_EFFECT"
                    if "SELECT" in (granted.get(recipient_name) or [])
                    else "GRANT_NOT_IN_EFFECT"),
        "means": ("A grant accepted with 200 and not applied would fully "
                  "explain an empty provider list downstream."),
    }

    status, payload = call(g_host, g_token,
                           f"{UC}/shares/{D2D_SHARE}?include_shared_data=true")
    objs = (payload or {}).get("objects") or []
    readbacks["share_contents"] = {
        "status": status,
        "objects": [o.get("name") for o in objs],
        "statuses": [o.get("status") for o in objs],
        "verdict": "SHARE_NON_EMPTY" if objs else "SHARE_EMPTY",
        "means": ("Object STATUS matters as much as presence: ACTIVE vs "
                  "PERMISSION_DENIED says whether the provider can "
                  "actually serve what it listed."),
    }

    status, payload = call(g_host, g_token,
                           f"{UC}/recipients/{recipient_name}")
    got_id = (payload or {}).get("data_recipient_global_metastore_id")
    readbacks["recipient_identifier"] = {
        "status": status,
        "recipient": recipient_name,
        "observed": got_id,
        "expected": primary_identifier,
        "matches_primary": got_id == primary_identifier,
        "authentication_type": (payload or {}).get("authentication_type"),
        "activated": (payload or {}).get("activated"),
        "means": ("A recipient whose identifier does not match the "
                  "primary's names a different metastore, grants fine, "
                  "and is invisible here -- indistinguishable from a "
                  "visibility failure without this check."),
    }
    res["readbacks"] = readbacks
    for name, rb in readbacks.items():
        good = rb["verdict"] if "verdict" in rb else (
            "MATCHES" if rb.get("matches_primary") else "MISMATCH")
        print(f"    [{'ok ' if good in ('GRANT_IN_EFFECT', 'SHARE_NON_EMPTY', 'MATCHES') else 'REF'}] "
              f"readback {name}: {good}")

    chain_complete = (
        readbacks["grant"]["verdict"] == "GRANT_IN_EFFECT"
        and readbacks["share_contents"]["verdict"] == "SHARE_NON_EMPTY"
        and readbacks["recipient_identifier"]["matches_primary"] is True)
    res["chain"] = "COMPLETE" if chain_complete else "INCOMPLETE"
    res["recipient_in_use"] = recipient_name

    # --- consumer side: the bounded poll ------------------------------
    # B-21. "None" is ambiguous; "none after N polls over T seconds" is
    # reportable. And the loop breaks out of a NON-transient refusal
    # rather than retrying through it for the full bound, which would
    # print the same sentence for "the list is empty" and "we were
    # refused 12 times" -- the silent negative, inside our own tooling.
    #
    # THE FIX THE FIRST RUN FORCED. The old loop broke when the provider
    # list was non-empty and called that surfacing. The list was not
    # empty: it held awoz1227_p19_glovashu_provider, which scripts/19
    # IMPORTED over the open protocol with a TOKEN credential. So this
    # test printed "D2D_SURFACING_ONLY IS CONTRADICTED" at a provider
    # created by hand on the token path, graded the whole run
    # NATIVE_PATH_UNEXPECTEDLY_AVAILABLE_RERUN_PROBES, and would have
    # sent the operator to re-run two probes whose findings were sound.
    #
    # A D2D-surfaced provider is identifiable, not merely present: its
    # authentication_type is DATABRICKS and its
    # data_provider_global_metastore_id names glovashu. So the poll now
    # asks for those two attributes and sorts every provider into a
    # bucket. Nothing is dropped silently -- the excluded names and the
    # reason for each exclusion are recorded, because an exclusion the
    # reader cannot see is how the original error would come back
    # inverted.
    def provider_attrs(entry):
        """auth type and provider metastore for one provider.

        The list payload may omit either field. When it does, GET the
        provider: an absent attribute must not be read as a mismatch,
        which would exclude a genuine D2D provider and manufacture the
        negative this part is here to test for.
        """
        name = entry.get("name")
        auth = entry.get("authentication_type")
        pid = entry.get("data_provider_global_metastore_id")
        src = "list"
        if name and (auth is None or pid is None):
            gstatus, gpayload = call(p_host, p_token,
                                     f"{UC}/providers/{name}")
            if gstatus == 200 and gpayload:
                auth = auth or gpayload.get("authentication_type")
                pid = pid or gpayload.get(
                    "data_provider_global_metastore_id")
                src = "list+get"
            else:
                src = f"list+get_failed_{gstatus}"
        return {"name": name, "authentication_type": auth,
                "data_provider_global_metastore_id": pid,
                "fields_from": src}

    def sort_providers(entries):
        candidates, excluded, unclassified = [], [], []
        for entry in entries:
            a = provider_attrs(entry)
            auth, pid = a["authentication_type"], (
                a["data_provider_global_metastore_id"] or "")
            if auth == "DATABRICKS" and glovashu_id and glovashu_id in pid:
                candidates.append(a)
            elif auth == "DATABRICKS" and pid:
                a["excluded_because"] = (
                    "DATABRICKS auth but the provider metastore is not "
                    "glovashu, so it is a different counterparty.")
                excluded.append(a)
            elif auth == "TOKEN":
                a["excluded_because"] = (
                    "authentication_type TOKEN: imported by hand from a "
                    "credential file, which is the open-protocol path. "
                    "Its presence says nothing about D2D surfacing. This "
                    "is the provider that caused the first run's false "
                    "retraction.")
                excluded.append(a)
            else:
                a["unclassified_because"] = (
                    f"Could not read authentication_type "
                    f"(auth={auth!r}, provider_metastore={pid!r}, "
                    f"fields_from={a['fields_from']}). NOT excluded: an "
                    f"unreadable attribute is our blind spot, not a "
                    f"negative result.")
                unclassified.append(a)
        return candidates, excluded, unclassified

    deadline = time.time() + poll_seconds
    polls, last_status, refusal = 0, None, None
    names, candidates, excluded, unclassified = [], [], [], []
    while True:
        polls += 1
        last_status, payload = call(p_host, p_token, f"{UC}/providers")
        if last_status == 200:
            entries = (payload or {}).get("providers") or []
            names = [p.get("name") for p in entries]
            candidates, excluded, unclassified = sort_providers(entries)
            if candidates:
                break
        elif last_status not in TRANSIENT:
            refusal = classify(last_status, payload)
            break
        if time.time() + poll_interval > deadline:
            break
        time.sleep(poll_interval)
    elapsed = round(poll_seconds - max(0, deadline - time.time()), 1)

    res["consumer_poll"] = {
        "endpoint": f"{UC}/providers",
        "polls": polls,
        "elapsed_seconds": elapsed,
        "bound_seconds": poll_seconds,
        "last_status": last_status,
        "providers_visible": names,
        "attribution_rule": (
            f"A provider counts as D2D-surfaced only if "
            f"authentication_type == DATABRICKS AND "
            f"data_provider_global_metastore_id contains glovashu's "
            f"metastore id {glovashu_id}. Presence in the list is not "
            f"the test."),
        "d2d_candidates": candidates,
        "excluded": excluded,
        "unclassified": unclassified,
        "refusal": refusal[0] if isinstance(refusal, tuple) else refusal,
        "verdict": ("D2D_PROVIDER_APPEARED" if candidates else
                    "POLL_REFUSED" if refusal else
                    "UNCLASSIFIABLE" if unclassified else
                    "NO_D2D_PROVIDER_BOUNDED_NEGATIVE"),
    }
    print(f"    [{'ok ' if candidates else '---'}] providers on the "
          f"primary: {names or 'none'}")
    print(f"          D2D-attributable: "
          f"{[c['name'] for c in candidates] or 'none'} | excluded: "
          f"{[e['name'] for e in excluded] or 'none'} | unclassified: "
          f"{[u['name'] for u in unclassified] or 'none'}")
    if not candidates and not refusal:
        print(f"          bounded negative after {polls} poll(s) over "
              f"~{elapsed}s")

    if candidates:
        res["verdict"] = "NATIVE_D2D_SURFACED_RETRACTION_REQUIRED"
        res["retraction"] = (
            f"A provider ATTRIBUTABLE TO GLOVASHU OVER DATABRICKS AUTH "
            f"appeared: {[c['name'] for c in candidates]}. That "
            f"contradicts {SAME_PAIR.relative_to(REPO)}'s "
            f"D2D_SURFACING_ONLY and {SYMMETRY.relative_to(REPO)}'s "
            f"bounded negatives. Do not quietly prefer this result: "
            f"label the earlier finding retracted rather than deleting "
            f"it (B-19), re-run scripts/18 and 19 to find what differs, "
            f"and only then write up T-19 as a native pass. Before any "
            f"of that, check the recorded authentication_type and "
            f"data_provider_global_metastore_id of each name above by "
            f"hand -- the first run of this test raised this alarm "
            f"against a TOKEN provider left by scripts/19, and a false "
            f"retraction costs more than a missed one.")
        print("    ** D2D_SURFACING_ONLY IS CONTRADICTED -- see "
              "retraction in the evidence file")
    elif unclassified:
        res["verdict"] = "PROVIDER_LIST_UNCLASSIFIABLE_NOT_A_RESULT"
        res["means"] = (
            f"{len(unclassified)} provider(s) on the consumer could not "
            f"be attributed either way, because their "
            f"authentication_type could not be read. That is neither a "
            f"surfacing result nor a bounded negative, and it is "
            f"reported as its own state rather than folded into either "
            f"-- folding it in is the silent negative (§12.9), and "
            f"folding it the other way is the false retraction the "
            f"first run produced. Resolve the names listed under "
            f"consumer_poll.unclassified, then re-run.")
    elif not chain_complete:
        res["verdict"] = "NO_PROVIDER_WITH_CONFOUNDS"
        res["means"] = (
            "A read-back failed, so this run's negative is not clean and "
            "cannot be added to the evidence for D2D_SURFACING_ONLY. "
            "Fix the chain and re-run before reporting anything.")
    elif refusal:
        res["verdict"] = "POLL_REFUSED_NOT_A_VISIBILITY_RESULT"
        res["means"] = (
            "The consumer-side call was refused, which is a different "
            "fact from an empty list. Recorded as a refusal so it cannot "
            "be counted as corroboration of the surfacing finding.")
    else:
        res["verdict"] = "NOT_RUN_CAPABILITY_NAMED"
        res["capability_missing"] = (
            "Automatic provider surfacing on the consuming metastore for "
            "a recipient with authentication_type = DATABRICKS.")
        res["means"] = (
            f"The chain was built and every mutation read back "
            f"(chain={res['chain']}), and no provider ATTRIBUTABLE to "
            f"glovashu over DATABRICKS auth appeared on the consumer "
            f"within {elapsed}s over {polls} poll(s) -- "
            f"{len(excluded)} provider(s) were present and excluded on "
            f"recorded attributes, not on name. §2.4.1's "
            f"D2D steps 5a and 5b therefore have no object to run "
            f"against. This is the THIRD independent bounded negative "
            f"for the same capability, after both directions in "
            f"{SYMMETRY.relative_to(REPO)} -- and it is reported NOT_RUN "
            f"with the capability named, NOT as a T-19 failure, because "
            f"nothing about the CONOPS procedure was shown to be wrong.")
    print(f"    PART 1 VERDICT: {res['verdict']}")
    return res


# =====================================================================
# PART 2 -- substitute ingress over the open protocol
# =====================================================================

def part2_substitute(s, fixture, token_recipient):
    """§2.4.1's sequence over the one surfacing mechanism that works.

    LABELLED A SUBSTITUTE EVERYWHERE. This is not D2D. What it
    demonstrates is that the CONOPS ingress PROCEDURE -- import,
    enumerate shares, create a catalog, grant, read -- runs end to end
    against glovashu, and that rows genuinely cross the boundary. What
    it does not demonstrate is anything about authentication_type =
    DATABRICKS, which Part 1 measured.
    """
    res = {"substitute": True,
           "why": ("The native surfacing step is missing (Part 1). This "
                   "path exercises the same §2.4.1 sequence over the open "
                   "protocol so the procedure is evidenced rather than "
                   "asserted. It is NOT a D2D result."),
           "steps": {}}
    g_host, g_token = s["g_host"], s["g_token"]
    p_host, p_token = s["p_host"], s["p_token"]
    table_full = fixture["table_full_name"]

    print("\nPART 2 -- substitute ingress, open protocol (§2.4.1 steps 5a-6)")
    print("-" * 68)

    if not CREDENTIAL.exists():
        res["verdict"] = "NOT_RUN_NO_CREDENTIAL"
        res["means"] = (
            f"{CREDENTIAL.relative_to(REPO)} is absent. Run "
            f"scripts/19_probe_token_path_same_pair.py --mint and open "
            f"the activation URL it vaults. That step is human-mediated "
            f"by design -- the link is single-use and the download lands "
            f"at the operator's umask, which is B-25 -- so this test "
            f"will not fabricate it.")
        print(f"    [---] {res['verdict']}")
        return res

    # B-25, as a measurement rather than a correction. Stat before
    # touching: chmod-then-check would record the mode this test just
    # set and report every run as compliant.
    mode_before = CREDENTIAL.stat().st_mode & 0o777
    if mode_before != 0o600:
        CREDENTIAL.chmod(0o600)
    res["steps"]["credential_custody"] = {
        "mode_on_arrival": oct(mode_before),
        "mode_now": oct(CREDENTIAL.stat().st_mode & 0o777),
        "arrived_restricted": mode_before == 0o600,
        "verdict": ("CUSTODY_OK" if mode_before == 0o600
                    else "ARRIVED_PERMISSIVE_CORRECTED"),
        "means": ("CONOPS 3.4.1 step 3 names no file mode, so a "
                  "browser-downloaded credential lands at the operator's "
                  "umask while every scripted write is 0600. The runbook "
                  "defect, not the operator, is the finding (B-25)."),
    }
    profile = json.loads(CREDENTIAL.read_text())
    res["credential"] = profile_summary(profile)
    endpoint = (profile.get("endpoint") or "")
    ep_host = urlparse(endpoint).hostname or ""
    p_hostname = urlparse(p_host).hostname or ""
    g_hostname = urlparse(g_host).hostname or ""

    # B-26 rebuilt. The decisive failure is a credential pointing at the
    # CONSUMER, because a read through that is a local read wearing a
    # sharing costume. Databricks serves open sharing from a dedicated
    # <uuid>.opensharing.<region> endpoint whose UUID is NEITHER
    # metastore id, so comparing against glovashu's workspace hostname
    # flags the normal case -- and a guard that fires on the normal case
    # trains the reader to skip the line that matters when it is real.
    if ep_host and ep_host == p_hostname:
        ep_verdict = "POINTS_AT_THE_CONSUMER"
    elif ep_host and ep_host == g_hostname:
        ep_verdict = "POINTS_AT_PROVIDER_WORKSPACE_HOST"
    elif ".opensharing." in ep_host:
        ep_verdict = "DEDICATED_SHARING_ENDPOINT"
    else:
        ep_verdict = "UNRECOGNISED_ENDPOINT"
    res["steps"]["endpoint_check"] = {
        "endpoint_host": ep_host,
        "verdict": ep_verdict,
        "means": {
            "POINTS_AT_THE_CONSUMER":
                "DECISIVE FAILURE. The credential names the primary, so "
                "any read through it is the primary reading itself.",
            "POINTS_AT_PROVIDER_WORKSPACE_HOST":
                "Corroborative only.",
            "DEDICATED_SHARING_ENDPOINT":
                "Expected. Databricks serves open sharing from a "
                "dedicated <uuid>.opensharing.<region> host that is "
                "neither workspace hostname, so this is normal and NOT a "
                "problem. Attributability of the read rests on the row "
                "count and origin stamp below, not on this hostname.",
            "UNRECOGNISED_ENDPOINT":
                "Neither workspace host nor a recognised sharing "
                "endpoint. Not decisive either way -- read the "
                "attributability result before concluding anything.",
        }[ep_verdict],
        "allow_list_implication": (
            f"{ep_host} is a REQUIRED outbound destination for ingress "
            f"over the open protocol and is not derivable from "
            f"DATABRICKS_HOST or GLOVASHU_HOST. An allow-list built from "
            f"those two fails closed. Candidate addition to "
            f"iac/config/outbound-allow-list.yaml; OD-4 and T-20's "
            f"rendered list both depend on it." if ep_host else None),
    }
    print(f"    [{'REF' if ep_verdict == 'POINTS_AT_THE_CONSUMER' else 'ok '}] "
          f"endpoint_check: {ep_verdict} ({ep_host})")
    if ep_verdict == "POINTS_AT_THE_CONSUMER":
        res["verdict"] = "VOID_CREDENTIAL_POINTS_AT_CONSUMER"
        return res

    # --- provider side: this test's own share, granted to the existing
    #     TOKEN recipient. See the module docstring for why the
    #     recipient is reused rather than re-minted.
    status, payload = call(g_host, g_token, f"{UC}/shares", "POST",
                           {"name": SUB_SHARE,
                            "comment": "T-19 substitute ingress path"})
    made = step(res["steps"], "create_share", status, payload)
    pre = (not made and "already exists" in json.dumps(payload or {}).lower())
    if made or pre:
        register_created(SUB_SHARE)
        if pre:
            res["steps"]["create_share"]["verdict"] = "PERMITTED_PREEXISTING"
            print("    [ok ] create_share: PERMITTED_PREEXISTING "
                  "(adopted; corrects the line above)")
    if not (made or pre):
        res["verdict"] = "BLOCKED_AT_SHARE"
        return res

    status, payload = call(
        g_host, g_token, f"{UC}/shares/{SUB_SHARE}", "PATCH",
        {"updates": [{"action": "ADD",
                      "data_object": {"name": table_full,
                                      "data_object_type": "TABLE"}}]})
    added_ok = step(res["steps"], "add_table_to_share", status, payload)
    if not added_ok:
        # This step used to stop at the raw classification, and the run
        # of 2026-10-20 shows the cost: the evidence file recorded
        # add_table_to_share = REFUSED_UNCLASSIFIED for a table that
        # was demonstrably in the share -- 37 attributable rows were
        # read through it four steps later in the same run. A refusal
        # in an evidence record is a claim about the PLATFORM, and that
        # one would have carried into docs/12 as a Databricks refusal
        # when the real cause was this test re-adding its own object
        # (B-20, ours before theirs).
        #
        # Adoption is VERIFIED rather than matched on the message. "The
        # error says already exists" and "the object is in the share"
        # are different claims, and only the second one licenses the
        # read below.
        body = json.dumps(payload or {}).lower()
        cstatus, cpayload = call(
            g_host, g_token,
            f"{UC}/shares/{SUB_SHARE}?include_shared_data=true")
        listed = [str(o.get("name", "")).split(".")[-1]
                  for o in ((cpayload or {}).get("objects") or [])]
        leaf = table_full.split(".")[-1]
        res["steps"]["add_table_to_share"].update({
            "already_exists_in_body": "already" in body,
            "share_contents_readback_status": cstatus,
            "share_contents": listed,
            "object_present": leaf in listed,
        })
        if leaf in listed:
            res["steps"]["add_table_to_share"]["verdict"] = \
                "PERMITTED_PREEXISTING_VERIFIED"
            res["steps"]["add_table_to_share"]["means"] = (
                f"The ADD was refused because {leaf} was already in "
                f"this share from an earlier run, and the share's own "
                f"contents confirm it is there. Recorded as adopted on "
                f"the READBACK, not on the error text -- and corrected "
                f"on the console too, because the reader who decides "
                f"whether to stop the run is reading the console.")
            print(f"    [ok ] add_table_to_share: "
                  f"PERMITTED_PREEXISTING_VERIFIED "
                  f"(in share: {listed}; corrects the line above)")
        else:
            res["steps"]["add_table_to_share"]["means"] = (
                f"The ADD was refused ({status}) and {leaf} is NOT in "
                f"the share's contents ({listed}). This one is real: "
                f"the refusal stands and nothing downstream should be "
                f"read as sharing that table.")
            print(f"    [REF] add_table_to_share: refusal CONFIRMED by "
                  f"readback (in share: {listed})")

    status, payload = call(
        g_host, g_token, f"{UC}/shares/{SUB_SHARE}/permissions", "PATCH",
        {"changes": [{"principal": token_recipient, "add": ["SELECT"]}]})
    step(res["steps"], "grant_share_to_token_recipient", status, payload)
    res["steps"]["grant_share_to_token_recipient"]["recipient"] = \
        token_recipient
    res["steps"]["grant_share_to_token_recipient"]["provenance"] = (
        f"Recipient minted by scripts/19 --mint and activated by hand. "
        f"Re-minting is not scripted here: the activation URL is "
        f"single-use and human-opened. The credential on disk is "
        f"CORROBORATED as belonging to it by endpoint and token "
        f"fingerprint, not proven -- the claim the read rests on is "
        f"attributability of the DATA, below.")

    status, payload = call(
        g_host, g_token, f"{UC}/shares/{SUB_SHARE}/permissions")
    granted = {a.get("principal"): a.get("privileges")
               for a in ((payload or {}).get("privilege_assignments") or [])}
    res["steps"]["grant_readback"] = {
        "status": status,
        "privileges": granted.get(token_recipient),
        "verdict": ("GRANT_IN_EFFECT"
                    if "SELECT" in (granted.get(token_recipient) or [])
                    else "GRANT_NOT_IN_EFFECT"),
    }
    print(f"    [{'ok ' if res['steps']['grant_readback']['verdict'] == 'GRANT_IN_EFFECT' else 'REF'}] "
          f"grant_readback: {res['steps']['grant_readback']['verdict']}")

    # --- consumer side: §2.4.1 step 5a, 5b, 5c ------------------------
    status, payload = call(p_host, p_token, f"{UC}/providers", "POST", {
        "name": PROVIDER_NAME,
        "authentication_type": "TOKEN",
        "recipient_profile_str": json.dumps(profile),
        "comment": "T-19 substitute ingress path",
    })
    verdict, code, msg = classify(status, payload)
    already = (status in (400, 409)
               or "already exists" in f"{code} {msg}".lower())
    res["steps"]["import_provider"] = {
        "status": status,
        "verdict": "PERMITTED" if status in (200, 201) else verdict,
        "error_code": code, "message": redact(msg)[:400] or None}
    if status not in (200, 201):
        if "already exists" not in f"{code} {msg}".lower():
            print(f"    [REF] import_provider: {verdict} ({status}) "
                  f"{code} {redact(msg)[:160]}")
            res["verdict"] = "BLOCKED_AT_PROVIDER_IMPORT"
            return res
        # Adopting is not enough: a provider from an earlier run still
        # holds THAT run's credential, so the read would measure a
        # credential this test never loaded and a failure would be
        # unattributable. Push the current profile on first. Note the
        # platform returns 400 here, not 409 -- only the message match
        # catches it.
        ustatus, upayload = call(
            p_host, p_token, f"{UC}/providers/{PROVIDER_NAME}", "PATCH",
            {"recipient_profile_str": json.dumps(profile)})
        res["steps"]["import_provider"].update({
            "verdict": ("PERMITTED_PREEXISTING_UPDATED"
                        if ustatus in (200, 201)
                        else "PREEXISTING_UPDATE_REFUSED"),
            "update_status": ustatus,
            "means": ("Pre-existing provider refreshed with the "
                      "credential THIS run loaded, so the read below "
                      "goes through the file on disk."),
        })
        print(f"    [{'ok ' if ustatus in (200, 201) else 'REF'}] "
              f"import_provider: "
              f"{res['steps']['import_provider']['verdict']} "
              f"({status} -> update {ustatus})")
        if ustatus not in (200, 201):
            res["verdict"] = "BLOCKED_AT_PROVIDER_CREDENTIAL_UPDATE"
            return res
    else:
        print(f"    [ok ] import_provider: PERMITTED ({status})")

    status, payload = call(p_host, p_token,
                           f"{UC}/providers/{PROVIDER_NAME}/shares")
    shares = [sh.get("name") for sh in ((payload or {}).get("shares") or [])]
    res["steps"]["list_provider_shares"] = {
        "status": status, "shares": shares,
        "verdict": "SHARES_LISTED" if shares else "NO_SHARES",
        "means": ("§2.4.1's SHOW SHARES IN PROVIDER. Reaching this step "
                  "at all is the D-6 contrast: T-20's Path A created a "
                  "catalog over a provider it could never reach, and "
                  "Part 1 could not even produce the object to run this "
                  "against."),
    }
    print(f"    [{'ok ' if shares else 'REF'}] list_provider_shares: "
          f"{shares or 'none'}")
    if SUB_SHARE not in shares:
        res["verdict"] = "SUBSTITUTE_SHARE_NOT_VISIBLE"
        res["means"] = (
            f"{SUB_SHARE} was granted to {token_recipient} and does not "
            f"appear in that recipient's share list. Either the grant is "
            f"not in effect or the credential on disk belongs to a "
            f"different recipient -- the corroboration-not-proof limit "
            f"recorded above. Check grant_readback before anything else.")
        print(f"    [REF] {res['verdict']}")
        return res

    status, payload = call(p_host, p_token, f"{UC}/catalogs", "POST", {
        "name": CATALOG_NAME, "provider_name": PROVIDER_NAME,
        "share_name": SUB_SHARE})
    verdict, code, msg = classify(status, payload)
    already = (status in (400, 409)
               or "already exists" in f"{code} {msg}".lower())
    res["steps"]["create_catalog_from_share"] = {
        "status": status, "share": SUB_SHARE,
        "verdict": ("PERMITTED" if status in (200, 201)
                    else "PERMITTED_PREEXISTING"
                    if "already exists" in f"{code} {msg}".lower()
                    else verdict),
        "error_code": code, "message": redact(msg)[:400] or None}
    print(f"    [{'ok ' if 'PERMITTED' in res['steps']['create_catalog_from_share']['verdict'] else 'REF'}] "
          f"create_catalog_from_share: "
          f"{res['steps']['create_catalog_from_share']['verdict']} ({status})")
    if "PERMITTED" not in res["steps"]["create_catalog_from_share"]["verdict"]:
        res["verdict"] = "BLOCKED_AT_CATALOG"
        return res

    # --- the entitled read, attributable or it is nothing -------------
    parts = table_full.split(".")
    schema, table = (parts[1], parts[2]) if len(parts) == 3 else \
        ("opensharing_provider", "test_dataset")
    target = f"{CATALOG_NAME}.{schema}.{table}"
    res["shared_schema"] = schema

    wh = find_warehouse(p_host, p_token)
    if not wh:
        res["steps"]["entitled_read"] = {
            "verdict": NOT_RUN,
            "means": ("No SQL warehouse on the primary. The provider and "
                      "catalog exist, which is more than Part 1 reached, "
                      "but NO ROW CROSSED. NOT_RUN, not a pass.")}
        res["verdict"] = "CATALOG_CREATED_BUT_UNREAD"
        print("    [---] entitled_read: NOT_RUN (no warehouse)")
        return res
    res["warehouse_id"] = wh

    stmt = (f"SELECT count(*) AS n, "
            f"count(DISTINCT origin_metastore) AS origins, "
            f"min(origin_metastore) AS origin FROM {target}")
    rows, raw = run_sql(p_host, p_token, wh, stmt)
    res["steps"]["entitled_read"] = {"statement": stmt, "target": target,
                                     "raw": raw}
    if rows is None:
        res["steps"]["entitled_read"]["verdict"] = "READ_REFUSED"
        res["verdict"] = "BLOCKED_AT_READ"
        print(f"    [REF] entitled_read: REFUSED -- {raw}")
        return res

    n = int(rows[0][0]) if rows and rows[0][0] is not None else None
    origins = int(rows[0][1]) if rows and rows[0][1] is not None else None
    origin = rows[0][2] if rows else None
    count_ok = n == fixture["row_count"]
    origin_ok = origin == fixture["origin_metastore"]
    res["steps"]["entitled_read"].update({
        "row_count": n, "distinct_origins": origins,
        "origin_metastore": origin,
        "row_count_matches_fixture": count_ok,
        "origin_matches_glovashu": origin_ok,
        "verdict": ("READ_ATTRIBUTABLE_TO_GLOVASHU" if count_ok and origin_ok
                    else "READ_SUCCEEDED_BUT_NOT_ATTRIBUTABLE"),
        "means": (f"The fixture holds {fixture['row_count']} rows -- "
                  f"deliberately a different count from the primary's own "
                  f"test_dataset -- each stamped "
                  f"{fixture['origin_metastore']}. Matching BOTH is what "
                  f"separates reading ACROSS the boundary from reading a "
                  f"local table of the same name. Matching one or neither "
                  f"is a defect or a misdirected provider, not a pass."),
    })
    print(f"    [{'ok ' if count_ok and origin_ok else 'REF'}] "
          f"entitled_read: n={n} (expected {fixture['row_count']}) "
          f"origins={origins} origin={origin}")
    print(f"          {res['steps']['entitled_read']['verdict']}")

    res["verdict"] = ("SUBSTITUTE_INGRESS_WORKS" if count_ok and origin_ok
                      else "SUBSTITUTE_INGRESS_UNATTRIBUTABLE")
    print(f"    PART 2 VERDICT: {res['verdict']}")
    return res


# =====================================================================
# PART 3A -- denial by object scope
# =====================================================================

def part3a_denial_object(s, part2, fixture):
    """A table the provider owns and did NOT share must not be readable.

    The control is what makes this a test rather than an anecdote: the
    SAME catalog, the SAME schema, the SAME statement shape already
    returned rows in Part 2. So the only variable between the success
    and the refusal is whether the object is inside the share. Without
    that pairing, a refusal here is equally well explained by a typo.
    """
    res = {"steps": {}}
    g_host, g_token = s["g_host"], s["g_token"]
    p_host, p_token = s["p_host"], s["p_token"]
    print("\nPART 3A -- denial: an object outside the share")
    print("-" * 68)

    if part2.get("verdict") != "SUBSTITUTE_INGRESS_WORKS":
        res["verdict"] = NOT_RUN
        res["means"] = (
            f"Part 2 ended {part2.get('verdict')!r}, so there is no "
            f"positive control to pair a refusal against. A refusal "
            f"recorded without its control is the silent negative "
            f"(§12.9): it looks like default-deny working and is equally "
            f"consistent with a broken read.")
        print(f"    [---] {res['verdict']} -- no positive control")
        return res

    parts = fixture["table_full_name"].split(".")
    cat, schema = parts[0], parts[1]
    unshared = f"{cat}.{schema}.{DENIED_TABLE}"

    g_wh = find_warehouse(g_host, g_token)
    if not g_wh:
        res["verdict"] = NOT_RUN
        res["means"] = ("No SQL warehouse on glovashu, so the unshared "
                        "control table could not be created.")
        print(f"    [---] {res['verdict']} (no glovashu warehouse)")
        return res

    rows, raw = run_sql(g_host, g_token, g_wh,
                        f"CREATE TABLE IF NOT EXISTS {unshared} "
                        f"(id INT, note STRING) USING DELTA")
    res["steps"]["create_unshared_table"] = {
        "target": unshared, "raw": raw,
        "verdict": "CREATED" if rows is not None else "CREATE_REFUSED"}
    if rows is None:
        res["verdict"] = NOT_RUN
        res["means"] = ("Could not create the unshared control table on "
                        "the provider, so there is nothing to be denied.")
        print(f"    [---] {res['verdict']}: {raw}")
        return res
    run_sql(g_host, g_token, g_wh,
            f"INSERT INTO {unshared} VALUES (1, 'must never cross')")
    print(f"    [ok ] created {unshared} on glovashu, NOT added to any share")

    # Confirm it really is outside the share, rather than trusting that
    # we never added it. An assumption about the subject of a refusal is
    # the thing most worth checking.
    status, payload = call(g_host, g_token,
                           f"{UC}/shares/{SUB_SHARE}?include_shared_data=true")
    in_share = [o.get("name") for o in ((payload or {}).get("objects") or [])]
    res["steps"]["share_contents_confirm"] = {
        "objects": in_share,
        "unshared_table_absent": unshared not in in_share,
        "verdict": ("CONFIRMED_OUTSIDE_SHARE" if unshared not in in_share
                    else "TABLE_IS_ACTUALLY_SHARED"),
        "means": ("Reads the share's contents back to confirm the subject "
                  "of the refusal is genuinely outside it. If it IS in "
                  "the share, a refusal below is a bug, not default-deny."),
    }
    print(f"    [{'ok ' if unshared not in in_share else 'REF'}] "
          f"share_contents_confirm: "
          f"{res['steps']['share_contents_confirm']['verdict']}")
    if unshared in in_share:
        res["verdict"] = "VOID_SUBJECT_IS_SHARED"
        return res

    target = f"{CATALOG_NAME}.{part2.get('shared_schema', schema)}." \
             f"{DENIED_TABLE}"
    stmt = f"SELECT count(*) AS n FROM {target}"
    rows, raw = run_sql(p_host, p_token, part2["warehouse_id"], stmt)
    refused = rows is None
    res["steps"]["read_unshared_through_catalog"] = {
        "statement": stmt, "target": target, "raw": raw,
        "rows_returned": None if refused else rows,
        "verdict": "REFUSED" if refused else "READ_SUCCEEDED_UNEXPECTEDLY"}
    print(f"    [{'ok ' if refused else 'REF'}] "
          f"read_unshared_through_catalog: "
          f"{res['steps']['read_unshared_through_catalog']['verdict']}")

    control = (part2.get("steps", {}).get("entitled_read", {}) or {})
    res["paired_control"] = {
        "shared_object_read": control.get("verdict"),
        "shared_object_rows": control.get("row_count"),
        "unshared_object_read": res["steps"][
            "read_unshared_through_catalog"]["verdict"],
        "single_variable": ("membership of the share; same catalog, same "
                            "schema, same statement shape, same "
                            "warehouse, same credential"),
    }
    res["verdict"] = ("DENIAL_A_DEMONSTRATED" if refused
                      else "DENIAL_A_FAILED_OBJECT_LEAKED")
    res["means"] = (
        "A table the provider owns but did not share is unreadable "
        "through the shared catalog, while a shared table in the same "
        "schema reads. Share membership is therefore an enforced "
        "boundary and not a listing convention -- which is what AC3's "
        "purpose-limitation control rests on."
        if refused else
        "AN UNSHARED TABLE WAS READ. This is a leak and outranks every "
        "other result in this file. Stop and investigate before "
        "reporting any part of T-19.")
    print(f"    PART 3A VERDICT: {res['verdict']}")
    return res


# =====================================================================
# PART 3B -- denial by identity, and the route left unexhausted
# =====================================================================

def part3b_denial_identity(s, part2, gates, poll_seconds, poll_interval,
                           fresh=False):
    """Probe 15 reported IDENTITY_WITHOUT_CREDENTIAL. Its own evidence
    named the route it had not tried, so try it.

    The chain is: grant the service principal CAN_USE on tokens, mint an
    on-behalf-of token for it, give it warehouse access ONLY, then read
    the shared catalog twice -- once with no catalog grant (expect
    refused) and once with SELECT (expect rows). Two states, one
    variable: the grant.

    The refusal is taken FIRST. Granting and then revoking leaves a
    window where a cached entitlement could carry the earlier state, and
    the order default-deny-then-grant is also the order the CONOPS
    procedure actually runs in.

    If any link refuses, this stays NOT_RUN with the specific link
    named. What it must NOT do is substitute our own identity with a
    narrower grant and call that a denied group -- that is defect D-2,
    and probe 15's evidence says so in as many words.
    """
    res = {"steps": {}}
    p_host, p_token = s["p_host"], s["p_token"]
    print("\nPART 3B -- denial: a second identity with no grant")
    print("-" * 68)

    if part2.get("verdict") != "SUBSTITUTE_INGRESS_WORKS":
        res["verdict"] = NOT_RUN
        res["means"] = ("No readable shared catalog to be denied access "
                        "to. See Part 2.")
        print(f"    [---] {res['verdict']}")
        return res

    res["prior_finding"] = {
        "verdict": gates["second_identity"]["verdict"],
        "source": gates["second_identity"]["source"],
        "unexhausted_routes": gates["second_identity"]["unexhausted_routes"],
        "means": ("Probe 15 created a service principal and was refused "
                  "a token for it: PERMISSION_DENIED, 'does not have "
                  "permission to use tokens'. That refusal is about an "
                  "ACL this test can set, so the prior NOT_RUN was "
                  "bounded by what the probe tried, not by the tier."),
    }

    # The principal. Reused by default so the account does not
    # accumulate one per run -- but reuse is what carried a crashed
    # run's grants into the next run and produced a false leak alarm,
    # so --fresh-principal makes the ungranted state true BY
    # CONSTRUCTION rather than by cleanup. The reused path now proves
    # its state instead (see ungranted_state_verified); the fresh path
    # is the decisive instrument when that proof is what is in doubt.
    sp_display = (f"{SP_DISPLAY}_{int(time.time())}" if fresh
                  else SP_DISPLAY)
    app_id = (((gates.get("second_identity") or {}).get("application_id"))
              or None)
    status, payload = call(p_host, p_token,
                           "/api/2.0/preview/scim/v2/ServicePrincipals")
    existing = {r.get("displayName"): r
                for r in ((payload or {}).get("Resources") or [])}
    sp = None if fresh else existing.get(sp_display)
    if sp is None:
        status, payload = call(
            p_host, p_token, "/api/2.0/preview/scim/v2/ServicePrincipals",
            "POST", {"displayName": sp_display,
                     "schemas": ["urn:ietf:params:scim:schemas:core:2.0:"
                                 "ServicePrincipal"]})
        ok = status in (200, 201)
        res["steps"]["create_principal"] = {
            "status": status,
            "verdict": "PERMITTED" if ok else classify(status, payload)[0]}
        sp = payload if ok else None
    else:
        res["steps"]["create_principal"] = {
            "status": 200, "verdict": "PERMITTED_PREEXISTING"}
    if not sp:
        res["verdict"] = NOT_RUN
        res["blocked_at"] = "create_principal"
        res["means"] = ("Could not obtain a second service principal, so "
                        "there is no second identity to deny.")
        print(f"    [---] {res['verdict']} (blocked at create_principal)")
        return res
    app_id = sp.get("applicationId") or app_id
    sp_id = sp.get("id")
    res["principal"] = {"display_name": sp_display, "application_id": app_id,
                        "scim_id": sp_id,
                        "fresh_this_run": bool(fresh),
                        "provenance": (
                            "Created for this run and never granted "
                            "anything before it, so the ungranted state "
                            "is structural." if fresh else
                            "Reused across runs; its ungranted state is "
                            "MEASURED below rather than assumed.")}
    print(f"    [ok ] principal: {sp_display} ({app_id})"
          f"{' [fresh]' if fresh else ''}")

    # Route 1 of the two probe 15 left open: the token ACL.
    status, payload = call(
        p_host, p_token, "/api/2.0/permissions/authorization/tokens",
        "PATCH", {"access_control_list": [
            {"service_principal_name": app_id,
             "permission_level": "CAN_USE"}]})
    acl_ok = status in (200, 201)
    res["steps"]["token_acl_grant"] = {
        "status": status,
        "endpoint": "/api/2.0/permissions/authorization/tokens",
        "verdict": "PERMITTED" if acl_ok else classify(status, payload)[0],
        "message": redact(json.dumps(payload or {}))[:300] if not acl_ok
                   else None,
        "means": ("This is the route probe 15 recorded as untried. The "
                  "403 it hit was an ACL refusal, and an ACL is "
                  "configuration, not a tier ceiling -- B-18's "
                  "distinction, which is exactly the one that turns an "
                  "untestable half into a testable one."),
    }
    print(f"    [{'ok ' if acl_ok else 'REF'}] token_acl_grant: "
          f"{res['steps']['token_acl_grant']['verdict']} ({status})")

    sp_token = None
    if acl_ok:
        status, payload = call(
            p_host, p_token,
            "/api/2.0/token-management/on-behalf-of/tokens", "POST",
            {"application_id": app_id, "lifetime_seconds": 1800,
             "comment": "T-19 denial (B) -- 30 min, revoked at end of run"})
        minted = status in (200, 201)
        sp_token = ((payload or {}).get("token_value") if minted else None)
        res["steps"]["mint_obo_token"] = {
            "status": status,
            "verdict": "PERMITTED" if minted else classify(status, payload)[0],
            "lifetime_seconds": 1800,
            "token_fingerprint": fingerprint(sp_token) if sp_token else None,
            "token_id": ((payload or {}).get("token_info") or {}).get(
                "token_id") if minted else None,
            "message": (redact(json.dumps(payload or {}))[:300]
                        if not minted else None),
            "means": ("The token VALUE is never recorded -- only a "
                      "sha256 prefix, so a reader can tell two runs "
                      "apart without holding a credential. 30-minute "
                      "lifetime and revoked below, because a long-lived "
                      "token minted by a test is R4 made worse by us."),
        }
        print(f"    [{'ok ' if minted else 'REF'}] mint_obo_token: "
              f"{res['steps']['mint_obo_token']['verdict']} ({status})")
    if not sp_token:
        res["verdict"] = NOT_RUN
        res["blocked_at"] = ("token_acl_grant" if not acl_ok
                             else "mint_obo_token")
        res["routes_now_exhausted"] = ["workspace PAT for the principal",
                                       "token ACL + on-behalf-of mint"]
        res["routes_still_open"] = ["account-level OAuth M2M secret "
                                    "(accounts.cloud.databricks.com; .env "
                                    "holds workspace tokens only)"]
        res["means"] = (
            f"Blocked at {res['blocked_at']}. Denial (B) stays NOT_RUN "
            f"with the cause named, and the route list above is now one "
            f"shorter than probe 15 left it. Do NOT substitute our own "
            f"identity with a narrower grant and call it a denied group "
            f"-- that is defect D-2.")
        print(f"    [---] PART 3B VERDICT: {res['verdict']} "
              f"(blocked at {res['blocked_at']})")
        return res

    # --- crash-safe restore -------------------------------------------
    # The third run crashed in the revert loop at the END of this
    # function, which left this principal holding every grant the run
    # had applied. The run after it then read the shared catalog with no
    # grant of its own and reported an ACCESS CONTROL LEAK. The leak was
    # our own uncleaned state, and nothing in the file could tell the
    # two apart.
    #
    # So the restore is registered the moment the credential exists,
    # not written at the bottom of the happy path. A test that can only
    # clean up when it succeeds leaves its worst runs behind, and the
    # state it leaves is indistinguishable from the finding it is
    # looking for.
    restore = {"done": False, "token_id": None, "grants": []}

    def _restore():
        if restore["done"]:
            return
        restore["done"] = True
        for securable, full_name, privs in restore["grants"]:
            call(p_host, p_token,
                 f"{UC}/permissions/{securable}/{full_name}", "PATCH",
                 {"changes": [{"principal": app_id, "remove": privs}]})
        if restore["token_id"]:
            call(p_host, p_token,
                 f"/api/2.0/token-management/tokens/{restore['token_id']}",
                 "DELETE")
    atexit.register(_restore)
    restore["token_id"] = (res["steps"].get("mint_obo_token")
                           or {}).get("token_id")

    wh = part2["warehouse_id"]
    status, payload = call(
        p_host, p_token, f"/api/2.0/permissions/warehouses/{wh}", "PATCH",
        {"access_control_list": [{"service_principal_name": app_id,
                                  "permission_level": "CAN_USE"}]})
    res["steps"]["warehouse_grant"] = {
        "status": status,
        "verdict": "PERMITTED" if status in (200, 201)
                   else classify(status, payload)[0],
        "means": ("Compute access ONLY. Granted before either read so "
                  "that the two states below differ in the CATALOG grant "
                  "and nothing else. Without this, a refusal would be "
                  "equally explained by having no warehouse."),
    }
    print(f"    [{'ok ' if status in (200, 201) else 'REF'}] "
          f"warehouse_grant: {res['steps']['warehouse_grant']['verdict']}")

    # --- workspace entitlement, the other constant --------------------
    # CAN_USE on a warehouse is an ACL on an object. ENTITLEMENT is a
    # separate thing: a principal with no workspace-access cannot call
    # the SQL execution API at all, and what it gets back is 403 with an
    # empty body -- the same shape as a UC authorisation refusal. The
    # second run returned exactly that, which means the ungranted read
    # and the granted read could BOTH have been refused for a reason
    # that has nothing to do with grants, and nothing in the output
    # would have said so.
    #
    # Entitlements are therefore set BEFORE either read and held
    # constant across both, like the warehouse grant. They are read back
    # too, because this is the point in the file where an unverified 200
    # has already cost two runs.
    ent_want = ["workspace-access", "databricks-sql-access"]
    estatus, epayload = call(
        p_host, p_token,
        f"/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}")
    before = [e.get("value") for e in ((epayload or {}).get("entitlements")
                                       or [])]
    missing = [e for e in ent_want if e not in before]
    pstatus = None
    if missing:
        pstatus, _ = call(
            p_host, p_token,
            f"/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}", "PATCH",
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "add", "path": "entitlements",
                             "value": [{"value": e} for e in missing]}]})
    rstatus, rpayload = call(
        p_host, p_token,
        f"/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}")
    after = [e.get("value") for e in ((rpayload or {}).get("entitlements")
                                      or [])]
    res["steps"]["principal_entitlements"] = {
        "wanted": ent_want,
        "before": before,
        "missing_before": missing,
        "patch_status": pstatus,
        "after": after,
        "readback_status": rstatus,
        "verdict": ("ENTITLED" if all(e in after for e in ent_want)
                    else "NOT_ENTITLED"),
        "means": ("A principal without workspace-access is refused the "
                  "SQL execution API with 403 and an empty error body -- "
                  "indistinguishable from a UC denial. Held constant "
                  "across both reads so the only variable between them "
                  "stays the catalog grant. NOT_ENTITLED here means the "
                  "two reads below measure entitlement, not grants, and "
                  "neither one is a denial result."),
    }
    entitled = res["steps"]["principal_entitlements"]["verdict"] == "ENTITLED"
    print(f"    [{'ok ' if entitled else 'REF'}] principal_entitlements: "
          f"{res['steps']['principal_entitlements']['verdict']} "
          f"(before={before or 'none'} -> after={after or 'none'})")

    target = (part2.get("steps", {}).get("entitled_read", {}) or {}).get(
        "target")
    stmt = f"SELECT count(*) AS n FROM {target}"
    schema_full = f"{CATALOG_NAME}.{part2.get('shared_schema')}"
    LEVELS = [("catalog", CATALOG_NAME), ("schema", schema_full),
              ("table", target)]

    # --- the ungranted state is MEASURED, not assumed -----------------
    # This is the control the first three runs did not have. "Read
    # without grant" named an ASSUMPTION about this principal, and the
    # fourth run showed what that costs: the principal still held every
    # privilege a crashed earlier run had applied, so the "ungranted"
    # read was not ungranted, and the test reported FAIL_ACCESS_CONTROL
    # _LEAK against Databricks for our own dirt. B-20, ours before
    # theirs, aimed straight at the strongest claim this test can make.
    #
    # Two things are therefore established before the read, and both
    # are recorded as fields rather than trusted:
    #   1. the principal holds NO explicit privilege at any of the three
    #      levels -- and if it does, they are revoked and re-read;
    #   2. what its GROUPS hold, because a privilege inherited through
    #      'account users' produces a successful read that no
    #      principal-filtered query would ever show.
    groups = [g.get("display") or g.get("value")
              for g in ((rpayload or {}).get("groups") or [])]
    group_set = set(g for g in groups if g) | {"account users", "users"}

    def explicit(securable, full_name):
        _st, pay = call(
            p_host, p_token,
            f"{UC}/permissions/{securable}/{full_name}?principal={app_id}")
        for a in ((pay or {}).get("privilege_assignments") or []):
            if a.get("principal") == app_id:
                return a.get("privileges") or []
        return []

    prestate = {}
    for securable, full_name in LEVELS:
        held = explicit(securable, full_name)
        revoked, after_revoke = None, held
        if held:
            call(p_host, p_token,
                 f"{UC}/permissions/{securable}/{full_name}", "PATCH",
                 {"changes": [{"principal": app_id, "remove": held}]})
            after_revoke = explicit(securable, full_name)
            revoked = not after_revoke
        _ast, apay = call(p_host, p_token,
                          f"{UC}/permissions/{securable}/{full_name}")
        all_assign = {a.get("principal"): (a.get("privileges") or [])
                      for a in ((apay or {}).get("privilege_assignments")
                                or [])}
        prestate[securable] = {
            "held_before": held,
            "revoke_attempted": bool(held),
            "revoke_succeeded": revoked,
            "held_after_revoke": after_revoke,
            "all_principals_with_privileges": all_assign,
            "inherited_via_groups": {p: v for p, v in all_assign.items()
                                     if p in group_set},
        }
    clean = all(not v["held_after_revoke"] for v in prestate.values())
    inheritance = {s: v["inherited_via_groups"] for s, v in prestate.items()
                   if v["inherited_via_groups"]}
    res["steps"]["ungranted_state_verified"] = {
        "principal_groups": groups,
        "groups_considered": sorted(group_set),
        "levels": prestate,
        "explicit_privileges_clean": clean,
        "inheritance_candidates": inheritance,
        "verdict": ("UNGRANTED_CONFIRMED" if clean and not inheritance
                    else "UNGRANTED_WITH_GROUP_INHERITANCE" if clean
                    else "PRESTATE_DIRTY"),
        "means": ("The ungranted half of the pair, turned from an "
                  "assumption into a measurement. PRESTATE_DIRTY means "
                  "the principal still holds privileges that could not "
                  "be cleared, so the read below is not an ungranted "
                  "read and must not be graded as one. "
                  "UNGRANTED_WITH_GROUP_INHERITANCE means a group this "
                  "principal belongs to holds privileges on the "
                  "securable -- a successful read would then be the "
                  "grant model working as configured, which is a "
                  "finding about OUR configuration and not a platform "
                  "leak."),
    }
    print(f"    [{'ok ' if clean and not inheritance else 'REF'}] "
          f"ungranted_state_verified: "
          f"{res['steps']['ungranted_state_verified']['verdict']}")
    print(f"          groups={groups or 'none'} | held_before="
          f"{ {s: v['held_before'] for s, v in prestate.items()} }")
    if inheritance:
        print(f"          INHERITANCE CANDIDATES: {inheritance}")

    if not clean:
        res["verdict"] = "DENIAL_B_NOT_RUN_PRESTATE_DIRTY"
        res["blocked_at"] = "ungranted_state_verified"
        res["means"] = (
            f"This principal still holds explicit privileges that could "
            f"not be revoked: "
            f"{ {s: v['held_after_revoke'] for s, v in prestate.items() if v['held_after_revoke']} }"
            f". There is no ungranted state to read from, so neither "
            f"read below would mean anything. Clear them by hand, or "
            f"re-run with --fresh-principal, which creates a principal "
            f"that has never held a grant and makes the ungranted state "
            f"true by construction rather than by cleanup.")
        print(f"    [---] PART 3B VERDICT: {res['verdict']}")
        _restore()
        return res

    rows, raw = run_sql(p_host, sp_token, wh, stmt)
    denied = rows is None
    res["steps"]["read_without_grant"] = {
        "statement": stmt, "raw": raw,
        "rows_returned": None if denied else rows,
        "as_identity": app_id,
        "verdict": "REFUSED" if denied else "READ_SUCCEEDED_UNEXPECTEDLY",
        "means": ("Default deny, measured. T-20 could not demonstrate "
                  "this: its grants went to 'account users', which on "
                  "this tier is effectively everyone, so default deny "
                  "was asserted by the procedure rather than shown."),
    }
    print(f"    [{'ok ' if denied else 'REF'}] read_without_grant: "
          f"{res['steps']['read_without_grant']['verdict']}")
    if denied:
        # Printed, not just filed. The SHAPE of this refusal is what
        # the granted read has to be compared against, and the second
        # run filed it where nobody looked.
        print(f"          raw: {str(raw)[:300]}")
    raw_without = raw

    # --- the grant, at all three levels it needs ----------------------
    # The first run granted USE CATALOG and SELECT at catalog scope
    # only, and the granted read was still refused -- so the ungranted
    # refusal above became unattributable and the guard below correctly
    # declined to call it a denial.
    #
    # Unity Catalog traversal is not inherited downward from one grant:
    # reading a table needs USE CATALOG on the catalog, USE SCHEMA on
    # the schema, and SELECT on something that covers the table. Missing
    # USE SCHEMA refuses the read with the same shape as missing
    # everything, which is the silent negative one more time: the test
    # could not tell "default deny works" from "we under-granted".
    #
    # So all three are granted, each recorded separately, and each read
    # BACK before the read is attempted -- B-23, because a 200 on a
    # PATCH is not the grant.
    # SELECT at catalog scope already covers the table. The table-level
    # grant is belt and braces, and it is marked OPTIONAL because a
    # refusal on a Delta Sharing securable there would otherwise grade
    # the whole grant PARTIAL and make a working positive control look
    # broken -- B-26, a guard firing on the normal case.
    # SPELLING. The REST privilege enum is USE_CATALOG / USE_SCHEMA with
    # UNDERSCORES; the spaced form is SQL's GRANT syntax, not the API's.
    # The second run granted the spaced form, got 200 at every level,
    # and the readback showed NOT_IN_EFFECT at catalog and schema while
    # the table level -- whose only privilege was SELECT, spelled the
    # same in both dialects -- came back IN_EFFECT. So the API accepted
    # a privilege name it then discarded: a 200 that applied nothing,
    # which is precisely what the readback column was added to catch,
    # and it caught it on its first outing.
    #
    # Both spellings are attempted, underscore first, and BOTH results
    # are recorded. Not defensiveness: which spelling the API honours is
    # a behaviour this repo has to write down, because a 200 on the
    # wrong one is silent and every grant in the IaC tree will carry
    # whichever form we standardise on.
    SPELLINGS = {"USE_CATALOG": "USE CATALOG", "USE_SCHEMA": "USE SCHEMA"}
    grant_plan = [
        ("catalog", CATALOG_NAME, ["USE_CATALOG", "SELECT"], True),
        ("schema", schema_full, ["USE_SCHEMA"], True),
        ("table", target, ["SELECT"], False),
    ]
    grants = {}

    def apply_grant(securable, full_name, privs):
        status, payload = call(
            p_host, p_token, f"{UC}/permissions/{securable}/{full_name}",
            "PATCH", {"changes": [{"principal": app_id, "add": privs}]})
        rstatus, rpayload = call(
            p_host, p_token,
            f"{UC}/permissions/{securable}/{full_name}"
            f"?principal={app_id}")
        in_effect = []
        for a in ((rpayload or {}).get("privilege_assignments") or []):
            if a.get("principal") == app_id:
                in_effect = a.get("privileges") or []
        # Compare on BOTH dialects: a privilege returned as USE_CATALOG
        # satisfies a request for "USE CATALOG" and the reverse, so the
        # readback measures the entitlement rather than the string.
        def present(p):
            return (p in in_effect
                    or SPELLINGS.get(p, p) in in_effect
                    or p.replace(" ", "_") in in_effect)
        return {
            "requested": privs,
            "status": status,
            "verdict": ("PERMITTED" if status in (200, 201)
                        else classify(status, payload)[0]),
            "message": (redact(json.dumps(payload or {}))[:300]
                        if status not in (200, 201) else None),
            "readback_status": rstatus,
            "privileges_in_effect": in_effect,
            "readback_verdict": ("IN_EFFECT" if all(present(p) for p in privs)
                                 else "NOT_IN_EFFECT"),
        }

    for securable, full_name, privs, required in grant_plan:
        attempts = {"underscore": apply_grant(securable, full_name, privs)}
        chosen = attempts["underscore"]
        if chosen["readback_verdict"] != "IN_EFFECT":
            spaced = [SPELLINGS.get(p, p) for p in privs]
            if spaced != privs:
                attempts["spaced"] = apply_grant(securable, full_name,
                                                 spaced)
                if attempts["spaced"]["readback_verdict"] == "IN_EFFECT":
                    chosen = attempts["spaced"]
        # Recorded for the restore BEFORE anything can fail, in the
        # spelling actually requested at each attempt.
        for attempt in attempts.values():
            restore["grants"].append(
                (securable, full_name, attempt["requested"]))
        grants[securable] = dict(chosen)
        grants[securable].update({
            "securable": securable, "full_name": full_name,
            "required_for_traversal": required,
            "spelling_attempts": attempts,
            "spelling_honoured": ("underscore"
                                  if attempts["underscore"]
                                  ["readback_verdict"] == "IN_EFFECT"
                                  else "spaced"
                                  if (attempts.get("spaced") or {}).get(
                                      "readback_verdict") == "IN_EFFECT"
                                  else "NEITHER"),
        })
        print(f"    [{'ok ' if chosen['verdict'] == 'PERMITTED' else 'REF'}] "
              f"grant {securable} {'/'.join(privs)}"
              f"{'' if required else ' (optional)'}: "
              f"{chosen['verdict']} -> readback "
              f"{chosen['readback_verdict']} "
              f"(spelling={grants[securable]['spelling_honoured']}, "
              f"in_effect={chosen['privileges_in_effect']})")
    required_levels = [g for g in grants.values()
                       if g["required_for_traversal"]]
    res["steps"]["grant_catalog_to_principal"] = {
        "levels": grants,
        "verdict": ("PERMITTED"
                    if all(g["verdict"] == "PERMITTED"
                           for g in required_levels)
                    else "PARTIAL"),
        "all_in_effect": all(g["readback_verdict"] == "IN_EFFECT"
                             for g in required_levels),
        "api_privilege_spelling": {
            s: g["spelling_honoured"] for s, g in grants.items()},
        "means": ("Three levels because UC traversal needs three: USE "
                  "CATALOG, USE SCHEMA, and SELECT. The first run "
                  "granted catalog scope alone and the granted read was "
                  "refused -- a missing USE SCHEMA refuses identically "
                  "to a correct default deny, which is why that run "
                  "could not attribute its own refusal. The readback "
                  "column is what distinguishes an accepted grant from "
                  "an applied one; the first run had no such column, so "
                  "a 200 stood in for a fact (B-23). Verdict counts the "
                  "levels REQUIRED for traversal only. "
                  "api_privilege_spelling records which dialect the API "
                  "actually honoured at each level -- NEITHER there "
                  "means the grant never applied, whatever the status "
                  "said, and the read below cannot be read as a denial."),
    }

    # Propagation. A single read straight after a grant measures the
    # cache, not the entitlement. Bounded, so a refusal is reportable.
    t0 = time.time()
    g_deadline = t0 + min(poll_seconds, 120)
    g_polls, rows, raw = 0, None, None
    while True:
        g_polls += 1
        rows, raw = run_sql(p_host, sp_token, wh, stmt)
        if rows is not None:
            break
        if time.time() + poll_interval > g_deadline:
            break
        time.sleep(poll_interval)
    allowed = rows is not None
    res["steps"]["read_with_grant"] = {
        "statement": stmt, "raw": raw,
        "polls": g_polls,
        "waited_seconds": round(time.time() - t0, 1),
        "bound_seconds": min(poll_seconds, 120),
        "row_count": int(rows[0][0]) if allowed and rows and rows[0] else None,
        "verdict": "READ_SUCCEEDED" if allowed else "REFUSED",
        "means": ("The POSITIVE control. If the grant does not open the "
                  "read, the refusal above is unattributable: it could "
                  "be the grant model, the shared catalog, or the "
                  "principal's compute access, and we would not know "
                  "which. Polled rather than read once, so a refusal "
                  "here is not merely 'we asked too early'."),
    }
    print(f"    [{'ok ' if allowed else 'REF'}] read_with_grant: "
          f"{res['steps']['read_with_grant']['verdict']} after "
          f"{res['steps']['read_with_grant']['waited_seconds']}s / "
          f"{g_polls} poll(s)")
    if not allowed:
        print(f"          raw: {str(raw)[:300]}")
    # Two refusals of the same shape are one fact, not two. If the
    # ungranted and granted reads fail identically, the grant changed
    # nothing observable and the pair cannot support a denial claim --
    # which is a sharper statement than "unattributable" and is derived
    # from the fields rather than asserted (B-23b).
    def shape(r):
        r = r or {}
        return {"http_status": r.get("http_status"),
                "state": r.get("state"),
                "error": str(r.get("error"))[:120]}
    res["steps"]["refusal_comparison"] = {
        "without_grant": shape(raw_without),
        "with_grant": shape(raw),
        "identical": shape(raw_without) == shape(raw),
        "means": ("Identical refusal shapes mean the grant made no "
                  "observable difference, so the pair measures "
                  "something upstream of grants -- entitlement, "
                  "traversal, or the shared catalog -- and not default "
                  "deny. Different shapes narrow it. NOTE: identical "
                  "SUCCESS shapes are not a refusal comparison at all "
                  "-- read the verdict, which distinguishes them."),
    }

    # --- the spelling question, settled rather than inferred ----------
    # After the third run I wrote that the API "accepted the spaced
    # privilege name and discarded it". That was not in the fields. The
    # readback in that run compared the string "USE CATALOG" against a
    # response that may well have said "USE_CATALOG", so NOT_IN_EFFECT
    # was equally explained by a dialect mismatch in OUR comparison --
    # and a claim typed in advance of the evidence is B-23b, in a
    # message warning about B-23b. The claim is retracted, and this
    # probe is what replaces it.
    #
    # Three calls on one securable, after the experiment above so it
    # cannot contaminate it: clear the principal's catalog privileges,
    # add ONLY the spaced form, and read back what the API stored.
    for securable, full_name in [("catalog", CATALOG_NAME)]:
        held = explicit(securable, full_name)
        if held:
            call(p_host, p_token,
                 f"{UC}/permissions/{securable}/{full_name}", "PATCH",
                 {"changes": [{"principal": app_id, "remove": held}]})
        dstatus, dpayload = call(
            p_host, p_token, f"{UC}/permissions/{securable}/{full_name}",
            "PATCH", {"changes": [{"principal": app_id,
                                   "add": ["USE CATALOG"]}]})
        stored = explicit(securable, full_name)
        res["steps"]["api_privilege_dialect_probe"] = {
            "securable": f"{securable} {full_name}",
            "cleared_first": held,
            "requested": ["USE CATALOG"],
            "patch_status": dstatus,
            "patch_message": (redact(json.dumps(dpayload or {}))[:300]
                              if dstatus not in (200, 201) else None),
            "stored": stored,
            "verdict": (
                "SPACED_REJECTED" if dstatus not in (200, 201) else
                "SPACED_NORMALISED_TO_UNDERSCORE"
                if "USE_CATALOG" in stored else
                "SPACED_STORED_AS_IS" if "USE CATALOG" in stored else
                "SPACED_ACCEPTED_THEN_DISCARDED"),
            "means": ("Which privilege dialect the REST API honours is "
                      "not a T-19 question, it is an IaC question: "
                      "every GRANT in iac/ will carry one spelling, and "
                      "SPACED_ACCEPTED_THEN_DISCARDED would mean the "
                      "wrong one fails with a 200 and no message. "
                      "Measured here because this is the only place in "
                      "the repo with a live principal and a securable "
                      "to measure it on. Supersedes the unsupported "
                      "claim made after the third run (B-19: the claim "
                      "is labelled retracted, not deleted)."),
        }
        if stored:
            call(p_host, p_token,
                 f"{UC}/permissions/{securable}/{full_name}", "PATCH",
                 {"changes": [{"principal": app_id, "remove": stored}]})
        print(f"    [ok ] api_privilege_dialect_probe: "
              f"{res['steps']['api_privilege_dialect_probe']['verdict']} "
              f"(stored={stored})")
    if not allowed:
        print(f"          refusal shapes identical: "
              f"{res['steps']['refusal_comparison']['identical']}")

    # Put the principal back where it was. A test that leaves a granted
    # identity behind has changed the thing it measured. Reverse order,
    # so the narrow grants go before the traversal they hang off.
    for securable, full_name, privs, _required in reversed(grant_plan):
        call(p_host, p_token,
             f"{UC}/permissions/{securable}/{full_name}", "PATCH",
             {"changes": [{"principal": app_id, "remove": privs}]})
    # Verified, not assumed -- the whole reason this part was wrong
    # twice. What the principal holds AFTER the revert is recorded, so
    # the next run inherits a measured state instead of a hope.
    res["steps"]["post_revert_state"] = {
        s: explicit(s, f) for s, f in LEVELS}
    res["steps"]["post_revert_state"]["verdict"] = (
        "CLEAN" if not any(res["steps"]["post_revert_state"].get(s)
                           for s, _f in LEVELS) else "RESIDUAL_PRIVILEGES")
    print(f"    [{'ok ' if res['steps']['post_revert_state']['verdict'] == 'CLEAN' else 'REF'}] "
          f"post_revert_state: "
          f"{res['steps']['post_revert_state']['verdict']}")
    tid = (res["steps"].get("mint_obo_token") or {}).get("token_id")
    if tid:
        dstatus, _ = call(p_host, p_token,
                          f"/api/2.0/token-management/tokens/{tid}", "DELETE")
        res["steps"]["revoke_obo_token"] = {
            "status": dstatus,
            "verdict": "REVOKED" if dstatus in (200, 204) else "REVOKE_FAILED",
            "means": ("A test-minted credential outliving the test is R4 "
                      "made worse by us. If this says REVOKE_FAILED, "
                      "revoke it by hand -- the token id is recorded "
                      "above and the value was never stored.")}
        print(f"    [{'ok ' if dstatus in (200, 204) else 'REF'}] "
              f"revoke_obo_token: "
              f"{res['steps']['revoke_obo_token']['verdict']}")

    restore["done"] = True

    # Before grading the pair: two prerequisites can make BOTH reads
    # refuse for reasons that are ours, and each has its own verdict so
    # the next run is told what to fix instead of being told "it is
    # unattributable" for the third time.
    spelling = res["steps"]["grant_catalog_to_principal"][
        "api_privilege_spelling"]
    never_applied = [s for s, v in spelling.items() if v == "NEITHER"
                     and grants[s]["required_for_traversal"]]
    if denied and not allowed and not entitled:
        res["verdict"] = "DENIAL_B_NOT_RUN_PRINCIPAL_NOT_ENTITLED"
        res["blocked_at"] = "principal_entitlements"
        res["means"] = (
            f"Both reads refused AND the principal does not hold "
            f"{ent_want}. A principal that cannot call the SQL API at "
            f"all is refused with the same 403 as one that is denied by "
            f"UC, so this pair measures entitlement and says nothing "
            f"about grants. NOT a denial result and NOT merely "
            f"unattributable: the cause is named and it is fixable. "
            f"Entitlements observed after the PATCH: {after}.")
    elif denied and not allowed and never_applied:
        res["verdict"] = "DENIAL_B_NOT_RUN_GRANT_NEVER_APPLIED"
        res["blocked_at"] = f"grant_{'_and_'.join(never_applied)}"
        res["means"] = (
            f"Both reads refused AND the required grant(s) at "
            f"{never_applied} never took effect in either privilege "
            f"spelling, whatever the PATCH status said. There was no "
            f"second state, so there was no experiment. The spelling "
            f"attempts and the privileges actually in effect are "
            f"recorded under grant_catalog_to_principal.levels -- read "
            f"those, not the status codes.")
    elif denied and allowed:
        res["verdict"] = "DENIAL_B_DEMONSTRATED"
        res["means"] = (
            "A second, real identity was refused the shared catalog with "
            "no grant and served it with one. Two states, one variable. "
            "This closes the half probe 15 reported NOT_RUN under "
            "IDENTITY_WITHOUT_CREDENTIAL, and it demonstrates the "
            "default deny that T-20 could only assert. Carry the earlier "
            "NOT_RUN forward as superseded rather than deleting it "
            "(B-19): it was correct about the routes it had tried.")
    elif denied and not allowed:
        res["verdict"] = "DENIAL_B_UNATTRIBUTABLE_NO_POSITIVE_CONTROL"
        res["means"] = (
            f"The ungranted read was refused AND the granted read was "
            f"refused. The refusal therefore says nothing about grants. "
            f"Reported as unattributable rather than as a denial, "
            f"because a refusal for an unknown reason recorded as "
            f"default-deny is the silent negative with a flattering "
            f"label. What this run tried, so the next one does not "
            f"repeat it: USE CATALOG and SELECT on {CATALOG_NAME}, USE "
            f"SCHEMA on {schema_full}, SELECT on {target}, each read "
            f"back (all_in_effect="
            f"{res['steps']['grant_catalog_to_principal']['all_in_effect']}"
            f"), then the read polled for "
            f"{res['steps']['read_with_grant']['waited_seconds']}s. The "
            f"raw error is recorded under read_with_grant.raw -- read "
            f"THAT before changing the grant model again, because "
            f"guessing at the next privilege is how a grant model gets "
            f"three privileges it never needed.")
    elif not denied and inheritance:
        res["verdict"] = "DENIAL_B_UNGRANTED_READ_EXPLAINED_BY_INHERITANCE"
        res["means"] = (
            f"The principal read the shared catalog with no explicit "
            f"grant of its own, AND a group it belongs to holds "
            f"privileges on the securable: {inheritance}. That is our "
            f"grant model behaving as configured, not a platform leak. "
            f"It is still a finding and it still blocks a pass -- "
            f"'account users' holding privileges on a share-backed "
            f"catalog is exactly the purpose-limitation problem AC3 "
            f"exists to prevent, and T-20 asserted default deny while "
            f"granting to that same group. Fix the configuration, then "
            f"re-run for a clean denial result. Filed as a "
            f"CONFIGURATION finding, because filing it as a Databricks "
            f"leak would attribute our own grant to the platform "
            f"(B-20).")
    elif not denied:
        res["verdict"] = "DENIAL_B_FAILED_UNGRANTED_IDENTITY_READ"
        res["means"] = (
            f"AN UNGRANTED IDENTITY READ THE SHARED CATALOG, and the "
            f"two explanations that would make it ours are both "
            f"excluded by measurement: the principal held no explicit "
            f"privilege at catalog, schema or table level "
            f"(ungranted_state_verified = "
            f"{res['steps']['ungranted_state_verified']['verdict']}), "
            f"and no group it belongs to "
            f"({res['steps']['ungranted_state_verified']['principal_groups']}) "
            f"holds privileges on any of those securables. This "
            f"outranks everything else in the file. Before it is "
            f"reported outside this repo, check the remaining "
            f"instrument explanation by hand: whether this principal "
            f"carries workspace-admin or metastore-admin, which no "
            f"privilege query would show. A leak claim against the "
            f"platform is the single most expensive thing this test can "
            f"get wrong (B-20).")
    else:
        res["verdict"] = "DENIAL_B_INCONCLUSIVE"
    print(f"    PART 3B VERDICT: {res['verdict']}")
    return res


# =====================================================================
# PART 4 -- refresh behaviour, measured at two levels
# =====================================================================

def part4_refresh(s, part2, fixture, poll_seconds, poll_interval):
    """§2.4.1 asks for refresh behaviour. There are TWO refresh
    questions and they are not the same question.

      object visibility -- a table newly ADDED to the share: when does
          it appear inside the consumer's shared catalog?
      row visibility   -- rows newly INSERTED into an already-shared
          table: when does the consumer's read see them?

    Collapsing them would produce one number that answers neither. A
    consumer whose share membership updates instantly but whose row
    reads lag is in a completely different operational position from
    the reverse, and §2.4.4's landing-and-validation design depends on
    which it is.

    The fixture table is deliberately NOT mutated. Its 37 rows and
    origin stamp are the attributability basis for every read in this
    repo; appending to it would make this test the reason a later run
    cannot tell a shared read from a local one.
    """
    res = {"questions": ["object_visibility", "row_visibility"], "steps": {}}
    g_host, g_token = s["g_host"], s["g_token"]
    p_host, p_token = s["p_host"], s["p_token"]
    print("\nPART 4 -- refresh behaviour (§2.4.1, D2D and D2O columns)")
    print("-" * 68)

    if part2.get("verdict") != "SUBSTITUTE_INGRESS_WORKS":
        res["verdict"] = NOT_RUN
        res["means"] = ("No working consumer-side read to measure refresh "
                        "against. See Part 2.")
        print(f"    [---] {res['verdict']}")
        return res

    parts = fixture["table_full_name"].split(".")
    cat, schema = parts[0], parts[1]
    # A per-run name, and the reason is the previous run's result.
    #
    # Run 3 reused the fixed REFRESH_TABLE name. The share-membership
    # PATCH came back RESOURCE_ALREADY_EXISTS -- because run 1 had put
    # that table in the share -- and the code treated "already" as
    # added and started the stopwatch anyway. The 5.3s it then printed
    # as object_visibility was the time taken to SELECT from an object
    # that had been in the consumer's catalog since the first run. That
    # is not a refresh latency. It was reported in the same field, the
    # same units and the same [ok ] as one, which is the worse half of
    # the defect: §2.4.4's landing design would have been sized off it.
    #
    # A unique name makes the membership new, which is the only state
    # in which "time to appear" is a measurement rather than a
    # restatement of how fast a warehouse answers a count(*).
    refresh_table = f"{REFRESH_TABLE}_{int(time.time())}"
    src = f"{cat}.{schema}.{refresh_table}"
    g_wh = find_warehouse(g_host, g_token)
    p_wh = part2["warehouse_id"]
    if not g_wh:
        res["verdict"] = NOT_RUN
        res["means"] = "No SQL warehouse on glovashu to mutate from."
        print(f"    [---] {res['verdict']}")
        return res

    origin = fixture["origin_metastore"]
    rows, raw = run_sql(g_host, g_token, g_wh,
                        f"CREATE TABLE IF NOT EXISTS {src} "
                        f"(id INT, batch INT, origin_metastore STRING) "
                        f"USING DELTA")
    if rows is None:
        res["verdict"] = NOT_RUN
        res["means"] = f"Could not create {src} on the provider: {raw}"
        print(f"    [---] {res['verdict']}")
        return res
    run_sql(g_host, g_token, g_wh, f"DELETE FROM {src}")
    run_sql(g_host, g_token, g_wh,
            f"INSERT INTO {src} SELECT id, 1, '{origin}' "
            f"FROM range(5)")
    rows, _ = run_sql(g_host, g_token, g_wh,
                      f"SELECT count(*) FROM {src}")
    baseline_rows = int(rows[0][0]) if rows else None
    res["steps"]["provider_seed"] = {
        "target": src, "batch": 1, "rows": baseline_rows,
        "stamped": origin,
        "means": ("A dedicated refresh table. The 37-row fixture is NOT "
                  "touched: it is the attributability basis for every "
                  "read in this repo and a test that erodes its own "
                  "control is worse than no test."),
    }
    print(f"    [ok ] seeded {src} batch 1 -> {baseline_rows} rows")

    # --- carry-forward: run 1's bounded negative, re-read -------------
    # Run 1 added REFRESH_TABLE to the share and could not read it
    # through the consumer's catalog within 170.8s. That object is
    # still in the share and the catalog has never been dropped since
    # (Part 2 adopts it: PERMITTED_PREEXISTING). So one SELECT, right
    # now, extends that same bounded negative from 170.8s to days --
    # and days is the number §2.4.1 cares about, because it is the gap
    # between "slow" and "never on this catalog".
    #
    # Readability on its own would NOT settle it. If the catalog was
    # created AFTER the object joined the share, then a snapshot-at-
    # create catalog is also readable, and the two hypotheses predict
    # the identical SELECT. So the ordering is measured, not assumed:
    # the share's added_at for that object against the catalog's
    # created_at. Readability is evidence of post-create refresh only
    # when the object was added after the catalog existed.
    shared_schema = part2.get("shared_schema", schema)
    sh_status, sh_payload = call(
        g_host, g_token,
        f"{UC}/shares/{SUB_SHARE}?include_shared_data=true")
    c_status, c_payload = call(p_host, p_token,
                               f"{UC}/catalogs/{CATALOG_NAME}")
    created_at = (c_payload or {}).get("created_at")

    # Every refresh probe in the share is a candidate, not just the
    # fixed-name one: a previous run that ended NOT_VISIBLE leaves its
    # unique probe behind precisely so this read can pick it up. The
    # most useful candidate is the OLDEST object added AFTER the
    # catalog was created, because that is the one whose absence or
    # presence cannot be explained by the catalog being newer than it.
    cands = []
    for obj in ((sh_payload or {}).get("objects") or []):
        leaf = str(obj.get("name", "")).split(".")[-1]
        if leaf == REFRESH_TABLE or leaf.startswith(f"{REFRESH_TABLE}_"):
            cands.append({"leaf": leaf, "added_at": obj.get("added_at")})
    after = [c for c in cands
             if c["added_at"] and created_at
             and int(c["added_at"]) > int(created_at)]
    chosen = (min(after, key=lambda c: int(c["added_at"])) if after
              else min((c for c in cands if c["added_at"]),
                       key=lambda c: int(c["added_at"]), default=None)
              or {"leaf": REFRESH_TABLE, "added_at": None})
    standing = f"{CATALOG_NAME}.{shared_schema}.{chosen['leaf']}"
    added_at = chosen["added_at"]
    srows, sraw = run_sql(p_host, p_token, p_wh,
                          f"SELECT count(*) FROM {standing}")
    standing_readable = bool(srows and srows[0] and srows[0][0] is not None)

    # Does the object still exist on the PROVIDER? A share can carry a
    # membership entry for a table someone has since dropped, and the
    # consumer's read then fails for a reason that has nothing to do
    # with refresh. Reporting that as "still not visible after days"
    # would publish our own housekeeping as snapshot-at-create
    # behaviour in the platform -- ours before theirs (B-20).
    prov_rows, prov_raw = run_sql(
        g_host, g_token, g_wh,
        f"SELECT count(*) FROM {cat}.{schema}.{chosen['leaf']}")
    provider_side_exists = bool(prov_rows and prov_rows[0]
                                and prov_rows[0][0] is not None)

    if added_at and created_at:
        ordering = ("OBJECT_ADDED_AFTER_CATALOG_CREATED"
                    if int(added_at) > int(created_at)
                    else "OBJECT_ADDED_BEFORE_CATALOG_CREATED")
    else:
        ordering = "ORDERING_UNKNOWN"
    age_hours = (round((time.time() * 1000 - int(added_at)) / 3_600_000, 1)
                 if added_at else None)

    if standing_readable and ordering == "OBJECT_ADDED_AFTER_CATALOG_CREATED":
        cf_verdict = "STANDING_OBJECT_NOW_READABLE_CATALOG_DOES_REFRESH"
    elif standing_readable and ordering == "OBJECT_ADDED_BEFORE_CATALOG_CREATED":
        cf_verdict = "READABLE_BUT_CATALOG_IS_NEWER_PROVES_NOTHING"
    elif standing_readable:
        cf_verdict = "READABLE_ORDERING_UNKNOWN_NOT_EVIDENCE"
    elif not provider_side_exists:
        cf_verdict = "NOT_READABLE_BUT_SOURCE_TABLE_GONE_UNATTRIBUTABLE"
    elif ordering == "OBJECT_ADDED_AFTER_CATALOG_CREATED":
        cf_verdict = "STILL_NOT_READABLE_NEGATIVE_EXTENDED"
    else:
        cf_verdict = "NOT_READABLE_ORDERING_UNKNOWN"
    res["steps"]["carry_forward_prior_probe"] = {
        "object": standing,
        "candidates_in_share": cands,
        "candidates_added_after_catalog": [c["leaf"] for c in after],
        "chosen_because": ("oldest object added after the catalog was "
                           "created" if after else
                           "no candidate was added after the catalog was "
                           "created -- this read cannot discriminate"),
        "readable_now": standing_readable,
        "rows": (int(srows[0][0]) if standing_readable else None),
        "provider_side_exists": provider_side_exists,
        "provider_side_raw": None if provider_side_exists else prov_raw,
        "share_added_at": added_at,
        "catalog_created_at": created_at,
        "ordering": ordering,
        "age_hours_since_added": age_hours,
        "prior_bounded_negative_seconds": 170.8,
        "prior_bounded_negative_source": (
            "RETYPED FROM RUN 1'S CONSOLE OUTPUT, not read from disk -- "
            "run 3 overwrote the evidence file before the prior_runs "
            "carry-forward existed, so 170.8s now survives only in the "
            "session transcript. Flagged because every other "
            "precondition in this file is read from a file, and a "
            "retyped number is one edit away from disagreeing with its "
            "source. From this run on, prior figures come from "
            "results.prior_runs."),
        "share_read_status": sh_status,
        "catalog_read_status": c_status,
        "last_raw": None if standing_readable else sraw,
        "verdict": cf_verdict,
        "means": ("Run 1's 170.8s bounded negative, re-read after "
                  f"{age_hours}h on a catalog that has not been "
                  "recreated. CATALOG_DOES_REFRESH = the object list is "
                  "not frozen at CREATE CATALOG, so §2.4.1 needs a "
                  "timing note and not a re-import step. "
                  "NEGATIVE_EXTENDED = still absent after all that time, "
                  "which is the snapshot-at-create reading and a "
                  "procedure change. PROVES_NOTHING / NOT_EVIDENCE / "
                  "UNATTRIBUTABLE = the ordering, or a source table "
                  "that no longer exists on the provider, stops this "
                  "read discriminating; the unique-name probe below is "
                  "then the only instrument and this step must not be "
                  "quoted as support (B-23b)."),
    }
    print(f"    [{'ok ' if 'CATALOG_DOES_REFRESH' in cf_verdict else '---'}]"
          f" carry_forward_prior_probe: {cf_verdict}"
          f" (age={age_hours}h, {ordering})")

    # --- question 1: object visibility --------------------------------
    # Membership before and after, because "did the PATCH create new
    # membership" is the precondition for the stopwatch below meaning
    # anything, and a 200 does not answer it (B-23).
    pre_names = [str(o.get("name", "")).split(".")[-1]
                 for o in ((sh_payload or {}).get("objects") or [])]
    status, payload = call(
        g_host, g_token, f"{UC}/shares/{SUB_SHARE}", "PATCH",
        {"updates": [{"action": "ADD",
                      "data_object": {"name": src,
                                      "data_object_type": "TABLE"}}]})
    body = json.dumps(payload or {}).lower()
    pstatus, ppayload = call(
        g_host, g_token,
        f"{UC}/shares/{SUB_SHARE}?include_shared_data=true")
    post_names = [str(o.get("name", "")).split(".")[-1]
                  for o in ((ppayload or {}).get("objects") or [])]
    in_share = refresh_table in post_names
    membership_new = in_share and refresh_table not in pre_names
    res["steps"]["add_to_share"] = {
        "status": status,
        "object": refresh_table,
        "present_before": refresh_table in pre_names,
        "present_after": in_share,
        "membership_new": membership_new,
        "already_exists_in_body": "already" in body,
        "readback_status": pstatus,
        "verdict": ("PERMITTED_NEW_MEMBERSHIP" if membership_new else
                    "PRE_EXISTING_MEMBERSHIP_NOT_MEASURABLE" if in_share else
                    classify(status, payload)[0]),
        "means": ("The stopwatch below only measures refresh if this "
                  "PATCH put something in the share that was not there "
                  "before. Run 3's did not, and the elapsed time was "
                  "printed as a latency regardless. present_before is "
                  "read from the share, not inferred from the status "
                  "code."),
    }
    print(f"    [{'ok ' if membership_new else 'REF'}] add_to_share: "
          f"{res['steps']['add_to_share']['verdict']} ({status})")
    if not in_share:
        res["verdict"] = NOT_RUN
        res["means"] = (
            f"The refresh table is not in the share after the ADD "
            f"({status}), so there is nothing whose arrival could be "
            f"timed. NOT_RUN -- not a bounded negative, because the "
            f"provider side never got as far as presenting the object.")
        return res
    if not membership_new:
        res["verdict"] = "REFRESH_NOT_MEASURED_MEMBERSHIP_PRE_EXISTING"
        res["means"] = (
            f"{refresh_table} was already in the share before this run's "
            f"ADD, so any elapsed time to read it measures warehouse "
            f"round-trip, not refresh. Refusing to emit a latency figure "
            f"rather than emitting an unattributable one -- this is the "
            f"exact defect that made run 3's 5.3s meaningless. The "
            f"unique per-run name should make this branch unreachable; "
            f"if it fires, the clock or the name collided and that is a "
            f"defect in this file, not a fact about Databricks (B-20).")
        res["steps"]["row_visibility"] = {
            "verdict": NOT_RUN,
            "means": "Blocked: object membership was not new."}
        print(f"    PART 4 VERDICT: {res['verdict']}")
        return res

    target = f"{CATALOG_NAME}.{shared_schema}.{refresh_table}"
    stmt = f"SELECT count(*) AS n, max(batch) AS b FROM {target}"
    t0 = time.time()
    deadline = t0 + poll_seconds
    polls, seen, last = 0, None, None
    while True:
        polls += 1
        r, last = run_sql(p_host, p_token, p_wh, stmt)
        if r is not None and r and r[0][0] is not None:
            seen = int(r[0][0])
            break
        if time.time() + poll_interval > deadline:
            break
        time.sleep(poll_interval)
    obj_latency = round(time.time() - t0, 1)
    res["steps"]["object_visibility"] = {
        "polls": polls,
        "latency_seconds": obj_latency,
        "bound_seconds": poll_seconds,
        "rows_seen": seen,
        "expected_rows": baseline_rows,
        "last_raw": last,
        "verdict": ("VISIBLE" if seen == baseline_rows else
                    "VISIBLE_WRONG_COUNT" if seen is not None else
                    "NOT_VISIBLE_WITHIN_BOUND"),
        "means": (f"Time from the share-membership PATCH to the consumer "
                  f"being able to read the new object through the "
                  f"EXISTING catalog -- no re-import, no catalog "
                  f"recreate. The object is {refresh_table}, unique to "
                  f"this run and confirmed absent from the share before "
                  f"the PATCH, so this is time-to-appear. "
                  f"NOT_VISIBLE_WITHIN_BOUND is a bounded negative "
                  f"({poll_seconds}s), not a claim that it never "
                  f"appears (B-21)."),
    }
    print(f"    [{'ok ' if seen == baseline_rows else '---'}] "
          f"object_visibility: "
          f"{res['steps']['object_visibility']['verdict']} "
          f"after {obj_latency}s / {polls} poll(s), rows={seen}")

    # --- what the bounded negative does NOT yet distinguish -----------
    # The first run stopped here with NOT_VISIBLE_WITHIN_BOUND, which is
    # an honest bounded negative and two different operational facts
    # wearing one label:
    #
    #   (a) refresh latency -- the object will appear, later than 180s;
    #   (b) the consumer's catalog is a SNAPSHOT of the share taken at
    #       CREATE CATALOG time, so the object will never appear in this
    #       catalog however long anyone polls.
    #
    # These point at opposite CONOPS procedures. (a) is a timing note in
    # a runbook; (b) means §2.4.1 step 5c has to be RE-RUN whenever the
    # provider adds an object, and a consumer who does not know that
    # sits in front of a catalog that is quietly out of date -- a silent
    # negative pointed at the data rather than the test.
    #
    # Two instruments, cheapest first. The tables API asks whether the
    # object is in the consumer's catalog METADATA at all, separating
    # "not there" from "there but unreadable". Then the catalog is
    # dropped and recreated from the same share: if the object appears
    # only after that, the answer is (b) and it is decisive.
    if seen is None:
        tstatus, tpayload = call(
            p_host, p_token,
            f"{UC}/tables?catalog_name={CATALOG_NAME}"
            f"&schema_name={shared_schema}")
        listed = [t.get("name") for t in ((tpayload or {}).get("tables")
                                          or [])]
        res["steps"]["object_metadata_check"] = {
            "status": tstatus,
            "endpoint": f"{UC}/tables?catalog_name={CATALOG_NAME}",
            "tables_listed": listed,
            "probe_table": refresh_table,
            "probe_table_listed": refresh_table in listed,
            "verdict": ("IN_METADATA_BUT_UNREADABLE"
                        if refresh_table in listed
                        else "ABSENT_FROM_CONSUMER_METADATA"),
            "means": ("Separates 'the object is not in the consumer's "
                      "catalog' from 'it is there and the read failed'. "
                      "Those have different causes and the SELECT "
                      "refuses identically for both."),
        }
        print(f"    [---] object_metadata_check: "
              f"{res['steps']['object_metadata_check']['verdict']} "
              f"(tables={listed})")

        # The recreate is destructive to this repo's own instruments: it
        # resets the catalog's created_at, which is half of the
        # carry-forward ordering above, and it discards the standing
        # 170.8s negative that run 1 paid for. So it only runs when the
        # cheaper read did NOT already answer the question. If the
        # standing object -- added after this catalog existed -- is
        # readable now, then the object list is NOT frozen at create
        # time, and this run's bounded negative is latency. Recreating
        # the catalog to re-prove that would spend the instrument to
        # confirm what it has already said.
        if cf_verdict == "STANDING_OBJECT_NOW_READABLE_CATALOG_DOES_REFRESH":
            res["steps"]["catalog_recreate_discriminator"] = {
                "verdict": "NOT_RUN_ALREADY_ANSWERED_BY_CARRY_FORWARD",
                "carry_forward_verdict": cf_verdict,
                "means": ("Skipped deliberately. The carry-forward read "
                          "shows an object added AFTER this catalog was "
                          "created is readable through it, so the "
                          "snapshot-at-create hypothesis is already "
                          "excluded and this run's miss is latency past "
                          f"{poll_seconds}s. Running the recreate would "
                          "reset catalog_created_at and destroy run 1's "
                          "standing negative to re-derive a conclusion "
                          "already in hand (B-19)."),
            }
            print("    [ok ] catalog_recreate_discriminator: "
                  "NOT_RUN_ALREADY_ANSWERED_BY_CARRY_FORWARD")
            res["verdict"] = "REFRESH_OBJECT_LATENCY_EXCEEDS_BOUND"
            res["conops_implication"] = (
                f"A newly shared object was not readable through the "
                f"existing catalog within {obj_latency}s over {polls} "
                f"poll(s), but a previously shared object added after "
                f"that catalog was created IS readable "
                f"({age_hours}h later). So the consumer's object list "
                f"does refresh without a re-import, and the refresh is "
                f"slower than {poll_seconds}s. §2.4.1 needs a timing "
                f"expectation here -- a consumer that polls for three "
                f"minutes and concludes the share is wrong will raise a "
                f"false defect. The exact upper bound is NOT measured by "
                f"this run and should not be quoted as one.")
            res["steps"]["row_visibility"] = {
                "verdict": NOT_RUN,
                "means": ("The probe object is not readable yet, so "
                          "there is nothing to append to. NOT_RUN "
                          "rather than blank: §2.4.4 needs this number "
                          "and a missing one must not read as zero.")}
            res["steps"]["probe_cleanup"] = {
                "object": src,
                "verdict": "PROBE_LEFT_DELIBERATELY",
                "means": ("Left in the share on purpose. It was added "
                          "at a known time to a catalog of known age "
                          "and was not visible within "
                          f"{poll_seconds}s, so the next run's "
                          "carry_forward_prior_probe can read it and "
                          "turn this bounded negative into a real upper "
                          "bound for free. Deleting it would throw away "
                          "the only cheap instrument for the one number "
                          "this run could not produce."),
            }
            print(f"    PART 4 VERDICT: {res['verdict']}")
            return res

        res["carry_forward_invalidated"] = True
        dstatus, _ = call(p_host, p_token,
                          f"{UC}/catalogs/{CATALOG_NAME}?force=true",
                          "DELETE")
        cstatus, cpayload = call(p_host, p_token, f"{UC}/catalogs", "POST", {
            "name": CATALOG_NAME, "provider_name": PROVIDER_NAME,
            "share_name": SUB_SHARE})
        recreated = cstatus in (200, 201)
        rows2, raw2 = (None, None)
        if recreated:
            r2_deadline = time.time() + min(poll_seconds, 60)
            while True:
                rows2, raw2 = run_sql(p_host, p_token, p_wh, stmt)
                if rows2 is not None and rows2 and rows2[0][0] is not None:
                    break
                if time.time() + poll_interval > r2_deadline:
                    break
                time.sleep(poll_interval)
        seen_after = (int(rows2[0][0]) if rows2 and rows2[0]
                      and rows2[0][0] is not None else None)
        res["steps"]["catalog_recreate_discriminator"] = {
            "delete_status": dstatus,
            "recreate_status": cstatus,
            "recreated": recreated,
            "rows_after_recreate": seen_after,
            "expected_rows": baseline_rows,
            "last_raw": raw2,
            "verdict": ("VISIBLE_ONLY_AFTER_CATALOG_RECREATE"
                        if seen_after is not None else
                        "STILL_NOT_VISIBLE_AFTER_RECREATE"
                        if recreated else
                        "DISCRIMINATOR_NOT_RUN_RECREATE_FAILED"),
            "means": ("DELETE then CREATE the catalog from the same "
                      "share, then re-read. Visible only after this = "
                      "the consumer's object list is fixed at catalog "
                      "creation, which is a procedure requirement for "
                      "§2.4.1 step 5c, not a latency figure. Still not "
                      "visible = the bounded negative stands and the "
                      "cause is upstream of the catalog."),
        }
        print(f"    [{'ok ' if seen_after is not None else '---'}] "
              f"catalog_recreate_discriminator: "
              f"{res['steps']['catalog_recreate_discriminator']['verdict']}"
              f" rows={seen_after}")

        if seen_after is not None:
            res["verdict"] = "REFRESH_OBJECT_REQUIRES_CATALOG_RECREATE"
            res["conops_implication"] = (
                f"A newly shared object was NOT readable through the "
                f"existing catalog within {obj_latency}s over {polls} "
                f"poll(s), and WAS readable immediately after the "
                f"catalog was recreated from the same share. On this "
                f"path the consumer's object list is established at "
                f"CREATE CATALOG time. §2.4.1 therefore needs an "
                f"explicit step: when the provider adds an object, the "
                f"consumer re-runs step 5c. Without it the consumer "
                f"reads a catalog that is silently short of what the "
                f"share contains -- and nothing in the UI says so. "
                f"ROW freshness is a separate question and is measured "
                f"below; do not carry this finding onto it.")
            seen = seen_after
            # Row freshness is still measurable now that the object is
            # readable, and it is the number §2.4.4 actually needs.
        else:
            res["verdict"] = "REFRESH_PARTIAL_OBJECT_NOT_VISIBLE"
            res["means"] = (
                f"Bounded negative on object visibility "
                f"({obj_latency}s / {polls} poll(s)), and a catalog "
                f"recreate did not change it "
                f"({res['steps']['catalog_recreate_discriminator']['verdict']})"
                f". So this is NOT the snapshot-at-create behaviour; "
                f"the cause is upstream of the consumer's catalog. Row "
                f"visibility is NOT_RUN because there is no readable "
                f"object to append to -- recorded as NOT_RUN rather "
                f"than left blank, since §2.4.4's landing design needs "
                f"that number and a missing one must not read as a "
                f"measured zero.")
            res["steps"]["row_visibility"] = {
                "verdict": NOT_RUN,
                "means": "Blocked by object visibility above."}
            return res

    # --- question 2: row visibility -----------------------------------
    run_sql(g_host, g_token, g_wh,
            f"INSERT INTO {src} SELECT id + 100, 2, '{origin}' "
            f"FROM range(3)")
    rows, _ = run_sql(g_host, g_token, g_wh, f"SELECT count(*) FROM {src}")
    after_rows = int(rows[0][0]) if rows else None
    res["steps"]["provider_append"] = {"batch": 2, "rows_now": after_rows}
    print(f"    [ok ] appended batch 2 on the provider -> {after_rows} rows")

    t0 = time.time()
    deadline = t0 + poll_seconds
    polls, seen2, maxbatch, last = 0, None, None, None
    while True:
        polls += 1
        r, last = run_sql(p_host, p_token, p_wh, stmt)
        if r is not None and r and r[0][0] is not None:
            seen2 = int(r[0][0])
            maxbatch = int(r[0][1]) if r[0][1] is not None else None
            if seen2 == after_rows:
                break
        if time.time() + poll_interval > deadline:
            break
        time.sleep(poll_interval)
    row_latency = round(time.time() - t0, 1)
    res["steps"]["row_visibility"] = {
        "polls": polls,
        "latency_seconds": row_latency,
        "bound_seconds": poll_seconds,
        "rows_seen": seen2,
        "expected_rows": after_rows,
        "max_batch_seen": maxbatch,
        "last_raw": last,
        "verdict": ("FRESH" if seen2 == after_rows else
                    "STALE_WITHIN_BOUND"),
        "means": ("Time from an INSERT on the provider to the consumer's "
                  "read reflecting it, through an already-established "
                  "catalog. max_batch_seen distinguishes 'saw the new "
                  "rows' from 'row count happened to match' -- a count "
                  "alone could coincide."),
    }
    print(f"    [{'ok ' if seen2 == after_rows else '---'}] "
          f"row_visibility: {res['steps']['row_visibility']['verdict']} "
          f"after {row_latency}s / {polls} poll(s), rows={seen2} "
          f"batch={maxbatch}")

    # The recreate finding is not overwritten by the row result. Both
    # are true at once and they are different facts: the object needed
    # a catalog recreate, the rows did or did not arrive on their own.
    # Collapsing them into one verdict is what Part 4 exists to avoid.
    recreate_needed = ("catalog_recreate_discriminator" in res["steps"]
                       and res["steps"]["catalog_recreate_discriminator"]
                       ["verdict"]
                       == "VISIBLE_ONLY_AFTER_CATALOG_RECREATE")
    if recreate_needed:
        res["verdict"] = (
            "REFRESH_OBJECT_REQUIRES_CATALOG_RECREATE_ROWS_FRESH"
            if seen2 == after_rows else
            "REFRESH_OBJECT_REQUIRES_CATALOG_RECREATE_ROWS_STALE")
    else:
        res["verdict"] = ("REFRESH_MEASURED"
                          if seen2 == after_rows else
                          "REFRESH_MEASURED_ROWS_STALE")
    res["means"] = (
        f"Both refresh questions have a number, and both are measured "
        f"against state this run created: the probe object "
        f"{refresh_table} joined the share in this run "
        f"(membership_new=True), so object visibility "
        f"{obj_latency}s"
        f"{' (only after a catalog recreate)' if recreate_needed else ''} "
        f"is time-to-appear and not time-to-count-an-old-table. Row "
        f"visibility {row_latency}s. Each polled at {poll_interval}s, so "
        f"the resolution is {poll_interval}s and both figures are upper "
        f"bounds, not latencies. Measured over the SUBSTITUTE path -- "
        f"the native D2D refresh behaviour is NOT measured, because "
        f"there is no native catalog to measure it on. Carry-forward on "
        f"run 1's standing negative: {cf_verdict}.")

    # The probe has answered both questions, so it is removed -- a
    # unique name per run must not mean an extra table and an extra
    # share object per run forever. The standing REFRESH_TABLE is
    # deliberately NOT touched: it is the carry-forward instrument the
    # next run reads, and its value comes from its age.
    rstatus, _ = call(
        g_host, g_token, f"{UC}/shares/{SUB_SHARE}", "PATCH",
        {"updates": [{"action": "REMOVE",
                      "data_object": {"name": src,
                                      "data_object_type": "TABLE"}}]})
    _, drop_raw = run_sql(g_host, g_token, g_wh,
                          f"DROP TABLE IF EXISTS {src}")
    res["steps"]["probe_cleanup"] = {
        "object": src,
        "share_remove_status": rstatus,
        "share_removed": rstatus in (200, 201, 204),
        "table_dropped_raw": drop_raw,
        "standing_object_preserved": REFRESH_TABLE,
        "verdict": ("PROBE_REMOVED" if rstatus in (200, 201, 204)
                    else "PROBE_LEFT_SHARE_REMOVE_REFUSED"),
        "means": ("Removes only this run's probe. If this says "
                  "PROBE_LEFT, the share now carries a stale object and "
                  "the next run's pre_names list will show it -- which "
                  "is why that list is read rather than assumed."),
    }
    print(f"    [{'ok ' if rstatus in (200, 201, 204) else 'REF'}] "
          f"probe_cleanup: {res['steps']['probe_cleanup']['verdict']} "
          f"({rstatus})")
    print(f"    PART 4 VERDICT: {res['verdict']}")
    return res


# =====================================================================
# PART 5 -- the D-6 contrast, read from T-20 rather than retyped
# =====================================================================

def part5_d6_contrast(part1, part2):
    """D-6: T-20 created a catalog from a share on a provider it could
    never reach. The control plane accepted CREATE CATALOG and GRANT
    over an endpoint that was refused at import.

    The contrast is only worth recording as a MEASUREMENT, which means
    reading T-20's own numbers rather than describing them. Here the
    provider is reachable, so SHOW SHARES IN PROVIDER returns real
    objects -- and that difference is one field against another field,
    not an argument.
    """
    res = {"defect": "D-6"}
    if not T20.exists():
        res["verdict"] = NOT_RUN
        res["means"] = (f"{T20.relative_to(REPO)} absent; run "
                        f"tests/t20_ingress_d2o.py first.")
        return res
    t20 = json.loads(T20.read_text())
    a = (t20.get("path_a_control_plane") or {})
    steps = {k: v.get("verdict") for k, v in a.items()
             if isinstance(v, dict) and "verdict" in v}
    res["t20_path_a"] = {
        "source": str(T20.relative_to(REPO)),
        "steps": steps,
        "verdict": (t20.get("verdict") or {}).get("path_a"),
    }
    here = (part2.get("steps", {}).get("list_provider_shares") or {})
    res["t19_here"] = {
        "shares_listed": here.get("shares"),
        "verdict": here.get("verdict"),
        "native_d2d_had_no_object_to_query": part1.get("verdict"),
    }

    # DERIVED, not typed. The first version of this sentence said T-20's
    # provider IMPORT was refused. It was not: 5a_import_provider came
    # back IMPORTED and 5b_confirm_shares was the step that failed. A
    # sentence written before the file was read describes the run its
    # author imagined, which is B-23b -- and this one would have
    # misstated the defect it exists to document, in the evidence
    # record, next to the field that disproves it.
    failed = [k for k, v in steps.items() if "REFUS" in str(v).upper()
              or "BLOCK" in str(v).upper()]
    succeeded_after = [k for k, v in steps.items()
                       if v in ("CREATED", "GRANTED")]
    res["contrast"] = (
        f"In T-20, step(s) {failed or 'none recorded'} failed against an "
        f"unreachable provider and step(s) {succeeded_after or 'none'} "
        f"then SUCCEEDED anyway, so those later successes described "
        f"nothing readable. Here the enumeration step that failed there "
        f"returns {here.get('shares')!r} -- real share names from a "
        f"reachable provider. One field against another field: the "
        f"control plane does not require the provider to be reachable "
        f"in order to accept catalog creation and grants against it.")
    res["contrast_derivation"] = (
        "The step names above are read from T-20's own record, not "
        "named in this file, so this sentence cannot describe a run that "
        "did not happen (B-23b).")
    res["conops_consequence"] = (
        "Any runbook step that treats a 200 from CREATE CATALOG as "
        "evidence that the share is readable is unsound. §2.4.1 step 5c "
        "needs a read-back -- which is B-23 as a procedure change, not "
        "just a scripting habit.")
    res["verdict"] = ("D6_CONTRAST_CAPTURED" if here.get("shares")
                      else "D6_CONTRAST_INCOMPLETE")
    print(f"\nPART 5 -- D-6 contrast: {res['verdict']}")
    return res


# =====================================================================
# §2.4.2 roles and §2.4.1 step coverage
# =====================================================================

def role_table(part3b):
    """Every hat in §2.4.2, with the hat actually worn.

    One addition T-20 could not make: denial (B), if it ran, is the one
    place in this repo where a SECOND identity genuinely exists, so the
    consumer role is not wholly simulated here.
    """
    second_real = part3b.get("verdict") == "DENIAL_B_DEMONSTRATED"
    return [
        {"role": "Requester", "held_by_conops": "Consuming team",
         "hat_worn_here": "CONOPS owner as requester",
         "steps": ["1"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "No ticket system; the request is this record."},
        {"role": "Approver", "held_by_conops": "Data Governance",
         "hat_worn_here": "CONOPS owner as approver",
         "steps": ["1"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "A1 unmet (1694-G1 has not arrived), so the approval is "
                 "provisional and labelled, not governance sign-off."},
        {"role": "Provider / sharing admin",
         "held_by_conops": "External provider organisation",
         "hat_worn_here": "CONOPS owner on the glovashu account",
         "steps": ["2", "3"], "status": "EXERCISED",
         "note": "A genuinely separate account and metastore, and NOT an "
                 "arm's-length counterparty: one operator holds both "
                 "ends. The share, recipient and grant are real; the "
                 "negotiation is not."},
        {"role": "Credential custodian", "held_by_conops": "Data Eng",
         "hat_worn_here": "CONOPS owner as custodian",
         "steps": ["4"], "status": "EXERCISED",
         "note": "Credential vaulted in _secrets/ at 0600 and "
                 "hygiene-gated. Its mode ON ARRIVAL is recorded rather "
                 "than corrected silently (B-25). UNSEPARATED: the same "
                 "operator also holds the read."},
        {"role": "Metastore admin / catalog creator",
         "held_by_conops": "Client-side admin",
         "hat_worn_here": "CONOPS owner via DATABRICKS_TOKEN",
         "steps": ["5a", "5b", "5c"], "status": "EXERCISED",
         "note": "Import, enumerate and catalog-create all exercised on "
                 "the substitute path. On the native D2D path 5a and 5b "
                 "had no object to run against."},
        {"role": "Catalog owner / grantor",
         "held_by_conops": "Data owner",
         "hat_worn_here": "CONOPS owner as catalog owner",
         "steps": ["6"], "status": ("EXERCISED" if second_real
                                    else "EXERCISED_PARTIAL"),
         "note": ("Grant issued to a real second service principal, and "
                  "the ungranted state measured first. Default deny is "
                  "DEMONSTRATED here, not asserted -- which is the one "
                  "thing T-20 could not do, because its grants went to "
                  "'account users'." if second_real else
                  "Grants exercised; default deny NOT demonstrated, see "
                  "Part 3B's verdict for why.")},
        {"role": "Consumer (entitled)",
         "held_by_conops": "Entitled group member",
         "hat_worn_here": ("A separate service principal with its own "
                           "credential" if second_real
                           else "CONOPS owner"),
         "steps": ["5c", "6"],
         "status": "EXERCISED" if second_real
                   else "SIMULATED_SINGLE_OPERATOR"},
        {"role": "Consumer (non-entitled)",
         "held_by_conops": "Non-entitled group member",
         "hat_worn_here": ("The same principal BEFORE its grant"
                           if second_real else "none available"),
         "steps": ["6"],
         "status": "EXERCISED" if second_real else NOT_RUN,
         "note": ("Two states of one real identity, one variable. Not "
                  "our own identity with a narrower grant, which would "
                  "be defect D-2." if second_real else
                  "Reported NOT_RUN with the cause named rather than "
                  "simulated.")},
        {"role": "Security approver", "held_by_conops": "Platform security",
         "hat_worn_here": "CONOPS owner",
         "steps": ["allow-list change"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "The dedicated opensharing endpoint recorded in Part 2 "
                 "is the allow-list change such an approval would attach "
                 "to."},
    ]


def step_coverage(part1, part2, part3a, part3b, part4):
    def v(d):
        return d.get("verdict")
    return [
        {"step": 1, "name": "Request and approval", "verdict": "SIMULATED",
         "note": "See role_table; no ticket system in the prototype."},
        {"step": 2, "name": "Identity exchange",
         "verdict": "SPLIT",
         "note": f"Native D2D: the primary's sharing identifier was "
                 f"exchanged and read back ({v(part1)}). Substitute: a "
                 f"credential file, minted by scripts/19 and activated by "
                 f"hand."},
        {"step": 3, "name": "Provider action", "verdict": "EXERCISED",
         "note": "Share created, table added, recipient granted SELECT, "
                 "all four read back on both paths."},
        {"step": 4, "name": "Custody", "verdict": "EXERCISED",
         "note": "0600, gitignored, hygiene-gated; arrival mode measured."},
        {"step": 5, "name": "Connect", "verdict": "SPLIT",
         "note": f"5a/5b on the native D2D path: {v(part1)} -- no "
                 f"provider object appeared, so there was nothing to "
                 f"enumerate. On the substitute path: {v(part2)}."},
        {"step": 6, "name": "Grant and read",
         "verdict": "EXERCISED" if v(part3b) == "DENIAL_B_DEMONSTRATED"
                    else "PARTIAL",
         "note": f"Entitled read {v(part2)}; denial by object scope "
                 f"{v(part3a)}; denial by identity {v(part3b)}."},
        {"step": 7, "name": "Land and validate", "verdict": "OUT_OF_SCOPE",
         "note": "§2.4.4, test T-22."},
        {"step": 8, "name": "Register", "verdict": "EXERCISED",
         "note": "This evidence file is the inventory row: provider, "
                 "share, catalog, owner, tier, credential expiry, DSA "
                 "reference pending (OD-5/AC3), plus the refresh figures "
                 f"from Part 4 ({v(part4)})."},
    ]


# =====================================================================
# CLEANUP
# =====================================================================

def cleanup(s):
    """Remove this test's objects. Not run by default.

    The default is to LEAVE them, because 'no provider appeared' is
    exactly the finding where the two consoles are the next instrument,
    and a test that deletes its own subject leaves a human nothing to
    look at. Everything is TAG-prefixed so it is findable by hand.
    """
    res = {"deleted": [], "refused": []}
    p_host, p_token = s["p_host"], s["p_token"]
    g_host, g_token = s["g_host"], s["g_token"]
    print("\nCLEANUP")
    print("-" * 68)
    for host, token, path, label in (
        (p_host, p_token, f"{UC}/catalogs/{CATALOG_NAME}", "primary catalog"),
        (p_host, p_token, f"{UC}/providers/{PROVIDER_NAME}", "primary provider"),
        (g_host, g_token, f"{UC}/shares/{D2D_SHARE}", "glovashu d2d share"),
        (g_host, g_token, f"{UC}/shares/{SUB_SHARE}", "glovashu sub share"),
        (g_host, g_token, f"{UC}/recipients/{D2D_RECIPIENT}",
         "glovashu d2d recipient"),
    ):
        status, payload = call(host, token, path, "DELETE")
        ok = status in (200, 204, 404)
        (res["deleted"] if ok else res["refused"]).append(
            {"object": label, "path": path, "status": status})
        print(f"    [{'ok ' if ok else 'REF'}] {label}: {status}")
    res["preserved"] = {
        "token_recipient": DEFAULT_TOKEN_RECIPIENT,
        "why": ("Minted by scripts/19 and activated by hand. Revoking it "
                "kills the credential in _secrets/ and the activation "
                "link is single-use, so it would take a --mint --rotate "
                "and another manual browser step to get back. Left in "
                "place deliberately."),
        "provider_tables": [REFRESH_TABLE, DENIED_TABLE],
        "tables_why": ("Left on glovashu so a re-run does not have to "
                       "recreate them, and so the unshared control table "
                       "stays available as a standing negative."),
    }
    return res


# =====================================================================
# MAIN
# =====================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poll-seconds", type=int, default=180,
                    help="bound for every poll in this test. A bounded "
                         "negative is reportable; an unbounded one is not.")
    ap.add_argument("--poll-interval", type=int, default=15)
    ap.add_argument("--token-recipient", default=DEFAULT_TOKEN_RECIPIENT,
                    help="existing activated TOKEN recipient on glovashu "
                         "whose credential is in _secrets/")
    ap.add_argument("--fresh-principal", action="store_true",
                    help="create a NEW service principal for Part 3B "
                         "instead of reusing one. Makes the ungranted "
                         "state structural rather than measured, which "
                         "is the decisive instrument when a leak alarm "
                         "has to be cleared of our own leftover grants.")
    ap.add_argument("--cleanup", action="store_true",
                    help="delete this test's objects and exit")
    args = ap.parse_args()

    s = sides()
    if args.cleanup:
        res = cleanup(s)
        print(f"\nDeleted {len(res['deleted'])}, refused "
              f"{len(res['refused'])}. "
              f"{DEFAULT_TOKEN_RECIPIENT} preserved on purpose.")
        return 0

    print("T-19 -- Channel I-1 ingress, D2D pull")
    print("=" * 68)
    gates, fixture = preconditions()
    primary_identifier = gates["distinct_metastores"][
        "primary_sharing_identifier"]
    print(f"Primary sharing identifier: {primary_identifier}")
    for name in ("ingress_chain_permitted", "direction_excluded",
                 "credential_mode_narrowed", "second_identity"):
        print(f"Precondition {name}: {gates[name]['verdict']}")

    results = {
        "test_id": "T-19",
        "description": "Channel I-1 ingress, D2D pull (CONOPS 2.4.1 D2D "
                       "column)",
        "task": "E1 Task 1.10",
        "date": now(),
        "epic": "E1 (T04-10), co-owned by E3 (1227-E3)",
        "acceptance_criteria": ["AC1", "AC3"],
        "preconditions": gates,
        "poll_bound_seconds": args.poll_seconds,
        "poll_interval_seconds": args.poll_interval,
    }

    # --- B-19: this file used to erase the run before it ---------------
    # write_text replaces the evidence wholesale, so run 3's successes
    # silently deleted run 1's 170.8s bounded negative -- the single
    # most load-bearing number Part 4 had produced. A later success must
    # never make an earlier negative disappear: the negative is what
    # established that the behaviour is conditional, and a reader who
    # only sees the success will write a CONOPS that assumes it always
    # works. Prior runs are carried forward in a capped summary, not the
    # full tree, so the file stays readable, and they are read from the
    # file on disk rather than described from memory.
    prior = []
    if EVIDENCE.exists():
        try:
            old = json.loads(EVIDENCE.read_text())
        except (ValueError, OSError) as exc:
            prior = [{"carry_forward_error": str(exc),
                      "means": ("The previous evidence file could not be "
                                "parsed, so earlier runs are NOT carried "
                                "forward. Recorded as an error rather "
                                "than an empty history -- 'no prior "
                                "runs' and 'could not read prior runs' "
                                "must not print the same.")}]
            old = None
        if old:
            prior = (old.get("prior_runs") or [])[-5:]
            p4old = (old.get("part4_refresh") or {})
            # A figure produced before membership was measured is not
            # deleted on the way in -- it is carried with a label. Runs
            # whose add_to_share has no membership_new field came from
            # the code that started the stopwatch on an object already
            # in the share, so their object_visibility number is a
            # warehouse round-trip wearing a latency's name. Dropping
            # it would hide that this test once mismeasured; keeping it
            # unlabelled would let someone quote it (B-19).
            old_add = (p4old.get("steps", {}).get("add_to_share") or {})
            old_vis = (p4old.get("steps", {}).get("object_visibility")
                       or None)
            if old_vis and "membership_new" not in old_add:
                old_vis = dict(old_vis)
                old_vis["RETRACTED"] = (
                    "This run did not verify that the probe object was "
                    "absent from the share before the ADD, and the "
                    "fixed object name means it almost certainly was "
                    "present from an earlier run. latency_seconds here "
                    "is the time to count an already-visible table, "
                    "NOT refresh latency. Retained and labelled rather "
                    "than deleted: the mismeasurement is itself part of "
                    "the record. Do not quote this figure in §2.4.1 or "
                    "§2.4.4.")
            prior.append({
                "date": old.get("date"),
                "verdict": (old.get("verdict") or {}).get("t19")
                           or (old.get("verdict") or {}).get("verdict"),
                "part_verdicts": {
                    k: (old.get(k) or {}).get("verdict")
                    for k in ("part1_native_d2d",
                              "part2_substitute_ingress",
                              "part3a_denial_object_scope",
                              "part3b_denial_identity",
                              "part4_refresh")},
                "object_visibility": old_vis,
                "carry_forward_prior_probe": (p4old.get("steps", {})
                                              .get("carry_forward_"
                                                   "prior_probe")),
                "poll_bound_seconds": old.get("poll_bound_seconds"),
            })
    results["prior_runs"] = prior
    results["prior_runs_means"] = (
        "Earlier runs of this same test, carried forward so a later "
        "success cannot delete the negative it was derived from (B-19). "
        "Retracted claims are LABELLED in place, never removed. Read "
        "these before quoting any figure below as the behaviour of the "
        "platform: a number that holds in one run and not another is a "
        "conditional finding, and the condition is the finding.")
    if prior:
        print(f"Prior runs carried forward: {len(prior)}")

    results["part1_native_d2d"] = part1_native(
        s, fixture, gates, args.poll_seconds, args.poll_interval)
    results["part2_substitute_ingress"] = part2_substitute(
        s, fixture, args.token_recipient)
    results["part3a_denial_object_scope"] = part3a_denial_object(
        s, results["part2_substitute_ingress"], fixture)
    results["part3b_denial_identity"] = part3b_denial_identity(
        s, results["part2_substitute_ingress"], gates,
        args.poll_seconds, args.poll_interval,
        fresh=args.fresh_principal)
    results["part4_refresh"] = part4_refresh(
        s, results["part2_substitute_ingress"], fixture,
        args.poll_seconds, args.poll_interval)
    results["part5_d6_contrast"] = part5_d6_contrast(
        results["part1_native_d2d"], results["part2_substitute_ingress"])

    results["role_table"] = role_table(results["part3b_denial_identity"])
    results["step_coverage"] = step_coverage(
        results["part1_native_d2d"], results["part2_substitute_ingress"],
        results["part3a_denial_object_scope"],
        results["part3b_denial_identity"], results["part4_refresh"])
    results["role_separation_caveat"] = (
        "Every §2.4.2 hat except the non-entitled consumer was worn by "
        "one operator, so the SEQUENCE and the ARTEFACTS are evidence "
        "and the SEGREGATION OF DUTIES is not. The exception matters: if "
        "Part 3B demonstrated denial, a second real identity with its "
        "own credential was exercised, which is the first genuine "
        "separation anywhere in this repo.")

    # --- grade --------------------------------------------------------
    p1 = results["part1_native_d2d"]["verdict"]
    p2 = results["part2_substitute_ingress"]["verdict"]
    p3a = results["part3a_denial_object_scope"]["verdict"]
    p3b = results["part3b_denial_identity"]["verdict"]
    p4 = results["part4_refresh"]["verdict"]

    # Two different failures, two different grades, and the difference
    # is who owns the defect. FAIL_ACCESS_CONTROL_LEAK is a claim about
    # DATABRICKS and the most expensive sentence this test can emit, so
    # it is reserved for the case where the instrument explanations were
    # excluded by measurement. An over-broad grant of OURS gets its own
    # grade: equally blocking, correctly attributed (B-20). The fourth
    # run printed the first of these for what may have been the second,
    # and a dirty prestate besides.
    leak = p3a == "DENIAL_A_FAILED_OBJECT_LEAKED" or \
        p3b == "DENIAL_B_FAILED_UNGRANTED_IDENTITY_READ"
    overbroad = p3b == "DENIAL_B_UNGRANTED_READ_EXPLAINED_BY_INHERITANCE"
    if leak:
        verdict = "FAIL_ACCESS_CONTROL_LEAK"
    elif overbroad:
        verdict = "FAIL_OVER_BROAD_GRANT_IN_OUR_CONFIGURATION"
    elif p3b == "DENIAL_B_NOT_RUN_PRESTATE_DIRTY":
        verdict = "BLOCKED_DENIAL_B_INSTRUMENT_NOT_CLEAN"
    elif p1 == "NATIVE_D2D_SURFACED_RETRACTION_REQUIRED":
        verdict = "NATIVE_PATH_UNEXPECTEDLY_AVAILABLE_RERUN_PROBES"
    elif p2 != "SUBSTITUTE_INGRESS_WORKS":
        verdict = "PARTIAL_NO_INGRESS_PATH_DEMONSTRATED"
    elif p3a == "DENIAL_A_DEMONSTRATED" and p3b == "DENIAL_B_DEMONSTRATED" \
            and ("ROWS_FRESH" in p4 or p4 == "REFRESH_MEASURED"):
        # A refresh that needed a catalog recreate still ANSWERED both
        # questions, so it grades as measured. What it changes is the
        # CONOPS procedure, not T-19's standing -- the requirement is
        # carried in part4.conops_implication and must reach §2.4.1.
        verdict = "PASS_WITH_SCOPE"
    else:
        verdict = "PARTIAL_WITH_NAMED_GAPS"

    results["verdict"] = {
        "t19": verdict,
        "native_d2d": p1,
        "substitute_ingress": p2,
        "denial_object_scope": p3a,
        "denial_identity": p3b,
        "refresh": p4,
        "capability_missing": results["part1_native_d2d"].get(
            "capability_missing"),
        "conops_change_required": results["part4_refresh"].get(
            "conops_implication"),
        "scope": (
            "What is demonstrated: the §2.4.1 ingress procedure runs end "
            "to end against a genuinely separate metastore, rows cross "
            "attributably by count and origin stamp, share membership is "
            "an enforced boundary, and refresh has two measured numbers. "
            "What is NOT demonstrated: native D2D surfacing, which is "
            "reported NOT_RUN with the capability named and three "
            "independent bounded negatives behind it. The counterparty "
            "is a real second account but not an arm's-length "
            "organisation, so T-13 is still the only thing that can "
            "produce that."),
        "conops_recommendation": (
            "T-19's native D2D confirming calls should be recorded in "
            "v1.6 as NOT_RUN against a named platform capability, with "
            "open sharing as the EVIDENCED substitute ingress path "
            "rather than a workaround. That is a recommendation the "
            "CONOPS owner can take to the corporate discussion with "
            "measurements attached, and it converts a dead end into a "
            "decision: accept the open-protocol path for D2D ingress, or "
            "escalate the surfacing gap to Databricks."),
    }

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(results, indent=2, default=str))
    print("\n" + "=" * 68)
    print(f"Part 1 native D2D:        {p1}")
    print(f"Part 2 substitute:        {p2}")
    print(f"Part 3A denial (object):  {p3a}")
    print(f"Part 3B denial (identity):{p3b}")
    print(f"Part 4 refresh:           {p4}")
    print(f"\nT-19: {verdict}")
    print(f"\nWrote {EVIDENCE.relative_to(REPO)}")
    print("Now run: python3 scripts/check_secret_hygiene.py")
    print(f"Leftovers are {TAG}-prefixed; "
          f"'python3 tests/t19_ingress_d2d.py --cleanup' removes them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
