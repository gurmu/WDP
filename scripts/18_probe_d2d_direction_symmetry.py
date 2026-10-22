#!/usr/bin/env python3
"""Is 'the primary sees no provider' a fact about DIRECTION, or about this
environment?

WHY THIS EXISTS
---------------
scripts/15 run 5 (--keep) built the complete D2D ingress chain on
glovashu and verified every link by read-back, not by status code:

  create_share                  PERMITTED
  add_table_to_share            PERMITTED
  create_recipient_for_primary  PERMITTED
  grant_share_to_recipient      PERMITTED
  grant_readback                GRANT_IN_EFFECT      -> ['SELECT']
  share_contents_readback       SHARE_NON_EMPTY      -> [...] ['ACTIVE']
  recipient_readback            identifier matches primary

and the primary then listed NO providers, after 4 polls over 16.5s, with
`negative_is_clean` set. Two independent instruments agreed: the REST
call GET /providers and the CONOPS's own SQL `SHOW PROVIDERS` both
returned nothing, minutes apart.

The tempting sentence is "D2D ingress does not surface a provider". It
is one observation short of being allowed. B-12's standing rule in this
repo runs in both directions: a refusal is not evidence until a matching
PERMITTED case has succeeded differing in exactly one variable -- and an
ABSENCE is not evidence about a variable until the same absence has been
tested with that variable changed and nothing else.

Here the variable is direction, and we have never changed it. Checking
what the repo actually holds:

  * evidence/capability-baseline-d2d.json's egress probe CREATED a
    DATABRICKS-auth recipient on the primary (200) and stopped there. It
    never made a share, never added a table, never granted. A recipient
    with no grant offers nothing, so nothing could have appeared on
    glovashu. That run cannot serve as the egress control.
  * The two recipients still live on the primary are both
    authentication_type = TOKEN with names = None. Those are OPEN
    SHARING recipients, not D2D.
  * glovashu's own GET /providers is likewise EMPTY.

So no provider object has ever appeared in this environment in either
direction, and the ingress chain built by probe 15 is the first complete
D2D grant here. Attributing its empty list to the ingress direction
would be attributing to direction something observed exactly once, in
one direction, with no control -- the same reasoning error as B-18
(configuration read as a tier ceiling) and D-2 (a narrower grant on our
own identity read as a denial).

WHAT THIS PROBE DOES
--------------------
Builds the COMPLETE chain -- share, table, recipient, grant, all four
read-backs -- in a NAMED direction, then asks the recipient side whether
a provider appeared, using both instruments. Run it in both directions
and direction becomes the single variable.

  --direction egress    primary provides  -> glovashu receives   (E-2)
  --direction ingress   glovashu provides -> primary receives    (T-19)
  --direction both      one after the other, same run

The four outcomes and what each licenses:

  egress appears, ingress does not  DIRECTION_SPECIFIC. A real T-19
                                    finding, with its control in hand.
  both appear                       BOTH_DIRECTIONS_VISIBLE. Probe 15's
                                    negative was a transient or a
                                    propagation bound that 16.5s missed;
                                    T-19 runs as specified.
  neither appears                   VISIBILITY_UNVERIFIED. The honest
                                    verdict. NOT a direction finding and
                                    NOT a product constraint: D2D
                                    provider visibility is unverified in
                                    this environment, reported with the
                                    capability named and NOT_RUN -- the
                                    epic's own carried-forward rule.
  ingress appears, egress does not  DIRECTION_SPECIFIC_REVERSED, which
                                    would make E-2 the blocked channel,
                                    not T-19.

THE POLLING BOUND IS THE POINT, NOT AN IMPLEMENTATION DETAIL
------------------------------------------------------------
Probe 15 bounded its negative at 16.5s and said so (B-21), which is
what makes that negative reportable rather than ambiguous. 16.5s is also
a weak bound for an undocumented cross-account propagation path: the
research found NO documented SLA for provider appearance. So the bound
here is minutes, configurable, and recorded next to the result. A
negative at 180s is a much more expensive claim than a negative at 16s
and is worth the wait exactly once.

WHAT THIS PROBE IS NOT
----------------------
Not a T-19 result and not an E-2 result. It decides whether the sentence
"the recipient cannot see the provider" may name a direction. It also
leaves behind, with --keep, a verified D2D chain in each direction that
tests/t19_ingress_d2d.py and the proposed tests/e2_egress_d2d.py can both
build on instead of reconstructing.
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
OUT = REPO / "evidence" / "d2d-direction-symmetry.json"

TAG = "awoz1227_p18"

# Probe 15's --keep run left these behind on glovashu. They are a SECOND
# live D2D grant pointed at the primary, which would make an ingress
# result here ambiguous about which chain surfaced -- so they are named
# here and removable with --clean-p15 rather than left to collide.
P15_SHARE = "awoz1227_p15_share"
P15_RECIPIENT = "awoz1227_p15_recipient"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def load_probe(filename, modname):
    """Reuse, never re-implement.

    Probe 15 already owns the verdict vocabulary that separates "the
    platform declined" from "the thing was absent" from "we called the
    wrong endpoint" (B-20), and probe 14 owns the one HTTP helper whose
    error-handling semantics the evidence depends on. A second copy of
    either in this file would eventually disagree with the original, and
    the disagreement would show up as a verdict in an evidence file
    rather than as a crash.
    """
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this probe reuses its helpers.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P15 = load_probe("15_probe_d2d_prereqs.py", "probe15")
P14 = load_probe("14_probe_d2o_provider_import.py", "probe14")
call = P14.call
step = P15.step
PERMITTED = P15.PERMITTED
NOT_ATTEMPTED = P15.NOT_ATTEMPTED
ABSENT = P15.ABSENT
classify_refusal = P15.classify_refusal


def register_created(name):
    """Feed probe 15's cross-check registry, not a local copy of it.

    P15.classify_refusal consults P15.CREATED_THIS_RUN to tell a real 404
    from our own namespace mistake. If this file kept its own set, every
    endpoint bug made here would be filed as a platform refusal -- which
    is precisely the attribution error B-20 exists to prevent.
    """
    P15.register_created(name)


# =====================================================================
# EXISTING-OBJECT TOLERANCE
# =====================================================================
# This probe is meant to be re-run, and re-run in two directions, which
# means a leftover share from an interrupted run must not read as a
# refusal. But "already exists" must also not read as PERMITTED without
# saying so: a share created by an earlier run may hold different
# objects or a different grant, and silently adopting it would make the
# read-backs describe a chain this run did not build.
EXISTS = "PERMITTED_PREEXISTING"
EXISTS_HINTS = ("already exists", "already_exists", "resource_already_exists")


def create_or_adopt(bucket, name, host, token, path, body, label):
    status, payload = call(host, token, path, "POST", body)
    if status in (200, 201):
        bucket[label] = {"status": status, "verdict": PERMITTED}
        register_created(name)
        print(f"    [ok ] {label}: {PERMITTED} ({status})")
        return True
    code, msg = P15.err(payload)
    if status == 409 or any(h in f"{code} {msg}".lower() for h in EXISTS_HINTS):
        bucket[label] = {
            "status": status,
            "verdict": EXISTS,
            "error_code": code,
            "message": msg[:300],
            "means": ("The object was already there from an earlier run. "
                      "Treated as satisfied so the chain can proceed, but "
                      "recorded distinctly: this run did not create it, so "
                      "its contents and grants are only as this run's "
                      "read-backs find them, not as this run set them."),
        }
        register_created(name)
        print(f"    [ok ] {label}: {EXISTS} ({status}) -- adopted")
        return True
    return step(bucket, label, status, payload)


# =====================================================================
# ONE DIRECTION, END TO END
# =====================================================================

def side_table(cat, sch, tbl):
    if not (cat and tbl):
        return None
    return f"{cat}.{sch or 'default'}.{tbl}"


def find_warehouse(host, token):
    status, payload = call(host, token, "/api/2.0/sql/warehouses")
    if status != 200:
        return None
    for wh in (payload.get("warehouses") or []):
        return wh.get("id")
    return None


def sql(host, token, warehouse_id, statement, wait="30s"):
    """Run one statement and return (rows, raw). Used only as a SECOND
    instrument on the visibility question.

    REST and SQL reaching the same answer matters: `SHOW PROVIDERS` is
    what CONOPS 2.4.1 actually prescribes, and GET /providers is what
    this tooling uses. If they ever disagree, the disagreement is the
    finding -- and if only one is ever consulted, we can never know.
    """
    status, payload = call(
        host, token, "/api/2.0/sql/statements", "POST",
        {"statement": statement, "warehouse_id": warehouse_id,
         "wait_timeout": wait, "on_wait_timeout": "CANCEL"})
    if status != 200:
        return None, {"status": status, "payload": payload}
    state = ((payload.get("status") or {}).get("state") or "").upper()
    if state != "SUCCEEDED":
        return None, {"status": status, "state": state,
                      "error": (payload.get("status") or {}).get("error")}
    data = (payload.get("result") or {}).get("data_array") or []
    return data, {"status": status, "state": state}


def build_chain(provider, recipient_identifier, res, source_table):
    """share -> table -> recipient -> grant, then read all four back.

    Same four separable permissions probe 15 records, and the same rule:
    a 200 on a mutation is not the finding, the re-read is (B-23, after
    script 16 established it). Re-stated here rather than assumed,
    because this probe's whole output is a comparison between two
    directions and a comparison between one verified chain and one
    unverified chain compares nothing.
    """
    host, token = provider["host"], provider["token"]
    share = f"{TAG}_{provider['slug']}_share"
    rcpt = f"{TAG}_{provider['slug']}_recipient"
    res["objects"] = {"share": share, "recipient": rcpt,
                      "source_table": source_table}
    res["steps"] = {}
    s = res["steps"]
    created = {"share": False, "recipient": False}

    created["share"] = create_or_adopt(
        s, share, host, token, "/api/2.1/unity-catalog/shares",
        {"name": share,
         "comment": "E1 direction-symmetry probe (scripts/18) -- "
                    "safe to delete"},
        "create_share")

    if created["share"] and source_table:
        status, payload = call(
            host, token, f"/api/2.1/unity-catalog/shares/{share}", "PATCH",
            {"updates": [{"action": "ADD",
                          "data_object": {"name": source_table,
                                          "data_object_type": "TABLE"}}]})
        # An ADD of a table already in the share is not a refusal of the
        # capability; adopt it the same way as the share itself.
        code, msg = P15.err(payload)
        if status not in (200, 201) and any(
                h in f"{code} {msg}".lower() for h in EXISTS_HINTS):
            s["add_table_to_share"] = {
                "status": status, "verdict": EXISTS,
                "error_code": code, "message": msg[:300]}
            print(f"    [ok ] add_table_to_share: {EXISTS} ({status})")
        else:
            step(s, "add_table_to_share", status, payload)
    else:
        s["add_table_to_share"] = {
            "verdict": NOT_ATTEMPTED,
            "means": ("No share to add to, or no source table resolved on "
                      "the provider side. NOT_ATTEMPTED, never a verdict: "
                      "a step that did not run must not read as a step "
                      "that passed (B-10a)."),
        }
        print("    [---] add_table_to_share: NOT_ATTEMPTED")

    created["recipient"] = create_or_adopt(
        s, rcpt, host, token, "/api/2.1/unity-catalog/recipients",
        {"name": rcpt,
         "authentication_type": "DATABRICKS",
         "data_recipient_global_metastore_id": recipient_identifier,
         "comment": "E1 direction-symmetry probe (scripts/18) -- "
                    "safe to delete"},
        "create_recipient")

    if created["share"] and created["recipient"]:
        # Share-SCOPED permissions endpoint. The generic
        # /api/2.1/unity-catalog/permissions/share/{name} path resolves
        # `principal` against ACCOUNT identities -- users, groups, service
        # principals -- and a share recipient is none of those, so it
        # returns 404 PRINCIPAL_DOES_NOT_EXIST for a recipient that
        # plainly exists. Probe 15 run 2 lost a run to that and the error
        # text reads exactly like a capability limit. B-20.
        status, payload = call(
            host, token,
            f"/api/2.1/unity-catalog/shares/{share}/permissions", "PATCH",
            {"changes": [{"principal": rcpt, "add": ["SELECT"]}]})
        step(s, "grant_share_to_recipient", status, payload)

        status, payload = call(
            host, token,
            f"/api/2.1/unity-catalog/shares/{share}/permissions")
        assigns = (payload or {}).get("privilege_assignments") or []
        granted = {a.get("principal"): a.get("privileges") for a in assigns}
        in_effect = "SELECT" in (granted.get(rcpt) or [])
        s["grant_readback"] = {
            "status": status,
            "privilege_assignments": assigns,
            "privileges": granted.get(rcpt),
            "verdict": "GRANT_IN_EFFECT" if in_effect
                       else "GRANT_NOT_IN_EFFECT",
        }
        print(f"    [{'ok ' if in_effect else 'REF'}] grant_readback: "
              f"{s['grant_readback']['verdict']} -> "
              f"{granted.get(rcpt) or 'recipient not listed'}")

        status, payload = call(
            host, token,
            f"/api/2.1/unity-catalog/shares/{share}?include_shared_data=true")
        objs = (payload or {}).get("objects") or []
        names = [o.get("name") for o in objs]
        s["share_contents_readback"] = {
            "status": status,
            "objects": names,
            "statuses": [o.get("status") for o in objs],
            "verdict": "SHARE_NON_EMPTY" if names else "SHARE_EMPTY",
        }
        print(f"    [{'ok ' if names else 'REF'}] share_contents_readback: "
              f"{s['share_contents_readback']['verdict']} -> "
              f"{names or 'no objects'} "
              f"{s['share_contents_readback']['statuses']}")

        status, payload = call(
            host, token, f"/api/2.1/unity-catalog/recipients/{rcpt}")
        got = (payload or {}).get("data_recipient_global_metastore_id")
        s["recipient_readback"] = {
            "status": status,
            "data_recipient_global_metastore_id": got,
            "expected": recipient_identifier,
            "matches_recipient_side": got == recipient_identifier,
            "authentication_type": (payload or {}).get("authentication_type"),
            "activated": (payload or {}).get("activated"),
            "means": ("A recipient naming the wrong metastore grants "
                      "cleanly and is invisible on the side we then watch "
                      "-- indistinguishable from a visibility failure "
                      "without this read-back."),
        }
        print(f"    [{'ok ' if got == recipient_identifier else 'REF'}] "
              f"recipient_readback: "
              f"{'identifier matches the recipient side' if got == recipient_identifier else f'MISMATCH {got!r}'}")
    else:
        for k in ("grant_share_to_recipient", "grant_readback",
                  "share_contents_readback", "recipient_readback"):
            s[k] = {"verdict": NOT_ATTEMPTED,
                    "means": "Needs both a share and a recipient."}
        print("    [---] grant + read-backs: NOT_ATTEMPTED")

    return share, rcpt, created


def watch_for_provider(recipient, res, poll_seconds, poll_interval):
    """Does the recipient side see a provider? Two instruments, one bound.

    The bound is reported WITH the negative. "None" alone is ambiguous
    between nothing-was-offered, not-yet-propagated and cannot-see;
    "none after N polls over T seconds" excludes the middle reading up to
    T, which is what makes it reportable (B-21).
    """
    host, token = recipient["host"], recipient["token"]
    deadline = time.time() + poll_seconds
    polls, names, status, payload = 0, [], None, None
    started = time.time()
    # Retrying through a refusal is worse than useless: it spends the
    # whole bound and then reports "none after 180s", which reads as an
    # empty list when it means the call never succeeded. Those are the two
    # readings 12.9 is about, and a long poll is exactly where they get
    # confused. Only transient statuses are worth another attempt.
    TRANSIENT = (429, 500, 502, 503, 504)
    while True:
        polls += 1
        status, payload = call(host, token, "/api/2.1/unity-catalog/providers")
        if status == 200:
            names = [p.get("name") for p in (payload.get("providers") or [])]
            if names:
                break
        elif status not in TRANSIENT:
            break
        if time.time() + poll_interval > deadline:
            break
        print(f"          ... poll {polls}: "
              f"{'none yet' if status == 200 else f'status {status}'} "
              f"({round(time.time() - started)}s elapsed)")
        time.sleep(poll_interval)
    elapsed = round(time.time() - started, 1)

    res["rest_list_providers"] = {}
    ok = step(res["rest_list_providers"], "GET /providers", status, payload)
    res["rest_list_providers"]["providers_visible"] = names
    res["rest_list_providers"]["polling"] = {
        "polls": polls,
        "interval_seconds": poll_interval,
        "bound_seconds": poll_seconds,
        "elapsed_seconds": elapsed,
        "stopped_because": ("provider appeared" if names
                            else "bound reached"),
    }
    print(f"          REST providers: {names or 'none'} "
          f"(after {polls} poll(s) over {elapsed}s, bound {poll_seconds}s)")

    # Second instrument: the call CONOPS 2.4.1 actually prescribes.
    wh = find_warehouse(host, token)
    if not wh:
        res["sql_show_providers"] = {
            "verdict": NOT_ATTEMPTED,
            "means": ("No SQL warehouse on the recipient side, so 2.4.1's "
                      "own confirming call could not be run. The REST "
                      "result stands alone and is therefore "
                      "single-instrument -- record it that way rather "
                      "than implying the two agreed."),
        }
        print("          SQL SHOW PROVIDERS: NOT_ATTEMPTED (no warehouse)")
    else:
        rows, raw = sql(host, token, wh, "SHOW PROVIDERS")
        sql_names = [r[0] for r in rows] if rows else []
        ran = rows is not None
        res["sql_show_providers"] = {
            "warehouse_id": wh,
            "raw": raw,
            "rows": sql_names,
            "verdict": ("PROVIDERS_LISTED" if sql_names else
                        "EMPTY" if ran else "UNAVAILABLE"),
        }
        if ran:
            agree = sorted(sql_names) == sorted(names)
            res["instrument_agreement"] = {
                "rest": names,
                "sql": sql_names,
                "agree": agree,
                "means": ("Two independent instruments on the same "
                          "question. Agreement removes 'we used the wrong "
                          "call' as an explanation for an empty list. "
                          "DISAGREEMENT would itself be the finding and "
                          "outrank everything else in this file."),
            }
            print(f"          SQL SHOW PROVIDERS: {sql_names or 'none'} "
                  f"({'instruments agree' if agree else 'INSTRUMENTS DISAGREE'})")
        else:
            # A statement that never SUCCEEDED yields an empty row list,
            # and an empty row list compared against an empty REST list
            # would have printed "instruments agree" -- two instruments
            # appearing to corroborate each other when only one ran. The
            # strongest sentence in this file ("both instruments agree the
            # list is empty") would then have been manufactured by a
            # failed warehouse. Second-instrument corroboration is claimed
            # only when the second instrument actually reported.
            res["instrument_agreement"] = {
                "rest": names,
                "sql": None,
                "agree": None,
                "means": ("The SQL statement did not reach SUCCEEDED, so "
                          "there is NO second instrument for this run. The "
                          "REST result stands alone. Do not read the "
                          "absence of a disagreement as an agreement."),
            }
            print(f"          SQL SHOW PROVIDERS: UNAVAILABLE "
                  f"({raw}) -- single-instrument result")

    for name in names:
        status, payload = call(
            host, token, f"/api/2.1/unity-catalog/providers/{name}/shares")
        bucket = {}
        if step(bucket, f"shares_in_{name}", status, payload):
            bucket[f"shares_in_{name}"]["shares"] = [
                sh.get("name") for sh in (payload.get("shares") or [])]
            print(f"          shares in {name}: "
                  f"{bucket[f'shares_in_{name}']['shares']}")
        res.setdefault("provider_shares", {}).update(bucket)
    return names


def run_direction(direction, sides, args):
    provider = sides["primary"] if direction == "egress" else sides["glovashu"]
    recipient = sides["glovashu"] if direction == "egress" else sides["primary"]

    print()
    print("=" * 68)
    print(f"DIRECTION: {direction}")
    print(f"  provider : {provider['label']}  {provider['host']}")
    print(f"  recipient: {recipient['label']}  {recipient['host']}")
    print(f"  recipient global_metastore_id: {recipient['identifier']}")
    print("=" * 68)

    res = {
        "direction": direction,
        "run_at": now(),
        "provider": {"label": provider["label"], "host": provider["host"],
                     "identifier": provider["identifier"],
                     "delta_sharing_scope": provider["scope"]},
        "recipient": {"label": recipient["label"], "host": recipient["host"],
                      "identifier": recipient["identifier"],
                      "delta_sharing_scope": recipient["scope"]},
        # Both scopes recorded on purpose. Whether the RECIPIENT metastore
        # also needs INTERNAL_AND_EXTERNAL is NOT DOCUMENTED anywhere the
        # research could find. Recording both sides every run means the
        # question gets answered by accumulated data instead of by
        # somebody's recollection.
        "scope_note": ("Provider-side INTERNAL_AND_EXTERNAL is required and "
                       "documented. Any recipient-side requirement is "
                       "undocumented; both sides are recorded so a future "
                       "run with differing scopes can settle it."),
    }

    table = side_table(provider["catalog"], provider["schema"],
                       provider["table"])
    if not table:
        res["source_table"] = {
            "verdict": ABSENT,
            "means": (f"No source table resolvable for {provider['label']}. "
                      f"Set the catalog/schema/table .env values for that "
                      f"side; without a table the chain cannot be completed "
                      f"and this direction cannot serve as a control."),
        }
        print(f"    [abs] source_table: ABSENT for {provider['label']}")
        res["conclusion"] = {"chain": "BLOCKED", "provider_visible": None}
        return res

    print(f"\n  [1/3] Provider-side table: {table}")
    status, payload = call(provider["host"], provider["token"],
                           f"/api/2.1/unity-catalog/tables/{table}")
    res["source_table"] = {}
    if step(res["source_table"], "lookup", status, payload):
        res["source_table"]["table_type"] = payload.get("table_type")
        res["source_table"]["data_source_format"] = \
            payload.get("data_source_format")
        print(f"          {table} is {payload.get('table_type')} / "
              f"{payload.get('data_source_format')}")
    else:
        res["conclusion"] = {"chain": "BLOCKED", "provider_visible": None}
        return res

    print(f"\n  [2/3] Build the complete chain on {provider['label']}")
    share, rcpt, created = build_chain(provider, recipient["identifier"],
                                       res, table)

    print(f"\n  [3/3] Watch {recipient['label']} for the provider "
          f"(bound {args.poll_seconds}s)")
    res["visibility"] = {}
    names = watch_for_provider(recipient, res["visibility"],
                               args.poll_seconds, args.poll_interval)

    s = res["steps"]
    chain_keys = ("create_share", "add_table_to_share", "create_recipient",
                  "grant_share_to_recipient")
    chain_ok = all((s.get(k) or {}).get("verdict") in (PERMITTED, EXISTS)
                   for k in chain_keys)
    verified = {
        "grant": (s.get("grant_readback") or {}).get("verdict")
                 == "GRANT_IN_EFFECT",
        "share_contents": (s.get("share_contents_readback") or {}).get(
            "verdict") == "SHARE_NON_EMPTY",
        "recipient_identifier": (s.get("recipient_readback") or {}).get(
            "matches_recipient_side") is True,
    }
    all_verified = all(verified.values())

    # The confound list is DERIVED, never written in advance. A sentence
    # typed before the run describes the run its author imagined -- probe
    # 15 printed "share was EMPTY" in a run whose own evidence file
    # recorded the table as added, and wrote the false sentence to disk
    # (B-23b).
    confounds = []
    if not chain_ok:
        confounds.append("the chain itself did not complete, so there was "
                         "nothing to surface")
    if not verified["share_contents"]:
        confounds.append("the share read back with no objects")
    if not verified["grant"]:
        confounds.append("the grant read back as not in effect")
    if not verified["recipient_identifier"]:
        confounds.append("the recipient names a metastore other than the "
                         "side being watched")
    agreement = (res["visibility"].get("instrument_agreement") or {})
    if agreement.get("agree") is False:
        confounds.append("the REST and SQL instruments disagree about the "
                         "provider list, which outranks the visibility "
                         "question and must be resolved first")
    res["instruments"] = (
        "BOTH" if agreement.get("agree") is True else
        "DISAGREE" if agreement.get("agree") is False else "REST_ONLY")

    res["conclusion"] = {
        "chain": "COMPLETE" if chain_ok else "BLOCKED",
        "chain_steps": {k: (s.get(k) or {}).get("verdict")
                        for k in chain_keys},
        "readbacks_verified": verified,
        "provider_visible": bool(names),
        "providers": names,
        "confounds": confounds or None,
        "instruments": res["instruments"],
        "verdict": (
            "PROVIDER_APPEARED" if names else
            "NO_PROVIDER_WITH_CONFOUNDS" if confounds else
            "NO_PROVIDER_CLEAN_NEGATIVE" if res["instruments"] == "BOTH" else
            "NO_PROVIDER_SINGLE_INSTRUMENT"),
        "means": (
            "PROVIDER_APPEARED: this direction surfaces a provider object; "
            "the confirming calls of 2.4.1 are available here. "
            "NO_PROVIDER_CLEAN_NEGATIVE: a complete chain, every link "
            "verified by read-back, both instruments agreeing, bounded "
            "poll -- a finding to chase, not a step to retry, and still "
            "not attributable to DIRECTION until the other direction has "
            "been run. NO_PROVIDER_SINGLE_INSTRUMENT: the same, except "
            "only GET /providers reported, so 'we used the wrong call' is "
            "not yet excluded. NO_PROVIDER_WITH_CONFOUNDS: not usable as "
            "a control; fix the listed confounds and re-run."),
    }
    res["left_in_place"] = None
    res["_cleanup_handles"] = {
        "host": provider["host"], "token_env": provider["token_env"],
        "share": share if created.get("share") else None,
        "recipient": rcpt if created.get("recipient") else None,
    }

    print()
    print(f"  chain: {res['conclusion']['chain']}   "
          f"read-backs: {'all verified' if all_verified else verified}   "
          f"verdict: {res['conclusion']['verdict']}")
    return res


# =====================================================================
# EVIDENCE: never let a later run erase the finding it was derived from
# =====================================================================

def write_evidence(new_results, args):
    """B-19. Script 16's successful --apply overwrote the 400 that proved
    the two-field requirement, and only a terminal scrollback saved it.
    Here the risk is sharper: this file's entire value is a COMPARISON
    between directions, so a second run that clobbered the first would
    destroy the comparison while appearing to produce it.
    """
    doc = {"probe": "d2d-direction-symmetry",
           "task": "E1 Task 1.10 -> T-19 / proposed E-2",
           "run_at": now(),
           "poll_bound_seconds": args.poll_seconds,
           "poll_interval_seconds": args.poll_interval,
           "directions": {}}
    if OUT.exists():
        try:
            prior = json.loads(OUT.read_text())
        except (json.JSONDecodeError, OSError):
            prior = None
        if isinstance(prior, dict):
            doc["directions"] = prior.get("directions") or {}

    for direction, res in new_results.items():
        history = list((doc["directions"].get(direction) or {})
                       .get("prior_attempts") or [])
        existing = doc["directions"].get(direction)
        if existing:
            trimmed = {k: v for k, v in existing.items()
                       if k != "prior_attempts"}
            history.append(trimmed)
        res = dict(res)
        res.pop("_cleanup_handles", None)
        if history:
            res["prior_attempts"] = history
            res["prior_attempts_note"] = (
                "Earlier runs of THIS direction, carried forward. A later "
                "success must never be able to erase the negative it was "
                "derived from (B-19).")
        doc["directions"][direction] = res

    e = (doc["directions"].get("egress") or {}).get("conclusion") or {}
    i = (doc["directions"].get("ingress") or {}).get("conclusion") or {}

    def usable(c):
        """A direction only counts as a control if its chain completed
        and its read-backs verified. A blocked chain that saw no provider
        says nothing about visibility, and letting it into the comparison
        would manufacture a direction finding out of two unrelated
        failures."""
        return c.get("chain") == "COMPLETE" and not c.get("confounds")

    if usable(e) and usable(i):
        ev, iv = e.get("provider_visible"), i.get("provider_visible")
        if ev and not iv:
            verdict, means = "DIRECTION_SPECIFIC", (
                "Egress surfaced a provider and ingress did not, with "
                "complete verified chains on both sides and direction as "
                "the single variable. This licenses a T-19 finding naming "
                "the direction, and it is reportable in v1.6.")
        elif iv and not ev:
            verdict, means = "DIRECTION_SPECIFIC_REVERSED", (
                "Ingress surfaced a provider and egress did not. That "
                "moves the blockage to channel E-2, not T-19, and the "
                "epic's T-19 gate note needs rewriting rather than "
                "confirming.")
        elif ev and iv:
            verdict, means = "BOTH_DIRECTIONS_VISIBLE", (
                "Both directions surface a provider. Probe 15's empty "
                "list was therefore bounded too tightly at 16.5s or was "
                "transient; compare the polling elapsed_seconds here. "
                "T-19 and E-2 both run as specified.")
        else:
            verdict, means = "VISIBILITY_UNVERIFIED", (
                "NEITHER direction surfaced a provider, from a complete "
                "and fully read-back chain in each, within the stated "
                "bound. The honest report is that D2D provider visibility "
                "is UNVERIFIED in this environment. It is NOT a "
                "direction-specific finding and NOT a Free Edition "
                "constraint -- no permitted case exists anywhere in this "
                "repo to contrast against, so the tier reading is "
                "unexcluded and must not be asserted. T-19's confirming "
                "calls (2.4.1's SHOW PROVIDERS / SHOW SHARES IN PROVIDER) "
                "are reported NOT_RUN with this named missing capability, "
                "per the epic's own rule, and the same applies to E-2.")
    else:
        verdict, means = "INSUFFICIENT_EVIDENCE", (
            "Fewer than two usable directions on file. A single direction, "
            "or a direction whose chain was blocked or whose read-backs "
            "did not verify, cannot support any statement about direction "
            "-- that was exactly the error this probe exists to avoid. Run "
            "--direction both, or fix the confounds listed under the "
            "incomplete direction and re-run it.")

    doc["comparison"] = {
        "egress": {"chain": e.get("chain"),
                   "provider_visible": e.get("provider_visible"),
                   "instruments": e.get("instruments"),
                   "usable_as_control": usable(e),
                   "confounds": e.get("confounds")},
        "ingress": {"chain": i.get("chain"),
                    "provider_visible": i.get("provider_visible"),
                    "instruments": i.get("instruments"),
                    "usable_as_control": usable(i),
                    "confounds": i.get("confounds")},
        "single_variable": "direction",
        "verdict": verdict,
        "means": means,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2))
    return doc


# =====================================================================

def cleanup_objects(label, host, token, share, recipient, res):
    """Delete, then verify. A DELETE that returned 200 and left the object
    behind is the 12.9 shape wearing a success code."""
    res[label] = {}
    for kind, path in (("share", f"/api/2.1/unity-catalog/shares/{share}"
                        if share else None),
                       ("recipient",
                        f"/api/2.1/unity-catalog/recipients/{recipient}"
                        if recipient else None)):
        if not path:
            continue
        status, _ = call(host, token, path, "DELETE")
        vstatus, _ = call(host, token, path)
        res[label][kind] = {
            "delete_status": status, "verify_status": vstatus,
            "verdict": ("DELETED" if vstatus == 404 else
                        "STILL_PRESENT" if vstatus == 200 else "UNVERIFIED"),
        }
        print(f"    {label} {kind}: {res[label][kind]['verdict']} "
              f"(delete {status}, verify {vstatus})")


def main():
    ap = argparse.ArgumentParser(
        description="Make direction the single variable in the D2D "
                    "provider-visibility question.")
    ap.add_argument("--direction", choices=("egress", "ingress", "both"),
                    default="both",
                    help="egress = primary provides to glovashu (E-2); "
                         "ingress = glovashu provides to primary (T-19); "
                         "both = run each in turn, which is the only "
                         "setting that can produce a direction verdict.")
    ap.add_argument("--poll-seconds", type=int, default=180,
                    help="How long to watch the recipient side for a "
                         "provider, per direction. Default 180. Probe 15's "
                         "negative was bounded at 16.5s and there is NO "
                         "documented propagation SLA, so the bound is "
                         "minutes here and is recorded next to the result.")
    ap.add_argument("--poll-interval", type=int, default=15,
                    help="Seconds between polls. Default 15.")
    ap.add_argument("--keep", action="store_true",
                    help="Leave the chains in place. Worth doing on the "
                         "run you intend to cite: it leaves a verified D2D "
                         "chain in each direction for tests/t19 and the "
                         "proposed tests/e2 to build on, and leaves "
                         "something for a human to look at in the two "
                         "consoles. Objects carry the "
                         f"{TAG} prefix.")
    ap.add_argument("--clean-p15", action="store_true",
                    help="Remove probe 15's --keep leftovers on glovashu "
                         f"({P15_SHARE}, {P15_RECIPIENT}) before starting. "
                         "They are a second live D2D grant aimed at the "
                         "primary, which would leave an ingress result "
                         "ambiguous about which chain surfaced.")
    args = ap.parse_args()

    P15.load_env()
    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN",
                "GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")

    sides = {
        "primary": {
            "label": "primary", "slug": "primary",
            "host": os.environ["DATABRICKS_HOST"].strip().rstrip("/"),
            "token": os.environ["DATABRICKS_TOKEN"].strip(),
            "token_env": "DATABRICKS_TOKEN",
            "catalog": os.environ.get("UC_METASTORE_CATALOG", "").strip(),
            "schema": os.environ.get("UC_SCHEMA", "").strip(),
            "table": os.environ.get("UC_TABLE", "").strip() or "test_dataset",
        },
        "glovashu": {
            "label": "glovashu", "slug": "glovashu",
            "host": os.environ["GLOVASHU_HOST"].strip().rstrip("/"),
            "token": os.environ["GLOVASHU_TOKEN"].strip(),
            "token_env": "GLOVASHU_TOKEN",
            "catalog": os.environ.get("GLOVASHU_CATALOG", "").strip(),
            "schema": os.environ.get("UC_SCHEMA_GLOVASHU", "").strip(),
            # Same resolution order as scripts 15 and 17. Three scripts
            # resolving one table name by three rules is how a probe ends
            # up reporting a table absent that somebody did create.
            "table": (os.environ.get("GLOVASHU_TABLE", "").strip()
                      or os.environ.get("UC_TABLE", "").strip()
                      or "test_dataset"),
        },
    }

    print("D2D direction-symmetry probe")
    print("=" * 68)
    # Read both identifiers and both scopes LIVE. The stored baseline has
    # one of them, but a hard-coded or stale identifier produces a
    # recipient that names nobody, grants cleanly, and is invisible
    # forever -- a failure mode indistinguishable from the one under
    # investigation.
    for key, side in sides.items():
        status, payload = call(side["host"], side["token"],
                               "/api/2.1/unity-catalog/metastore_summary")
        if status != 200:
            sys.exit(f"Cannot read {key}'s metastore summary "
                     f"(status {status}). Fix credentials before probing.")
        side["identifier"] = payload.get("global_metastore_id")
        side["scope"] = payload.get("delta_sharing_scope")
        side["metastore_id"] = payload.get("metastore_id")
        print(f"  {side['label']:9s} {side['identifier']}  "
              f"scope={side['scope']}")

    if sides["primary"]["metastore_id"] == sides["glovashu"]["metastore_id"]:
        sys.exit("Both hosts report the SAME metastore_id. D2D between one "
                 "metastore and itself is not the thing under test; a "
                 "provider would never appear and the result would be "
                 "meaningless. Check GLOVASHU_HOST and GLOVASHU_TOKEN.")

    if args.clean_p15:
        print("\nRemoving probe 15 leftovers on glovashu")
        tmp = {}
        cleanup_objects("p15", sides["glovashu"]["host"],
                        sides["glovashu"]["token"], P15_SHARE, P15_RECIPIENT,
                        tmp)

    order = (["egress", "ingress"] if args.direction == "both"
             else [args.direction])
    results, handles = {}, {}
    for d in order:
        res = run_direction(d, sides, args)
        handles[d] = res.pop("_cleanup_handles", None)
        results[d] = res

    print()
    print("Cleanup")
    if args.keep:
        for d, h in handles.items():
            if not h:
                continue
            results[d]["left_in_place"] = {
                "host": h["host"], "share": h["share"],
                "recipient": h["recipient"],
                "means": ("--keep was passed. These are LIVE objects and "
                          "must be removed by a run without --keep or by "
                          "hand in the console."),
            }
            print(f"    SKIPPED ({d}): share={h['share']} "
                  f"recipient={h['recipient']} on {h['host']}")
    else:
        cl = {}
        for d, h in handles.items():
            if h and (h["share"] or h["recipient"]):
                cleanup_objects(d, h["host"],
                                os.environ[h["token_env"]].strip(),
                                h["share"], h["recipient"], cl)
        for d in results:
            results[d]["cleanup"] = cl.get(d)
        if not cl:
            print("    nothing was created, so nothing to remove")

    doc = write_evidence(results, args)

    print()
    print("=" * 68)
    for d in order:
        c = results[d]["conclusion"]
        print(f"{d:8s} chain={c.get('chain')}  "
              f"provider_visible={c.get('provider_visible')}  "
              f"{c.get('verdict')}")
        for cf in (c.get("confounds") or []):
            print(f"         confound: {cf}")
    print()
    print(f"DIRECTION VERDICT: {doc['comparison']['verdict']}")
    print(doc["comparison"]["means"])
    print()
    print(f"Wrote {OUT.relative_to(REPO)}")
    print("Then run: python3 scripts/check_secret_hygiene.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
