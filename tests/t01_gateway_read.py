#!/usr/bin/env python3
"""
T-01 -- a recipient reads through the gateway. E1 Task 1.6, AC1/AC2.
CONOPS §2.1 (egress flow), §2.3.2 (channel E-1), §3.4.1 (reference
clients need only the endpoint changed).

WHY THIS TEST IS PER RECIPIENT
------------------------------
Because the upstream is. §2.3.2 draws E-1 as one route with one upstream
target for all recipients, and that cannot be built: each recipient's
issued credential carries its own endpoint hostname, and the platform
validates the host/token binding. docs/11 B-42, docs/10 D-9.

A single-endpoint T-01 would therefore pass or fail for reasons that have
nothing to do with the gateway. It would pass for whichever recipient
happened to match the pinned host, and the same code would report failure
for the other two while the gateway was working correctly. So the route
family is read from gravitee/generated/route-family.json and every
recipient is measured against its own route.

WHY A 200 THROUGH THE GATEWAY IS NOT THE FINDING
------------------------------------------------
§11.7 B-40, learned the hard way on T-21: a positive control must be the
SAME PATH as the subject, not merely the same host. Here it is stronger
than that -- the control is the same path read DIRECTLY, in the same run,
with the same credential, seconds apart. That gives three things a bare
gateway 200 cannot:

  1. Attribution. If the gateway refuses and the direct read also
     refuses, the gateway is not the cause and the result is CANNOT_SEE,
     not a gateway defect. Every other test in this repository that
     lacked this ended up measuring the wrong thing at least once.
  2. Fidelity. §3.4.1's promise is not "the gateway returns 200", it is
     that a reference client needs only the endpoint changed. That is a
     claim about the BODY. A gateway that returns 200 with a mangled or
     truncated body satisfies a status-code test and breaks every client.
  3. A free before-picture for T-07. The direct response's headers and
     the gateway response's headers are both captured, so what the
     perimeter stripped and what it leaked are observable rather than
     asserted. This test does NOT grade T-07 -- it records the input T-07
     needs.

WHAT IS COMPARED, AND WHAT IS DELIBERATELY NOT
----------------------------------------------
Class A metadata routes are compared BYTE FOR BYTE. They are
deterministic, so any difference is the gateway's.

S8 (query) is not, and comparing it byte-wise would guarantee a false
difference: the response carries freshly signed storage URLs whose
signature changes per request. For S8 the comparison is on the SCHEMA and
the row count parsed out of the ndjson, and the body is withheld from
evidence entirely -- a pre-signed URL is a credential (see
scripts/check_secret_hygiene.py's own note on why), and this test must
not be the place one gets committed.

PHASE 2 TURNS B-42 FROM AN OBSERVATION INTO A MEASUREMENT
---------------------------------------------------------
B-42 was found by accident: a request went to the wrong host and the
platform named the mismatch. Phase 2 does it on purpose, with a control.
Recipient A's credential is sent to recipient B's gateway route, and the
same credential is sent to A's own route in the same run. One variable:
which route. If the first is refused and the second succeeds, the
host/recipient binding is ENFORCED and D-9's premise is measured rather
than inferred.

    python3 tests/t01_gateway_read.py
    python3 tests/t01_gateway_read.py --recipient psp7-t2-us
    python3 tests/t01_gateway_read.py --skip-binding-probe
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from common import Report, load_env  # noqa: E402

FAMILY = ROOT / "gravitee" / "generated" / "route-family.json"
SECRETS = ROOT / "_secrets"
EVIDENCE = ROOT / "evidence" / "t01-gateway-read.json"
REPORT = ROOT / "evidence" / "t01-report.json"


def load_sibling(filename, modname):
    spec = importlib.util.spec_from_file_location(modname, ROOT / "tests" / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


T02 = load_sibling("t02_ip_access_list.py", "t01_t02")
scrub = T02.scrub


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------
# Transport. Separate from T-02's helper because this test needs the
# RESPONSE HEADERS, which T02.sharing_get discards.
# ---------------------------------------------------------------------

def http(url, bearer, method="GET", body=None, timeout=45):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except urllib.error.URLError as e:
        return 0, json.dumps({"error_code": "LOCAL_URLERROR",
                              "message": str(e.reason)}), {}
    except Exception as e:  # noqa: BLE001
        return 0, json.dumps({"error_code": type(e).__name__,
                              "message": str(e)}), {}


# ---------------------------------------------------------------------
# WHO ANSWERED. Added 2026-10-21 after the first run (§11.7 B-44).
#
# The first run read eight paths per recipient, got 404 on every one
# through the gateway, and reported GATEWAY_REFUSED_DIRECT_SUCCEEDED --
# "attributable: one variable, the edge". It was not the edge. A
# superseded API occupying /opensharing-demo/ prefix-matched every new
# path, FORWARDED it, and glued the recipient slug into the protocol
# path, so the 404 came from Databricks:
#
#   {"error_code":"ENDPOINT_NOT_FOUND","message":"No API found for
#    'GET /opensharing/metastores/48cda780-.../psp7-t2-us/shares'", ...}
#
# An edge refusal and an upstream refusal forwarded THROUGH the edge are
# the same status code with opposite remedies -- one means fix the
# policy, the other means fix the target -- and the first version of this
# test could not tell them apart. That is §11.7 B-20's failure mode:
# a verdict vocabulary too coarse to name the cause fails toward blaming
# the nearest thing, and the nearest thing was the gateway.
#
# Two independent discriminators, both observed rather than assumed:
#
#   1. Vocabulary. Gravitee's own unmatched-path refusal is text/plain,
#      body "No context-path matches the request URI.". Databricks
#      answers JSON carrying `error_code` and a `details[].@type` of
#      type.googleapis.com/google.rpc.*.
#   2. Round-trip headers. The unmatched-path 404 carries NO
#      x-gravitee-* headers. A response that was proxied carries them.
#
# Two signals because one is a single point of failure: either vocabulary
# could change in a platform upgrade, and a disagreement between the two
# is itself worth seeing rather than silently resolving.
# ---------------------------------------------------------------------
GRAVITEE_NO_CONTEXT = re.compile(r"no context-path matches", re.IGNORECASE)
UPSTREAM_VOCAB = re.compile(r'"error_code"|type\.googleapis\.com/google\.rpc',
                            re.IGNORECASE)
# Added 2026-10-21 from T-03's observed refusal body. This is a POSITIVE
# identification of one named policy, which is what the classifier was
# missing: see B-46. The policy also reports the address it saw, and the
# capture group is kept because that address turned out to matter more
# than the refusal did (B-47).
GRAVITEE_IP_FILTER = re.compile(
    r"Your IP \(([^)]*)\)[^.]*are not allowed to reach this resource",
    re.IGNORECASE)
# Added 2026-10-21 from the resource-filtering policy's observed refusal
# body, measured live on the AI route:
#
#   {"message":"You're not allowed to access this resource",
#    "http_status_code":403}
#
# Same reason as the ip-filtering pattern above: without it, a 403 issued
# by this policy lands in the `EDGE_POLICY_OR_PROXY_ERROR` catch-all --
# the label B-46 says must never be admissible as evidence, because a
# proxy failure wears it too. T-16's whole claim is "the edge refused
# THIS path by THIS decision", and a catch-all cannot carry that.
#
# Deliberately NOT anchored on the 403: the policy's status is
# configurable, and a test that recognised the policy only at its default
# status would stop recognising it the moment someone changed the status
# -- and would then report a refusal it could not attribute, which reads
# as the deny not working.
#
# Note the two refusal texts differ by one word -- ip-filtering says
# "reach this resource", resource-filtering says "access this resource"
# -- so the patterns are kept separate and both capture their own
# wording rather than sharing a loosened one.
GRAVITEE_RESOURCE_FILTER = re.compile(
    r"you're not allowed to access this resource", re.IGNORECASE)


def classify_responder(raw, headers, status=None):
    """Attribute a response to the party that produced it.

    `status` is optional only for backward compatibility and SHOULD be
    passed. B-46: this function was written for non-2xx responses and
    will happily label a 200 `EDGE_POLICY_OR_PROXY_ERROR`, because that
    branch is the catch-all for "round-tripped the edge, vocabulary
    unrecognised" -- and a successful body is of course unrecognised.
    A label that a success and a policy refusal can both carry is not an
    attribution, and T-03's first verdict accepted exactly that label as
    positive proof the edge had refused. It was right, but not for the
    reason it checked."""
    hl = {k.lower() for k in (headers or {})}
    round_trip = any(h.startswith("x-gravitee-") for h in hl)
    vocab_upstream = bool(UPSTREAM_VOCAB.search(raw or ""))
    vocab_edge = bool(GRAVITEE_NO_CONTEXT.search(raw or ""))
    ipf = GRAVITEE_IP_FILTER.search(raw or "")
    rsf = GRAVITEE_RESOURCE_FILTER.search(raw or "")
    out = {"round_trip_headers": round_trip,
           "vocabulary": "UPSTREAM" if vocab_upstream else
                         ("EDGE_IP_FILTERING" if ipf else
                          ("EDGE_RESOURCE_FILTERING" if rsf else
                           ("EDGE_NO_CONTEXT_PATH" if vocab_edge else
                            "UNRECOGNISED")))}
    if status is not None and 200 <= int(status) < 300:
        out["responder"] = "NOT_A_REFUSAL"
        out["meaning"] = (
            "A 2xx. There is no refusing party to attribute, and this "
            "function must not invent one. B-46."
        )
        return out
    if ipf:
        out["responder"] = "EDGE_IP_FILTERING_POLICY"
        out["observed_client_ip"] = ipf.group(1)
        out["meaning"] = (
            "Gravitee's ip-filtering policy refused this request, by "
            "name and in its own words. This is a POSITIVE "
            "identification of one named policy, not the catch-all -- "
            "the distinction B-46 exists to preserve. The policy also "
            "reports the address it observed, which is the address the "
            "allow-list is actually matched against."
        )
        return out
    if rsf:
        out["responder"] = "EDGE_RESOURCE_FILTERING_POLICY"
        out["meaning"] = (
            "Gravitee's resource-filtering policy refused this request "
            "by path, in its own words. A POSITIVE identification of one "
            "named policy, not the catch-all (B-46). This policy decides "
            "on the request PATH alone -- it says nothing about the "
            "caller's identity, so a refusal here is not an "
            "authorisation result and must not be read as one."
        )
        out["decided_on"] = "REQUEST_PATH_ONLY"
        return out
    if vocab_edge and not round_trip:
        out["responder"] = "EDGE_NO_ROUTE_MATCHED"
        out["meaning"] = (
            "No API on the gateway claims this path. Nothing was "
            "forwarded, so this says nothing about any upstream."
        )
    elif vocab_upstream and round_trip:
        out["responder"] = "UPSTREAM_VIA_THE_EDGE"
        out["meaning"] = (
            "The edge matched a route and forwarded; the answer is the "
            "upstream's. A refusal here is a TARGET problem, not a "
            "policy problem."
        )
    elif vocab_upstream and not round_trip:
        out["responder"] = "UPSTREAM_DIRECT_OR_HEADERS_STRIPPED"
        out["meaning"] = (
            "Upstream vocabulary with no round-trip headers. Either this "
            "was not proxied, or the header sanitizer removed the "
            "evidence of the round trip -- which would mean T-07's "
            "policy is destroying attribution. Both are worth knowing; "
            "neither is assumed."
        )
    elif round_trip:
        out["responder"] = "EDGE_POLICY_OR_PROXY_ERROR"
        out["meaning"] = (
            "The edge handled it and answered in its own voice. A policy "
            "refusal or a proxy failure -- the gateway is the subject."
        )
    else:
        out["responder"] = "UNATTRIBUTED"
        out["meaning"] = (
            "Neither vocabulary nor headers identify the responder. "
            "Recorded as unattributed rather than assigned to the "
            "nearest component."
        )
    return out


# Headers the perimeter is supposed to strip, per
# iac/config/policy-classes.yaml common.response. Observed, not graded:
# T-07 is the test that grades them and it is not this test.
LEAK_HEADERS = [
    "server", "via", "server-timing", "x-request-id",
    "x-databricks-org-id", "x-databricks-request-id",
    "x-gravitee-request-id", "x-gravitee-transaction-id",
]
# §2.3.2 requires this one to SURVIVE the sanitizer on S7. A perimeter
# that strips everything unrecognised takes it too, and the failure is
# invisible until a reference client stops negotiating formats.
PASSTHROUGH_HEADERS = ["delta-sharing-capabilities"]


def header_observation(direct_h, gw_h):
    dl = {k.lower(): v for k, v in (direct_h or {}).items()}
    gl = {k.lower(): v for k, v in (gw_h or {}).items()}
    return {
        "leaked_through_gateway": sorted(h for h in LEAK_HEADERS if h in gl),
        "present_direct_only": sorted(h for h in LEAK_HEADERS if h in dl and h not in gl),
        "passthrough_survived": sorted(h for h in PASSTHROUGH_HEADERS if h in gl),
        "passthrough_present_direct": sorted(h for h in PASSTHROUGH_HEADERS if h in dl),
        "this_is_not_t07": (
            "Recorded as T-07's input, not as T-07's verdict. A header "
            "absent from the gateway response may have been stripped by "
            "the perimeter or never sent by the upstream, and those are "
            "the same observation unless the direct response is captured "
            "beside it -- which is why present_direct_only exists."
        ),
    }


# ---------------------------------------------------------------------
# Edge base
# ---------------------------------------------------------------------

def edge_base():
    """route-table.yaml names GRAVITEE_EDGE_BASE as the source. It is not
    in .env; what is there is GRAVITEE_GATEWAY_EDGE_URL, and that value
    still points at /delta-sharing -- the listener route-table.yaml marks
    RETIRED. Deriving scheme+host from it and dropping the path is
    correct and is recorded as DERIVED so nobody mistakes it for a
    declared value."""
    explicit = os.environ.get("GRAVITEE_EDGE_BASE")
    if explicit:
        return explicit.rstrip("/"), "ENV_EXPLICIT", None
    raw = os.environ.get("GRAVITEE_GATEWAY_EDGE_URL", "http://localhost:8082")
    m = re.match(r"^(https?://[^/]+)", raw)
    base = (m.group(1) if m else raw).rstrip("/")
    note = None
    if "/delta-sharing" in raw:
        note = (
            "GRAVITEE_GATEWAY_EDGE_URL still names /delta-sharing, the "
            "listener route-table.yaml marks as RETIRED (B-1). Only its "
            "scheme and host were used. .env should gain "
            f"GRAVITEE_EDGE_BASE={base} so this is declared rather than "
            "derived."
        )
    return base, "DERIVED_FROM_GATEWAY_EDGE_URL", note


# ---------------------------------------------------------------------
# Path discovery -- the B-40 lesson applied up front
# ---------------------------------------------------------------------

def discover_paths(endpoint, bearer):
    """Build the real protocol paths for S1-S8 from what this credential
    can actually see. Hardcoding a share name is what made T-21's first
    run worthless: the seven mutations were aimed at a share the chosen
    credential had no grant on, so every 404 meant 'no such share for
    you' and the test proved nothing."""
    out = {"verdict": None, "paths": {}, "share": None,
           "schema": None, "table": None}
    st, raw, _ = http(endpoint.rstrip("/") + "/shares", bearer)
    out["shares_status"] = st
    if st != 200:
        out["verdict"] = "CANNOT_SEE_SHARES_LIST_FAILED"
        out["detail"] = scrub(raw)[:300]
        return out
    try:
        shares = [s.get("name") for s in (json.loads(raw).get("items") or [])]
    except (json.JSONDecodeError, AttributeError):
        out["verdict"] = "CANNOT_SEE_SHARES_LIST_UNPARSABLE"
        return out
    out["shares_visible"] = shares
    out["paths"]["S1"] = "/shares"
    for share in shares:
        st, raw, _ = http(endpoint.rstrip("/") + f"/shares/{share}/schemas", bearer)
        if st != 200:
            continue
        try:
            schemas = [s.get("name") for s in (json.loads(raw).get("items") or [])]
        except (json.JSONDecodeError, AttributeError):
            continue
        for schema in schemas:
            p = f"/shares/{share}/schemas/{schema}/tables"
            st, raw, _ = http(endpoint.rstrip("/") + p, bearer)
            if st != 200:
                continue
            try:
                tables = [t.get("name") for t in (json.loads(raw).get("items") or [])]
            except (json.JSONDecodeError, AttributeError):
                continue
            for table in tables:
                stem = f"/shares/{share}/schemas/{schema}/tables/{table}"
                st, _, _ = http(endpoint.rstrip("/") + stem + "/metadata", bearer)
                if st != 200:
                    continue
                out.update({"verdict": "PATHS_DISCOVERED", "share": share,
                            "schema": schema, "table": table})
                out["paths"].update({
                    "S2": f"/shares/{share}",
                    "S3": f"/shares/{share}/schemas",
                    "S4": p,
                    "S5": f"/shares/{share}/all-tables",
                    "S6": stem + "/version",
                    "S7": stem + "/metadata",
                    "S8": stem + "/query",
                })
                return out
    out["verdict"] = "CANNOT_SEE_NO_READABLE_TABLE"
    return out


# ---------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------
BYTE_COMPARABLE = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]


def summarise_query(raw):
    """Parse the ndjson query response into the two things that are
    stable across requests: the schema and the row count. Everything
    else in that body -- the file URLs, their expiry, their ids -- is
    per-request by design, so comparing it would manufacture a
    difference and blame the gateway for it."""
    out = {"lines": 0, "schema_fields": None, "num_records": None,
           "files": 0, "stats_complete": None}
    fields, total, files, missing = None, 0, 0, False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        out["lines"] += 1
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "metaData" in obj:
            ss = (obj["metaData"] or {}).get("schemaString")
            if ss:
                try:
                    fields = [f.get("name") for f in (json.loads(ss).get("fields") or [])]
                except (json.JSONDecodeError, AttributeError):
                    fields = "UNPARSABLE"
        if "file" in obj:
            files += 1
            stats = (obj["file"] or {}).get("stats")
            n = None
            if isinstance(stats, str):
                try:
                    n = json.loads(stats).get("numRecords")
                except json.JSONDecodeError:
                    n = None
            elif isinstance(stats, dict):
                n = stats.get("numRecords")
            if n is None:
                missing = True
            else:
                total += int(n)
    out["schema_fields"] = fields
    out["files"] = files
    out["stats_complete"] = not missing
    # A row count assembled from incomplete stats is a guess wearing a
    # number's clothes. Report the absence instead -- T-04 made the same
    # choice for the same reason.
    out["num_records"] = None if missing else total
    out["body_withheld_because"] = (
        "The query response carries freshly signed storage URLs. A "
        "pre-signed URL is a credential -- it carries an access key id "
        "and a signature and needs no other authentication -- so it is "
        "summarised here and never written to evidence."
    )
    return out


def compare_one(route_id, direct_url, gw_url, bearer):
    d_st, d_raw, d_h = http(direct_url, bearer,
                            method="POST" if route_id == "S8" else "GET",
                            body={} if route_id == "S8" else None)
    # Status 0 is a LOCAL transport error, not an answer. On the first
    # run S8 returned 0 for one recipient and 200 for another in the
    # same pass, which is the signature of a transient. Losing the
    # positive control to a transient is worse than one retry: it
    # converts a measurable route into CANNOT_SEE for a reason that has
    # nothing to do with the subject. Retried once, and the retry is
    # recorded so it is never mistaken for a clean first read.
    direct_retried = False
    if d_st == 0:
        direct_retried = True
        d_st, d_raw, d_h = http(direct_url, bearer,
                                method="POST" if route_id == "S8" else "GET",
                                body={} if route_id == "S8" else None)
    g_st, g_raw, g_h = http(gw_url, bearer,
                            method="POST" if route_id == "S8" else "GET",
                            body={} if route_id == "S8" else None)
    rec = {
        "route_id": route_id,
        "direct_status": d_st,
        "gateway_status": g_st,
        "direct_retried": direct_retried,
        "headers": header_observation(d_h, g_h),
    }
    if direct_retried:
        rec["direct_retried_note"] = (
            "The first direct attempt returned status 0 (local transport "
            "error, not an answer) and was retried once. A retried control "
            "is weaker than a clean one -- it says the path CAN answer, not "
            "that it answers reliably -- so the retry is recorded rather "
            "than hidden."
        )
    if d_st != 200:
        rec["verdict"] = "CANNOT_SEE_NO_DIRECT_CONTROL"
        rec["why"] = (
            "The direct read on this same path did not succeed, so a "
            "gateway failure here is not attributable to the gateway. "
            "This is the B-40 rule: without a same-path control, a "
            "refusal and an absence are the same observation."
        )
        rec["direct_detail"] = scrub(d_raw)[:300]
        rec["gateway_detail"] = scrub(g_raw)[:300]
        return rec
    if g_st != 200:
        who = classify_responder(g_raw, g_h)
        rec["responder"] = who
        rec["gateway_detail"] = scrub(g_raw)[:600]
        if who["responder"] == "EDGE_NO_ROUTE_MATCHED":
            rec["verdict"] = "NO_EDGE_ROUTE_FOR_THIS_PATH"
            rec["why"] = (
                "No API on the gateway claims this path, so nothing was "
                "forwarded. This is a MISSING ROUTE, not a refused one, "
                "and it is not evidence about any policy."
            )
        elif who["responder"] == "UPSTREAM_VIA_THE_EDGE":
            rec["verdict"] = "EDGE_FORWARDED_UPSTREAM_REFUSED"
            rec["why"] = (
                "The edge matched and forwarded; the refusal is the "
                "upstream's own, in its own error vocabulary. So the "
                "fault is the TARGET, not the policy. Recording this as "
                "a gateway refusal would send the next person to fix the "
                "wrong half -- B-44."
            )
        else:
            rec["verdict"] = "GATEWAY_REFUSED_DIRECT_SUCCEEDED"
            rec["why"] = (
                "Attributable to the edge: the same credential on the "
                "same protocol path succeeds directly and fails through "
                "the gateway, seconds apart, and the refusal is in the "
                "edge's own voice rather than the upstream's."
            )
        return rec
    if route_id == "S8":
        d_sum, g_sum = summarise_query(d_raw), summarise_query(g_raw)
        same = (d_sum["schema_fields"] == g_sum["schema_fields"]
                and d_sum["num_records"] == g_sum["num_records"]
                and d_sum["files"] == g_sum["files"])
        rec["direct_summary"] = d_sum
        rec["gateway_summary"] = g_sum
        rec["comparison_form"] = "SCHEMA_AND_ROW_COUNT_NOT_BYTES"
        rec["comparison_form_because"] = (
            "The signed URLs in this body change per request by design. "
            "A byte comparison would always differ and would blame the "
            "gateway for the platform's own freshness."
        )
        rec["verdict"] = "GATEWAY_QUERY_EQUIVALENT" if same else "GATEWAY_QUERY_DIFFERS"
        return rec
    rec["comparison_form"] = "BYTE_FOR_BYTE"
    rec["direct_bytes"] = len(d_raw)
    rec["gateway_bytes"] = len(g_raw)
    if d_raw == g_raw:
        rec["verdict"] = "GATEWAY_BODY_IDENTICAL"
    else:
        rec["verdict"] = "GATEWAY_BODY_DIFFERS"
        rec["why"] = (
            "§3.4.1's promise is that a reference client needs only the "
            "endpoint changed. A 200 with a different body satisfies a "
            "status-code test and breaks every client, so the difference "
            "is the finding, not the status."
        )
        rec["direct_head"] = scrub(d_raw)[:300]
        rec["gateway_head"] = scrub(g_raw)[:300]
    return rec


# ---------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Aggregation. Rewritten 2026-10-21 (§11.7 B-43).
#
# The first version tested for CANNOT_SEE_NO_DIRECT_CONTROL FIRST, and
# reported CANNOT_SEE if any single route had no control. On the first
# run six routes produced attributable gateway findings and two did not
# (S6 returned 400 direct, S8 hit a local transport error), so the two
# unobservable routes erased the six observable ones and the recipient
# verdict came back CANNOT_SEE.
#
# That is the worst possible direction for this repository's own rule to
# fail in. §12.9's silent negative is a check that cannot see reporting
# the same thing as a check that looked -- and here the aggregator
# MANUFACTURED one out of a run that had looked and found something. A
# reader of that line would have moved on.
#
# The precedence is therefore inverted and stated: an attributable
# finding, good or bad, outranks an unobservable route. CANNOT_SEE is
# the verdict of LAST RESORT -- it is correct only when there is nothing
# attributable anywhere in the set. The count of unobservable routes is
# carried alongside the verdict instead of overriding it.
# ---------------------------------------------------------------------
UNOBSERVABLE = {"CANNOT_SEE_NO_DIRECT_CONTROL"}
FAITHFUL = {"GATEWAY_BODY_IDENTICAL", "GATEWAY_QUERY_EQUIVALENT"}


def aggregate(verdicts):
    attributable = [v for v in verdicts if v not in UNOBSERVABLE]
    if not attributable:
        return "CANNOT_SEE"
    # Worst-first, because a perimeter is graded by what it lets through.
    if any(v in ("GATEWAY_BODY_DIFFERS", "GATEWAY_QUERY_DIFFERS")
           for v in attributable):
        return "GATEWAY_FORWARDS_BUT_ALTERS_THE_RESPONSE"
    if any(v == "GATEWAY_REFUSED_DIRECT_SUCCEEDED" for v in attributable):
        return "GATEWAY_REFUSES_READS_THAT_SUCCEED_DIRECTLY"
    if any(v == "EDGE_FORWARDED_UPSTREAM_REFUSED" for v in attributable):
        return "EDGE_FORWARDS_TO_THE_WRONG_UPSTREAM"
    if any(v == "NO_EDGE_ROUTE_FOR_THIS_PATH" for v in attributable):
        return "NO_EDGE_ROUTE"
    if all(v in FAITHFUL for v in attributable):
        return "GATEWAY_READ_FAITHFUL"
    return "PARTIAL"


def measure_recipient(member, base):
    cred_path = SECRETS / f"credential-{member['recipient']}.json"
    out = {
        "recipient": member["recipient"],
        "slug": member["slug"],
        "edge_path": member["edge_path"],
        "upstream_host_sha": member["upstream_host"].split(".")[0][:8] + "...",
        "credential_expires": member["credential_expires"],
        "ip_access_list_mode": member.get("ip_access_list_mode"),
    }
    if not cred_path.exists():
        out["verdict"] = "CANNOT_SEE_NO_CREDENTIAL"
        return out
    cred = json.loads(cred_path.read_text())
    bearer = cred.get("bearerToken")
    endpoint = cred.get("endpoint", "")
    exp = cred.get("expirationTime")
    if exp and exp.replace("Z", "") < now().replace("Z", ""):
        out["verdict"] = "CANNOT_SEE_CREDENTIAL_EXPIRED"
        out["why"] = (
            f"This credential expired at {exp}. Every refusal from here "
            "on would be a credential refusal wearing a gateway "
            "refusal's clothes. Rotate with scripts/27 --rotate-token "
            "and re-activate with scripts/28 before reading this as a "
            "gateway result."
        )
        return out

    disc = discover_paths(endpoint, bearer)
    out["discovery"] = {k: v for k, v in disc.items() if k != "paths"}
    if disc["verdict"] != "PATHS_DISCOVERED":
        # Name the cause when the configuration already declares it.
        # "Discovery failed" is true of a dead credential, a revoked
        # grant and an allow-list that excludes this client, and those
        # want three different responses from a reader. For the IP-list
        # recipient the cause is not a mystery: it is what
        # recipients.yaml asked for, and T-02 already proved it.
        if member.get("ip_access_list_mode") == "APPLIED" and \
                disc.get("shares_status") in (403, 0):
            out["verdict"] = "CANNOT_SEE_RECIPIENT_IP_LIST_EXCLUDES_THIS_CLIENT"
            out["why"] = (
                "This recipient carries an APPLIED Databricks IP access "
                "list that deliberately excludes this operator's "
                "address (recipients.yaml: a TEST-NET-3 address chosen "
                "so the list can never accidentally contain it). The "
                "DIRECT read is therefore refused before the gateway is "
                "reached, so T-01 has no positive control for this "
                "recipient and cannot be measured here AT ALL. That is "
                "by design, not a gap: the same property is what makes "
                "T-02's refusal attributable. T-01 for this recipient "
                "needs a client inside the allowed range, or a "
                "temporary widen with a verified restore (scripts/28 "
                "--widen-ip-list, per B-38)."
            )
            out["not_a_gateway_result"] = True
            # ... but say so only after checking whether it is STILL true.
            #
            # Added 2026-10-21. Until B-47 was fixed, the gateway's own
            # allow-list for this recipient contained LOCAL_TEST_CIDR and
            # so admitted this client; the Databricks list was genuinely
            # the only refuser and naming it was complete. With the
            # vacuous CIDR removed, the EDGE refuses this recipient too,
            # and there are now TWO independent refusals while this
            # branch names one. That is B-20 -- naming the refusing party
            # by assumption rather than observation -- and it would bite
            # exactly when someone widens the Databricks list to unblock
            # T-01: the test would keep failing and keep citing the list
            # that no longer refuses anything.
            est, eraw, ehdr = http(f"{base}{member['edge_path']}/shares",
                                   bearer)
            ewho = classify_responder(eraw, ehdr, status=est)
            out["edge_probe"] = {
                "status": est,
                "responder": ewho,
                "why_probed": (
                    "To find out whether the Databricks list is the only "
                    "thing refusing this recipient, or merely the first."
                ),
            }
            if ewho.get("responder") == "EDGE_IP_FILTERING_POLICY":
                out["verdict"] = "CANNOT_SEE_REFUSED_BY_BOTH_ALLOW_LISTS"
                out["refused_by"] = [
                    "the Databricks-side IP access list, on the DIRECT read",
                    "the gateway's own ip-filtering policy, at the EDGE",
                ]
                out["why"] = (
                    "Both allow-lists refuse this client independently, "
                    "and they do not even compare the same address: "
                    "Databricks compares this host's public NAT address, "
                    "the gateway compares "
                    f"{ewho.get('observed_client_ip')!r}. So T-01 has no "
                    "control AND no path for this recipient, and widening "
                    "either list alone would not change that. Both are "
                    "deliberate (recipients.yaml for the first, B-47's "
                    "fix for the second) -- this is the two controls "
                    "working, not two faults. Naming only one of them "
                    "would send the next reader to widen a list that is "
                    "not the blocker they are facing."
                )
            else:
                out["edge_probe"]["conclusion"] = (
                    "The edge did NOT refuse with its ip-filtering "
                    "policy, so the Databricks-side list is the only "
                    "refuser and the verdict above is complete."
                )
        else:
            out["verdict"] = "CANNOT_SEE_" + disc["verdict"].replace("CANNOT_SEE_", "")
            out["why"] = (
                "The paths to test are discovered from what this "
                "credential can see, not hardcoded. Discovery failed, so "
                "there is no path on which a same-path control exists."
            )
        return out
    out["target"] = {"share": disc["share"], "schema": disc["schema"],
                     "table": disc["table"]}

    gw_prefix = f"{base}{member['edge_path']}"
    routes = []
    for rid in BYTE_COMPARABLE + ["S8"]:
        p = disc["paths"].get(rid)
        if not p:
            continue
        routes.append(compare_one(rid, endpoint.rstrip("/") + p, gw_prefix + p, bearer))
    out["routes"] = routes

    verdicts = [r["verdict"] for r in routes]
    out["verdict"] = aggregate(verdicts)
    out["verdict_precedence"] = (
        "ATTRIBUTABLE_OUTRANKS_UNOBSERVABLE -- see aggregate() and B-43"
    )
    out["routes_measured"] = len(routes)
    out["routes_faithful"] = sum(1 for v in verdicts if v in FAITHFUL)
    out["routes_unobservable"] = sum(1 for v in verdicts if v in UNOBSERVABLE)
    out["routes_unobservable_note"] = (
        "Carried BESIDE the verdict, never overriding it. An "
        "unobservable route means one fewer measurement, not an "
        "unobservable run -- B-43."
    )
    return out


# ---------------------------------------------------------------------
# Phase 2 -- the B-42 / D-9 binding measurement
# ---------------------------------------------------------------------
MISMATCH_HINT = re.compile(
    r"does not match with the recipient|hostname .* does not match",
    re.IGNORECASE)


def binding_probe(family, base):
    """Send recipient A's credential to recipient B's route, with A's own
    route as the control in the same run.

    This is the only assertion in the repository where the EXPECTED
    result is a 400. If it came back 200, §2.3.2's single-route model
    would be buildable after all and D-9 would be wrong -- which is why
    the probe exists rather than the inference."""
    members = [m for m in family["family"]]
    if len(members) < 2:
        return {"verdict": "CANNOT_SEE_NEED_TWO_RECIPIENTS",
                "why": "A cross-route probe needs two routes to cross."}
    a, b = members[0], members[1]
    cred_a = SECRETS / f"credential-{a['recipient']}.json"
    if not cred_a.exists():
        return {"verdict": "CANNOT_SEE_NO_CREDENTIAL_FOR_A"}
    doc = json.loads(cred_a.read_text())
    bearer_a = doc.get("bearerToken")

    own_url = f"{base}{a['edge_path']}/shares"
    cross_url = f"{base}{b['edge_path']}/shares"
    c_st, c_raw, c_h = http(own_url, bearer_a)
    x_st, x_raw, x_h = http(cross_url, bearer_a)

    # B-44 applies here too, and phase 2 is where it bites hardest. On the
    # first run BOTH calls came back 404 and the probe reported
    # CANNOT_SEE_NO_CONTROL, which reads as "the probe could not be set
    # up". It was worse than that: a DIFFERENT API, matching
    # /opensharing-demo/ as a prefix, answered both calls by forwarding
    # them upstream -- so the probe measured a route it was not aiming at
    # and said nothing about the binding either way. A probe whose whole
    # value is attribution must name who answered it.
    control_who = classify_responder(c_raw, c_h)
    crossed_who = classify_responder(x_raw, x_h)

    out = {
        "credential_of": a["recipient"],
        "control_route": a["edge_path"],
        "control_status": c_st,
        "control_responder": control_who,
        "crossed_route": b["edge_path"],
        "crossed_status": x_st,
        "crossed_responder": crossed_who,
        "crossed_names_the_mismatch": bool(MISMATCH_HINT.search(x_raw or "")),
        "crossed_detail": scrub(x_raw)[:400],
        "one_variable": "which recipient's route the request was sent to",
    }
    if c_st != 200:
        if control_who["responder"] == "EDGE_NO_ROUTE_MATCHED":
            out["verdict"] = "CANNOT_SEE_ROUTE_NOT_DEPLOYED"
            out["why"] = (
                "The gateway has no route at the control path, so this "
                "probe never reached the binding. Import the route "
                "family and re-run; this is a deployment state, not a "
                "finding about the platform."
            )
        elif control_who["responder"] == "UPSTREAM_VIA_THE_EDGE":
            out["verdict"] = "CANNOT_SEE_EDGE_FORWARDED_TO_THE_WRONG_UPSTREAM"
            out["why"] = (
                "Some route matched and forwarded, and the UPSTREAM "
                "refused the control in its own error vocabulary. So a "
                "route answered -- but not necessarily the intended one, "
                "and not at the intended target. Recording this as "
                "'no control' would hide that the edge is mis-aimed "
                "(B-44)."
            )
            out["control_detail"] = scrub(c_raw)[:400]
        else:
            out["verdict"] = "CANNOT_SEE_NO_CONTROL"
            out["why"] = (
                "The credential's own route did not answer, so a refusal "
                "on the crossed route is not attributable to the crossing."
            )
            out["control_detail"] = scrub(c_raw)[:400]
        return out
    if x_st == 200:
        out["verdict"] = "BINDING_NOT_ENFORCED_D9_PREMISE_FALSIFIED"
        out["why"] = (
            "A credential read successfully through another recipient's "
            "route. If this is reproducible, the host/token binding is "
            "not enforced, §2.3.2's single-route model IS buildable, and "
            "D-9 must be withdrawn -- which would be the best possible "
            "outcome for AC4's self-service portal. It would also mean "
            "one recipient's route can serve another's data, which needs "
            "its own look."
        )
        return out
    if crossed_who["responder"] == "EDGE_NO_ROUTE_MATCHED":
        out["verdict"] = "CANNOT_SEE_CROSSED_ROUTE_NOT_DEPLOYED"
        out["why"] = (
            "The crossed route was refused by the GATEWAY, which has no "
            "API at that path -- the request never reached the platform, "
            "so it says nothing about the host/token binding. This is "
            "exactly the reading B-44 exists to prevent: a refusal that "
            "looks like the expected one and is produced by a different "
            "party for a different reason, which would have been scored "
            "as the probe SUCCEEDING."
        )
        return out
    if out["crossed_names_the_mismatch"]:
        out["verdict"] = "BINDING_ENFORCED_AND_THE_ERROR_NAMES_BOTH_HALVES"
        out["why"] = (
            "Refused on the crossed route, 200 on its own route, same "
            "credential, same run, one variable. And the error names "
            "both the hostname received and the recipient the token "
            "belongs to -- the opposite of B-20's problem, and the model "
            "E5's error contract should copy."
        )
        return out
    out["verdict"] = "BINDING_ENFORCED_BUT_THE_ERROR_IS_OPAQUE"
    out["why"] = (
        "The crossing was refused with the control succeeding, so the "
        "binding holds. But the refusal does not name the mismatch, so a "
        "caller cannot tell this apart from a credential problem -- "
        "B-20's failure mode, and worth recording as the contrast case."
    )
    return out


# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipient", help="slug or full recipient name")
    ap.add_argument("--skip-binding-probe", action="store_true")
    args = ap.parse_args()
    load_env()

    print("=" * 68)
    print("T-01: a recipient reads through the gateway")
    print("E1 Task 1.6 | AC1, AC2 | CONOPS 2.1, 2.3.2, 3.4.1")
    print("=" * 68)

    if not FAMILY.exists():
        print(f"\nMissing {FAMILY.relative_to(ROOT)}")
        print("Run: python3 scripts/29_gen_gravitee_route_family.py")
        print("\nT-01 VERDICT: CANNOT_SEE_NO_ROUTE_FAMILY")
        sys.exit(1)
    family = json.loads(FAMILY.read_text())

    base, base_source, base_note = edge_base()
    print(f"\nedge base:   {base}  ({base_source})")
    if base_note:
        print(f"  note:      {base_note}")
    print(f"route family: {len(family['family'])} recipients, shape {family['shape']}")

    members = family["family"]
    if args.recipient:
        members = [m for m in members
                   if args.recipient in (m["slug"], m["recipient"])]
        if not members:
            sys.exit(f"No family member matching {args.recipient!r}")

    rep = Report()
    results = []
    for m in members:
        print(f"\n--- {m['recipient']}")
        print(f"    edge {m['edge_path']}")
        r = measure_recipient(m, base)
        results.append(r)
        if r.get("routes"):
            for rt in r["routes"]:
                print(f"      {rt['route_id']:<4} direct {rt['direct_status']:<4} "
                      f"gateway {rt['gateway_status']:<4} {rt['verdict']}")
            leaked = sorted({h for rt in r["routes"]
                             for h in rt["headers"]["leaked_through_gateway"]})
            if leaked:
                print(f"      headers leaked through the edge (T-07 input): {', '.join(leaked)}")
        print(f"    verdict: {r['verdict']}")
        if r.get("why"):
            print(f"      why:   {r['why'][:200]}")
        rep.record(
            f"T-01[{m['slug']}]",
            "the recipient reads its own share through the gateway",
            "every discovered protocol path returns 200 through the edge "
            "with a body identical to the same path read directly, in the "
            "same run, with the same credential -- the direct read being "
            "the same-path positive control B-40 requires",
            r["verdict"],
            r["verdict"] in ("GATEWAY_READ_FAITHFUL",),
            "evidence/t01-gateway-read.json")

    binding = None
    if not args.skip_binding_probe:
        print("\n--- phase 2: host/recipient binding (B-42 / D-9)")
        binding = binding_probe(family, base)
        print(f"    control {binding.get('control_route')} -> {binding.get('control_status')}")
        print(f"    crossed {binding.get('crossed_route')} -> {binding.get('crossed_status')}")
        print(f"    verdict: {binding['verdict']}")
        rep.record(
            "T-01b",
            "the sharing host is bound to the recipient, so one route cannot front all",
            "a credential refused on another recipient's route while "
            "succeeding on its own, same run, one variable",
            binding["verdict"],
            binding["verdict"].startswith("BINDING_ENFORCED"),
            "evidence/t01-gateway-read.json")

    # Same precedence rule as aggregate(), for the same reason (B-43):
    # an attributable finding from ONE recipient outranks an unobservable
    # result from another. The earlier version of this roll-up had no
    # branch for the two verdicts B-44 introduced, so a run where every
    # recipient's edge forwarded to the wrong upstream -- a single,
    # nameable, fixable cause -- would have rolled up to "PARTIAL", a
    # word that sends nobody anywhere.
    verdicts = [r["verdict"] for r in results]
    attributable = [v for v in verdicts if not v.startswith("CANNOT_SEE")]
    if not attributable:
        top = "CANNOT_SEE"
    elif all(v == "GATEWAY_READ_FAITHFUL" for v in attributable):
        top = ("GATEWAY_READ_FAITHFUL_FOR_EVERY_RECIPIENT"
               if len(attributable) == len(verdicts)
               else "GATEWAY_READ_FAITHFUL_WHERE_OBSERVABLE")
    elif any(v == "GATEWAY_FORWARDS_BUT_ALTERS_THE_RESPONSE" for v in attributable):
        top = "GATEWAY_ALTERS_THE_RESPONSE"
    elif any(v == "GATEWAY_REFUSES_READS_THAT_SUCCEED_DIRECTLY" for v in attributable):
        top = "GATEWAY_REFUSES_READS_THAT_SUCCEED_DIRECTLY"
    elif any(v == "EDGE_FORWARDS_TO_THE_WRONG_UPSTREAM" for v in attributable):
        top = "EDGE_FORWARDS_TO_THE_WRONG_UPSTREAM"
    elif any(v == "NO_EDGE_ROUTE" for v in attributable):
        top = "NO_EDGE_ROUTE_DEPLOYED"
    else:
        top = "PARTIAL"

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "test_id": "T-01",
        "epic_task": "E1 Task 1.6",
        "acceptance_criteria": ["AC1", "AC2"],
        "conops": ["2.1", "2.3.2", "3.4.1"],
        "run_at": now(),
        "verdict": top,
        "edge_base": base,
        "edge_base_source": base_source,
        "edge_base_note": base_note,
        "route_family_shape": family["shape"],
        "route_family_inputs": family["inputs"],
        "per_recipient": results,
        "binding_probe": binding,
        "defect_history": [
            {
                "id": "B-43",
                "found": "2026-10-21",
                "found_by": "reading this test's own first-run output",
                "defect": "verdict precedence inverted in the per-recipient "
                          "roll-up: CANNOT_SEE_NO_DIRECT_CONTROL was tested "
                          "FIRST, so two routes without a control erased six "
                          "routes that had one and had produced an "
                          "attributable finding",
                "first_run_said": "CANNOT_SEE",
                "first_run_should_have_said":
                    "an attributable verdict naming the six routes where the "
                    "gateway refused a read that succeeded directly",
                "fix": "aggregate(): CANNOT_SEE is now the verdict of LAST "
                       "RESORT. It is returned only when NO route produced "
                       "an attributable result, and the count of "
                       "unobservable routes is carried beside the verdict "
                       "so the gap is visible rather than decisive.",
                "general_rule": "An aggregator that can manufacture a "
                                "silent negative out of a run that looked "
                                "and found something is worse than no "
                                "aggregator. Unobservable must never "
                                "outrank observed (docs/12 §12.9).",
                "status": "FIXED -- carried forward, not erased (B-19)",
            },
            {
                "id": "B-44",
                "found": "2026-10-21",
                "found_by": "curling the gateway by hand after the first run "
                            "reported 404 everywhere",
                "defect": "an EDGE refusal and an UPSTREAM refusal forwarded "
                          "THROUGH the edge are the same status code with "
                          "opposite remedies (fix the policy vs fix the "
                          "target), and this test could not tell them apart",
                "first_run_said": "404 on every gateway path, read as the "
                                  "gateway refusing",
                "first_run_should_have_said":
                    "a DIFFERENT API, prefix-matching /opensharing-demo/, "
                    "forwarded the request upstream with the recipient slug "
                    "glued into the protocol path; Databricks produced the "
                    "404. The edge was not refusing -- it was forwarding to "
                    "the wrong place.",
                "discriminators_now_used": [
                    "Gravitee's own unmatched-path refusal is text/plain, "
                    "body 'No context-path matches the request URI.', with "
                    "NO x-gravitee-* headers",
                    "Databricks answers JSON carrying error_code and "
                    "details[].@type: type.googleapis.com/google.rpc.*",
                    "a response that round-tripped the edge carries "
                    "x-gravitee-* headers",
                ],
                "fix": "classify_responder(), applied in compare_one AND in "
                       "binding_probe. Phase 2 is where this bit hardest: "
                       "its expected result IS a refusal, so an edge "
                       "refusal arriving for an unrelated reason would have "
                       "been scored as the probe succeeding.",
                "general_rule": "B-20, ours before theirs: a verdict "
                                "vocabulary too coarse to name the "
                                "refusing party fails toward blaming the "
                                "nearest thing.",
                "status": "FIXED -- carried forward, not erased (B-19)",
            },
        ],
        "shape_note": (
            "Reported PER RECIPIENT because the upstream is per-recipient. "
            "A single-endpoint T-01 would pass for whichever recipient "
            "matched the pinned host and report failure for the others "
            "while the gateway was working correctly. docs/11 B-42, "
            "docs/10 D-9."
        ),
        "what_this_does_not_prove": [
            "T-07. The header observations are T-07's INPUT. A header "
            "absent from the gateway response may have been stripped or "
            "never sent, and only the direct capture beside it tells "
            "those apart.",
            "T-05. No rate limit was exercised. A handful of sequential "
            "reads is below every configured limit, so nothing here says "
            "the limiters work.",
            "T-03. No refusal from outside the allow-list was attempted, "
            "and two of the three recipients carry the gateway allow-list "
            "DISABLED by design (recipients.yaml), so this run could not "
            "have produced one.",
            "That traffic cannot bypass the edge. §11.7 B-35: an IP "
            "allow-list cannot distinguish 'via the gateway' from "
            "'direct' when both leave one host through one NAT address. "
            "This test reads BOTH ways on purpose and proves the two "
            "paths agree -- it does not and cannot prove the direct path "
            "is closed to a real consumer.",
        ],
    }, indent=2) + "\n")

    rep.write(REPORT)
    ok = rep.summary()
    print("\n" + "=" * 68)
    print(f"T-01 VERDICT: {top}")
    print("=" * 68)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
