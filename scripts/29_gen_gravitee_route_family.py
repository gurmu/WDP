#!/usr/bin/env python3
"""
E2 Task 2.1, borrowed into E1 Task 1.6: generate the channel E-1 gateway
configuration from code.

WHY THIS IS A GENERATOR AND NOT A MERGE
---------------------------------------
Task 1.6 assumed the two live Gravitee definitions could be merged by
hand. API 1 (/opensharing-demo/) has the right KIND of upstream target
and no policies; API 2 (/delta-sharing/) has all the perimeter policies
and a target that is not a sharing endpoint at all. Take the policies
from one and the target from the other and you have a working route.

You do not, and the reason is §11.7 B-42 / docs/10 D-9. The sharing
endpoint hostname is PER RECIPIENT, and the platform validates the
binding between host and bearer token:

    400 BAD_REQUEST: Request URL hostname '634cbc18-...' does not match
    with the recipient id 'aa8b5b00-...'

So there is no single host to merge onto. Whichever host a single route
is pinned to, every other recipient's token is refused there, and the
refusal is correct. §2.3.2's picture of E-1 as one route with one
upstream target cannot be built.

This script therefore emits a ROUTE FAMILY: one V4 API definition per
recipient, each pinned to that recipient's own endpoint, all generated
from the same four inputs so that the family is reproducible from code
(AC6) and redeployable to a clean target (T-12).

A SECOND DEFECT IN THE OLD TARGET, WORTH RECORDING
--------------------------------------------------
gravitee/api-definition.json targets
`https://<DATABRICKS_HOST>/api/2.0/delta-sharing`. That is wrong TWICE:
wrong host (the workspace host is not the sharing host -- route-table.yaml
`targets.sharing_endpoint` already says so) and wrong PATH. The real
issued endpoints are

    https://<recipient-uuid>.opensharing.<region>.cloud.databricks.com
        /api/2.0/opensharing/metastores/<metastore-id>

There is no `/api/2.0/delta-sharing` path anywhere in an issued
credential. This is why T-01 has never produced a successful read through
the gateway, and it is a cleaner explanation than "the gateway is
misconfigured" -- the route was pointed at a path that does not exist.
Carried forward per B-19 rather than quietly corrected: the old file is
left in place and labelled by this script's output, not deleted.

WHAT IT READS
-------------
  iac/config/route-table.yaml     the 16 routes, their methods, paths,
                                  policy classes, targets and listeners
  iac/config/policy-classes.yaml  what a class contains
  iac/config/recipients.yaml      the declared recipients and their
                                  IP access list decisions
  _secrets/credential-<name>.json the per-recipient endpoint (HOST ONLY
                                  is read; the bearer token is never
                                  touched, and the script asserts that
                                  no token value reaches its output)

WHAT IT WRITES
--------------
  gravitee/generated/api-e1-<slug>.json   one per recipient, importable
                                          by scripts/05 --definition
  gravitee/generated/api-f1-storage-proxy.json  the F1 listener (B-3/D-4)
  gravitee/generated/route-family.json    the manifest: slug -> recipient
                                          -> host, provenance, input
                                          hashes, and what is NOT built

  evidence/gravitee-route-family.json     the evidence record

Nothing is deployed. Generation and deployment are separate on purpose:
a generator that also deploys cannot be diffed before it acts.

    python3 scripts/29_gen_gravitee_route_family.py
    python3 scripts/29_gen_gravitee_route_family.py --check   # diff only
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "iac" / "config"
SECRETS = ROOT / "_secrets"
OUT = ROOT / "gravitee" / "generated"
EVIDENCE = ROOT / "evidence" / "gravitee-route-family.json"

ROUTE_TABLE = CONFIG / "route-table.yaml"
POLICY_CLASSES = CONFIG / "policy-classes.yaml"
RECIPIENTS = CONFIG / "recipients.yaml"
LEGACY_DEF = ROOT / "gravitee" / "api-definition.json"

API_VERSION = "1.5.0-generated"

# This laptop's docker bridge. The gateway sees all host-originated test
# traffic as coming from 172.21.0.1 in this single-machine topology, so
# without this the generated allow-list refuses the operator's own tests
# and every result is a network refusal wearing a policy refusal's
# clothes. It is NOT a stand-in for a real agency range (input 1694-G1)
# and it must be removed before anything resembling a production review.
LOCAL_TEST_CIDR = "172.21.0.0/16"


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha12(path):
    if not path.exists():
        return "ABSENT"
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    # Drop the shared prefix so the edge path stays readable, but only if
    # something survives. `awoz1227-psp7-t2-us-recipient` -> `psp7-t2-us`.
    s = re.sub(r"^awoz1227-", "", s)
    s = re.sub(r"-recipient$", "", s)
    return s or "recipient"


def load_yaml(path):
    if not path.exists():
        sys.exit(f"Missing required input: {path}")
    return yaml.safe_load(path.read_text())


# ---------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------

def load_recipient_endpoints():
    """Read each declared recipient's own endpoint from its credential
    file. Returns (resolved, unresolved).

    The bearer token is read into memory because it is in the same JSON
    document, and then never used. assert_no_token_in_output() below is
    what makes that a checked property rather than a promise."""
    doc = load_yaml(RECIPIENTS)
    resolved, unresolved = [], []
    for rec in doc.get("recipients", []):
        name = rec["name"]
        cred = SECRETS / f"credential-{name}.json"
        if not cred.exists():
            unresolved.append({
                "recipient": name,
                "reason": "NO_CREDENTIAL_FILE",
                "looked_for": str(cred.relative_to(ROOT)),
                "consequence": (
                    "No endpoint can be resolved, so no route can be "
                    "generated for this recipient. This is not a "
                    "generator failure -- it is the recipient having no "
                    "issued credential. Run scripts/28 --activate first."
                ),
            })
            continue
        body = json.loads(cred.read_text())
        endpoint = body.get("endpoint", "")
        m = re.match(r"^(https?)://([^/]+)(/.*)?$", endpoint)
        if not m:
            unresolved.append({
                "recipient": name,
                "reason": "ENDPOINT_UNPARSABLE",
                "endpoint_length": len(endpoint),
                "consequence": (
                    "The credential exists but its endpoint is not an "
                    "absolute http(s) URL, so the upstream target cannot "
                    "be formed. Reported rather than guessed."
                ),
            })
            continue
        scheme, host, path = m.group(1), m.group(2), (m.group(3) or "")
        resolved.append({
            "recipient": name,
            "slug": slugify(name),
            "scheme": scheme,
            "host": host,
            "base_path": path.rstrip("/"),
            "target": f"{scheme}://{host}{path.rstrip('/')}",
            "expiration_time": body.get("expirationTime"),
            "iceberg_endpoint_present": bool(body.get("icebergEndpoint")),
            "channel": rec.get("channel"),
            "dsa_ref": rec.get("dsa_ref"),
            "dsa_ref_status": rec.get("dsa_ref_status"),
            "grants": [g.get("share") for g in rec.get("grants", [])],
            "ip_access_list": rec.get("ip_access_list") or {},
            "credential_file": str(cred.relative_to(ROOT)),
        })
    return resolved, unresolved


# ---------------------------------------------------------------------
# Flow construction
# ---------------------------------------------------------------------

def path_to_selector(protocol_path):
    """Delta Sharing paths carry {share}/{schema}/{table} segments.
    Gravitee V4 HTTP selectors accept the same :param or glob forms; this
    build uses STARTS_WITH on the fixed prefix plus an EQUALS where the
    path has no parameters, because a parameterised EQUALS that does not
    match falls through to the catch-all and the resulting refusal looks
    like an edge control working. See route-table.yaml selector_rule."""
    if "{" not in protocol_path:
        return {"type": "HTTP", "path": protocol_path, "pathOperator": "EQUALS"}
    # Gravitee's path params are :name
    converted = re.sub(r"\{(\w+)\}", r":\1", protocol_path)
    return {"type": "HTTP", "path": converted, "pathOperator": "EQUALS"}


def strip_meta(policy_row):
    """A policy row in policy-classes.yaml carries documentation keys
    (conops, note, *_because, status, limit_note ...). Gravitee rejects
    unknown keys in some versions and ignores them in others, and
    "sometimes ignored" is not a property to deploy on. Keep only the
    four keys the API accepts, and carry the documentation into a
    sibling `_rationale` that the import script strips."""
    keep = {}
    for k in ("name", "description", "policy", "enabled", "configuration"):
        if k in policy_row:
            keep[k] = policy_row[k]
    keep.setdefault("enabled", True)
    rationale = {k: v for k, v in policy_row.items() if k not in keep}
    if rationale:
        keep["_rationale"] = rationale
    return keep


def class_policies(pc, class_key, side):
    cls = pc["classes"].get(class_key) or {}
    rows = cls.get(side) or []
    out = []
    for row in rows:
        if row.get("policy") in (None, "DEFERRED"):
            # Recorded as NOT_BUILT in the manifest, not emitted as a
            # policy. An emitted policy with a null id imports as an API
            # that starts and enforces nothing.
            continue
        if "configuration" not in row and row.get("configuration_fallback"):
            row = dict(row)
            row["configuration"] = row.pop("configuration_fallback")
        out.append(strip_meta(row))
    return out


def common_policies(pc, side):
    return [strip_meta(r) for r in (pc["common"].get(side) or [])]


def ip_filter_policy(rec, local_test_cidr=False):
    """Carry the IP allow-list for every recipient, ENABLED only where the
    recipient's own configuration says APPLIED.

    MEASURED 2026-10-21 (B-47), and the reason local_test_cidr is now an
    explicit opt-in that defaults to OFF. T-03 captured the ip-filtering
    policy's own refusal, which reports the address it compared:
    `Your IP (172.21.0.1) ... not allowed to reach this resource`. That
    address is INSIDE LOCAL_TEST_CIDR. So adding the CIDR did not merely
    admit the test client -- it admitted the entire Docker bridge, which
    is every client that can reach this gateway from the host. The
    allow-list was vacuous in precisely the APPLIED configuration that is
    supposed to enforce it, and this file is the deployable source of
    truth for AC6 / T-12 "redeploy from code".

    The old default was the familiar shape of a test accommodation that
    silently disables the control under test. Now the honest-by-default
    artifact is generated unless someone asks for the accommodation by
    name, and asking for it stamps the output so the artifact says so.

    The important half is the other branch. Two recipients declare
    `mode: NOT_APPLIED_BY_DESIGN` with a reason that applies with equal
    force at the gateway: a network refusal and an entitlement refusal
    are the same observation from the client's side, so an allow-list in
    front of the recipient T-04 reads through would make T-04 pass for
    the wrong reason. The policy is emitted DISABLED and carrying that
    reason rather than omitted, because an absent control and a decided-
    against control look identical in a deployed gateway and only one of
    them is a decision."""
    ial = rec.get("ip_access_list") or {}
    mode = ial.get("mode")
    if mode == "APPLIED":
        declared = list(ial.get("allowed_ip_addresses") or [])
        effective = declared + ([LOCAL_TEST_CIDR] if local_test_cidr else [])
        return {
            "name": "CIDR allow-list (agency IP ranges)",
            "description": "CONOPS 3.1 - IP allow-listing. Step 2 of the egress flow. T-03."
                           + (" LOCAL_TEST_CIDR ADDED -- CONTROL IS VACUOUS ON THIS HOST."
                              if local_test_cidr else ""),
            "policy": "ip-filtering",
            "enabled": True,
            "configuration": {"whitelistIps": effective},
            "_rationale": {
                "local_test_cidr_included": local_test_cidr,
                "control_is_vacuous": local_test_cidr,
                "control_is_vacuous_because": (
                    "T-03 measured the address this policy compares "
                    "against: 172.21.0.1, the Docker bridge, which is "
                    "inside LOCAL_TEST_CIDR. Including the CIDR admits "
                    "every client that can reach the gateway from this "
                    "host, so the allow-list refuses nobody. B-47."
                ) if local_test_cidr else (
                    "LOCAL_TEST_CIDR is NOT included, so this allow-list "
                    "contains only the declared ranges and will refuse "
                    "this operator's own test client. That is the correct "
                    "and deployable shape; local reads through this "
                    "recipient's route are EXPECTED to be refused."
                ),
                "declared_in": "iac/config/recipients.yaml ip_access_list.allowed_ip_addresses",
                "declared": declared,
                "local_test_cidr_candidate": LOCAL_TEST_CIDR,
                "local_test_cidr_because_superseded": (
                    "The gateway sees host-originated test traffic as "
                    "172.21.0.1 on this single-machine topology. Without "
                    "it every local result is a network refusal wearing a "
                    "policy refusal's clothes. NOT a stand-in for a real "
                    "agency range (1694-G1) and must be removed before a "
                    "production config review."
                ),
                "local_test_cidr_because_superseded_note": (
                    "Carried, not deleted (B-19). The reasoning was "
                    "sound and the conclusion was wrong: the cure for "
                    "'a network refusal wearing a policy refusal's "
                    "clothes' is to ATTRIBUTE the refusal, which T-03's "
                    "classifier now does by reading the policy's own "
                    "message, not to widen the allow-list until nothing "
                    "is refused. Widening it produced a policy refusal "
                    "that could never fire -- the same confusion with "
                    "the sign flipped."
                ),
                "defense_in_depth": (
                    "This is the GATEWAY allow-list. The recipient object "
                    "in Databricks carries its own, applied separately by "
                    "scripts/27. They are two layers, and §11.7 B-35 "
                    "applies to both: neither can distinguish 'via the "
                    "gateway' from 'direct' when both leave one host "
                    "through one NAT address."
                ),
            },
        }
    return {
        "name": "CIDR allow-list (agency IP ranges)",
        "description": "CONOPS 3.1 - IP allow-listing. DISABLED for this recipient by design.",
        "policy": "ip-filtering",
        "enabled": False,
        "configuration": {"whitelistIps": (
            [LOCAL_TEST_CIDR] if local_test_cidr else [])},
        "_rationale": {
            "disabled_list_contents_note": (
                "The list of a DISABLED policy is inert, but it is still "
                "read by anyone auditing this file, and a disabled "
                "policy carrying a permissive CIDR is one toggle away "
                "from a vacuous control (B-47). It is therefore left "
                "empty unless the local-test accommodation was asked for."
            ),
            "enabled_false_because": (
                "This recipient declares ip_access_list.mode = "
                f"{mode!r} in iac/config/recipients.yaml. The reason "
                "given there applies at the gateway too: an allow-list "
                "denial and an entitlement denial are the same "
                "observation from the client's side, so a gateway "
                "allow-list in front of this recipient would let T-04 "
                "and T-21 pass without touching the mechanism they name "
                "(§12.9's silent negative with the sign flipped, the "
                "B-40 class)."
            ),
            "recipient_reason": ial.get("not_applied_because"),
            "emitted_disabled_rather_than_omitted_because": (
                "An absent control and a decided-against control look "
                "identical in a deployed gateway. Only one of them is a "
                "decision, and the definition should say which."
            ),
            "defense_in_depth_tested_on": ial.get("defense_in_depth_tested_on"),
        },
    }


def build_sharing_flows(rt, pc, rec, local_test_cidr=False):
    """One flow per exposed sharing route, selector on METHOD AND PATH.

    route-table.yaml's selector_rule is the whole reason this is per-route
    rather than one STARTS_WITH flow: S7 (GET .../metadata, class A) and
    S8 (POST .../query, class B) overlap on path, so a path-only selector
    files the query route under class A and T-05 then measures the wrong
    class while looking correct."""
    flows = []
    notes = []
    for row in rt["routes"]:
        if row.get("target") != "sharing_endpoint" or not row.get("exposed"):
            continue
        cls = row.get("policy_class")
        if not cls:
            continue
        req = common_policies(pc, "request") + [ip_filter_policy(rec, local_test_cidr)] + class_policies(pc, cls, "request")
        resp = common_policies(pc, "response") + class_policies(pc, cls, "response")
        flow = {
            "name": f"{row['id']}-class-{cls}",
            "enabled": True,
            "selectors": [
                dict(path_to_selector(row["protocol_path"]),
                     methods=list(row.get("methods") or ["GET"])),
            ],
            "request": req,
            "response": resp,
            "_provenance": {
                "route_id": row["id"],
                "channel": row.get("channel"),
                "policy_class": cls,
                "purpose": row.get("purpose"),
                "tests": row.get("tests"),
                "generated_from": "iac/config/route-table.yaml + iac/config/policy-classes.yaml",
            },
        }
        if row.get("protocol_path_unconfirmed"):
            flow["_provenance"]["path_unconfirmed"] = True
            flow["_provenance"]["path_unconfirmed_because"] = row.get(
                "protocol_path_unconfirmed_because")
            notes.append({
                "route_id": row["id"],
                "warning": "PATH_UNCONFIRMED",
                "detail": (
                    "This flow is generated onto a CANDIDATE path. If the "
                    "path is wrong the selector matches nothing, the "
                    "request falls to the catch-all, and the refusal will "
                    "look like an edge control working. Do not report a "
                    "refusal on this route as enforcement until the path "
                    "is settled."
                ),
                "settled_by": row.get("settled_by"),
            })
        if row.get("passthrough_headers"):
            flow["_provenance"]["passthrough_headers"] = row["passthrough_headers"]
            flow["_provenance"]["passthrough_note"] = row.get("passthrough_note")
        flows.append(flow)
    return flows, notes


def build_catch_all(pc):
    """route-table.yaml row X: everything else, denied, and it must be
    LAST.

    RETRACTION 2026-10-21 (B-19, B-48). This docstring used to end:
    "what actually denies today is the absence of a matching flow plus
    the absence of a usable endpoint, which is fail-closed by accident
    rather than by configuration. Recorded, not claimed."

    The claim was wrong, and wrong in the unsafe direction. An unmatched
    path is NOT denied by the absence of a matching flow. Gravitee
    prefix-matches the context path and FORWARDS any path no selector
    claims, with the context path stripped and the remainder appended to
    the endpoint target. Measured on the AI route, whose target is the
    workspace root: /ai-gateway-demo/api/2.0/token/list returned 200.
    Nothing was denied; the request went straight through.

    What is true of THESE APIs is narrower and is not a control. Their
    endpoint target carries a deep base path, so a stray path appends to
    it and the upstream 404s with "No API found for 'GET
    /opensharing/metastores/...'". That is confinement by URL
    concatenation -- a property of how two strings join, not a decision,
    not fail-closed, and one target edit away from being gone. Calling it
    "the right outcome reached by accident" credited it with being the
    right outcome. It is the right outcome only on the subset of APIs
    whose targets happen to be deep.

    The fix is built and verified on the AI route only: see
    terminal_allow_list() in scripts/30_gen_gravitee_ai_route.py, which
    emits a resource-filtering whitelist derived from the forwarding
    flows' own selectors, placed last. Bringing the same flow here is
    deliberately NOT done in the same change: T-01 and T-03 currently
    depend on these generated APIs and a whitelist that is wrong by one
    pattern turns the positive control of two passing tests into a 403.
    It needs its own change and its own run. AI-7 / B-48 carry it as
    open."""
    return {
        "name": "X-catch-all-deny",
        "enabled": False,
        "selectors": [{"type": "HTTP", "path": "/", "pathOperator": "STARTS_WITH"}],
        "request": [],
        "response": [],
        "_provenance": {
            "route_id": "X",
            "generated": False,
            "generated_false_because": (
                "SUPERSEDED IN PLACE 2026-10-21 -- see "
                "retracted_claim below. The policy shape is no longer "
                "unconfirmed: resource-filtering with a `whitelist` of "
                "Ant patterns was read from this installation's policy "
                "schema endpoint and verified live on the AI route. "
                "This flow stays disabled only because enabling it here "
                "would put an allow-list in front of the routes T-01 "
                "and T-03 use as their positive control, and a "
                "whitelist wrong by one pattern turns those passes into "
                "403s. It needs its own change and its own test run."
            ),
            "retracted_claim": (
                "B-19. This field previously read: 'Today an unmatched "
                "path fails closed because nothing matches it, which is "
                "the right OUTCOME reached by accident rather than by "
                "decision.' MEASURED FALSE 2026-10-21. Gravitee "
                "FORWARDS a path that matches no selector; it does not "
                "refuse it. On the AI route, whose target is the "
                "workspace root, /ai-gateway-demo/api/2.0/token/list "
                "returned 200. These sharing APIs are confined only "
                "because their target carries a deep base path, so a "
                "stray path appends and the upstream 404s -- "
                "confinement by string concatenation, not a control, "
                "and not fail-closed."
            ),
            "fix_location": (
                "terminal_allow_list() in "
                "scripts/30_gen_gravitee_ai_route.py. Built and verified "
                "there; not yet brought here. AI-7 / B-48."
            ),
            "policy_shape_confirmed": {
                "policy": "resource-filtering",
                "fields": ["whitelist", "blacklist",
                           "normalizeRequestPath", "decodeEncodedSlash"],
                "note": (
                    "normalizeRequestPath and decodeEncodedSlash both "
                    "default to FALSE. Left false, the policy matches the "
                    "raw path while the upstream resolves a normalized "
                    "one, so '/a/./b' and an encoded-slash variant are a "
                    "different string to the filter and the same resource "
                    "to the upstream. Set both true. PC-4 can be closed "
                    "when this flow is enabled."
                ),
            },
            "must_be_last": False,
            "must_be_last_RETRACTED": (
                "B-19. This read `must_be_last: true`, with the reason "
                "'A catch-all evaluated before a specific route swallows "
                "it. If this flow is ever enabled, its position in the "
                "flows array is load-bearing.' The hazard is real; the "
                "remedy was not. MEASURED 2026-10-21 on the AI route: a "
                "'/' STARTS_WITH flow emitted LAST in the array is "
                "evaluated FIRST anyway, because Gravitee orders flows "
                "from the most generic selector to the most specific. "
                "Array position is not evaluation order, so moving this "
                "flow cannot protect a specific route from it. What "
                "actually matters is that its policy ADMITS every path "
                "the specific flows claim -- which is why the AI route's "
                "equivalent derives its whitelist from those flows' own "
                "selectors rather than being a bare deny."
            ),
            "swallowing_is_still_the_hazard": (
                "On the AI route this cost M3's explicit deny its voice: "
                "the catch-all answers the legacy MCP path before M3's "
                "mock is reached, so the refusal carries no reason. "
                "Enabling this flow here would do the same to every "
                "specific sharing route unless its whitelist names them. "
                "AI-9."
            ),
        },
    }


def build_recipient_api(rt, pc, rec, local_test_cidr=False):
    flows, notes = build_sharing_flows(rt, pc, rec, local_test_cidr)
    flows.append(build_catch_all(pc))
    listener_path = f"{rt['edge']['sharing_listener']['path']}/{rec['slug']}"
    api = {
        "name": f"AWOZ-1227 E1 Sharing -- {rec['recipient']}",
        "apiVersion": API_VERSION,
        "definitionVersion": "V4",
        "type": "PROXY",
        "description": (
            f"Channel E-1 egress route for recipient {rec['recipient']}. "
            "GENERATED by scripts/29_gen_gravitee_route_family.py from "
            "route-table.yaml, policy-classes.yaml, recipients.yaml and "
            "this recipient's own issued credential endpoint. Do not edit "
            "by hand -- regenerate. One route per recipient because the "
            "sharing host is per-recipient and the platform validates the "
            "host/token binding (docs/11 B-42, docs/10 D-9)."
        ),
        "listeners": [{
            "type": "HTTP",
            "paths": [{"path": listener_path}],
            "entrypoints": [{"type": "http-proxy"}],
        }],
        "endpointGroups": [{
            "name": f"sharing-endpoint-{rec['slug']}",
            "type": "http-proxy",
            "endpoints": [{
                "name": "sharing-endpoint",
                "type": "http-proxy",
                "configuration": {"target": rec["target"]},
            }],
        }],
        "flows": flows,
    }
    plans = [{
        "name": f"plan-{rec['slug']}",
        "security": {"type": "KEY_LESS"},
        "definitionVersion": "V4",
        "description": (
            "KEY_LESS: authorization is the Delta Sharing bearer token, "
            "validated by Databricks, not by Gravitee plan security "
            "(§1 key architectural principle). Consequence recorded in "
            "policy-classes.yaml class A key_note: the rate limit is "
            "keyed on the Authorization header, so it is per-CREDENTIAL "
            "and not per-consumer if a credential is shared."
        ),
    }]
    doc = {
        "_generated": {
            "by": "scripts/29_gen_gravitee_route_family.py",
            "at": now(),
            "recipient": rec["recipient"],
            "edge_path": listener_path,
            "upstream_host": rec["host"],
            "upstream_base_path": rec["base_path"],
            "credential_expires": rec["expiration_time"],
            "do_not_edit": "Regenerate. Hand edits are lost and untraceable.",
            "import_with": (
                "python3 scripts/05_import_gravitee_api.py --definition "
                f"gravitee/generated/api-e1-{rec['slug']}.json"
            ),
        },
        "api": api,
        "plans": plans,
        "_not_built": notes,
    }
    return doc


def build_storage_proxy_api(rt, pc):
    """F1 on its OWN listener. This is §11.7 B-3 / docs/10 D-4's fix: as
    §2.3.2 is written F1 sits under the sharing listener, which makes the
    real edge path /delta-sharing/storage-proxy while .env declares
    http://localhost:8082/storage-proxy. .env is the source of truth."""
    sp = rt["edge"]["storage_proxy_listener"]
    f1 = next((r for r in rt["routes"] if r["id"] == "F1"), None)
    if f1 is None:
        return None
    req = common_policies(pc, "request") + class_policies(pc, "D", "request")
    resp = common_policies(pc, "response") + class_policies(pc, "D", "response")
    return {
        "_generated": {
            "by": "scripts/29_gen_gravitee_route_family.py",
            "at": now(),
            "route": "F1",
            "edge_path": sp["path"],
            "resolves": "B-3 / document defect D-4",
            "upstream": "storage_host_from_signed_url -- NOT CONFIGURABLE",
            "upstream_because": (
                "The host is whatever the sharing server vended inside "
                "the pre-signed URL in the S8/S9 response body. There is "
                "no static target to configure, which is why class D's "
                "forwarding policy is carried disabled."
            ),
        },
        "api": {
            "name": "AWOZ-1227 F1 Storage Proxy",
            "apiVersion": API_VERSION,
            "definitionVersion": "V4",
            "type": "PROXY",
            "description": (
                "Channel E-1 route F1: file download through the gateway "
                "storage proxy. Its own HTTP listener, not a flow "
                "selector beneath the sharing listener. GENERATED -- do "
                "not edit."
            ),
            "listeners": [{
                "type": "HTTP",
                "paths": [{"path": sp["path"]}],
                "entrypoints": [{"type": "http-proxy"}],
            }],
            "endpointGroups": [{
                "name": "storage-from-signed-url",
                "type": "http-proxy",
                "endpoints": [{
                    "name": "placeholder-no-static-target",
                    "type": "http-proxy",
                    "configuration": {"target": "https://storage.invalid/"},
                    "_rationale": {
                        "target_is_a_placeholder": True,
                        "because": (
                            "Gravitee requires an endpoint group with a "
                            "target to create a PROXY API. F1 has no "
                            "static upstream: the host lives inside the "
                            "signed URL. storage.invalid is used so that "
                            "a request reaching this upstream FAILS "
                            "LOUDLY rather than silently hitting a real "
                            "host, and so that no real storage hostname "
                            "is committed to the repository."
                        ),
                    },
                }],
            }],
            "flows": [{
                "name": "F1-class-D",
                "enabled": True,
                "selectors": [{
                    "type": "HTTP",
                    "path": "/files/:opaque",
                    "pathOperator": "EQUALS",
                    "methods": list(f1.get("methods") or ["GET", "HEAD"]),
                }],
                "request": req,
                "response": resp,
                "_provenance": {
                    "route_id": "F1",
                    "policy_class": "D",
                    "open_decision": f1.get("open_decision"),
                    "requirements": f1.get("requirements"),
                    "fallback": f1.get("fallback"),
                    "prototype_limit": f1.get("prototype_limit"),
                    "conops_defect": f1.get("conops_defect"),
                    "tests": f1.get("tests"),
                },
            }],
        },
        "plans": [{
            "name": "plan-storage-proxy",
            "security": {"type": "KEY_LESS"},
            "definitionVersion": "V4",
        }],
        "_not_built": [{
            "route_id": "F1",
            "warning": "FORWARDING_DISABLED",
            "detail": (
                "The listener and the policy chain are real; the "
                "forwarding step is not. policy-http-callout needs a "
                "static or EL `url` and the pre-signed URL exists only "
                "per-request inside the response body. OD-1's documented "
                "fallback applies: storage address limits plus "
                "short-lived credentials. T-08's refusal half is also not "
                "provable on Free Edition, where storage is "
                "Databricks-managed."
            ),
        }],
    }


# ---------------------------------------------------------------------
# The safety assertion
# ---------------------------------------------------------------------

def assert_no_token_in_output(blobs, resolved):
    """The generator reads credential files that contain live bearer
    tokens. Nothing stops a future edit from carrying one into the
    output except this check, so the check exists rather than the
    promise. §3.6: secrets appear only as .env references."""
    tokens = []
    for rec in resolved:
        cred = ROOT / rec["credential_file"]
        tok = json.loads(cred.read_text()).get("bearerToken")
        if tok:
            tokens.append(tok)
    findings = []
    for name, text in blobs.items():
        for tok in tokens:
            if tok and tok in text:
                findings.append({"file": name, "leak": "BEARER_TOKEN_IN_GENERATED_OUTPUT"})
            # Also catch a partial carry: a long prefix is still a secret.
            elif tok and len(tok) > 24 and tok[:24] in text:
                findings.append({"file": name, "leak": "BEARER_TOKEN_PREFIX_IN_GENERATED_OUTPUT"})
    return findings


# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-test-cidr", action="store_true",
                    help=f"add {LOCAL_TEST_CIDR} to every APPLIED IP "
                         "allow-list so this host's own test client is "
                         "admitted. OFF BY DEFAULT since 2026-10-21: T-03 "
                         "measured the address the policy compares "
                         "(172.21.0.1, the Docker bridge) and it is inside "
                         "that CIDR, so including it admits every client "
                         "that can reach the gateway from this host and the "
                         "allow-list refuses nobody (B-47). With this flag "
                         "off, reads through an APPLIED recipient's route "
                         "are EXPECTED to be refused locally -- that is the "
                         "control working, not a broken route.")
    ap.add_argument("--check", action="store_true",
                    help="generate in memory and report what would change, write nothing")
    args = ap.parse_args()

    rt = load_yaml(ROUTE_TABLE)
    pc = load_yaml(POLICY_CLASSES)
    resolved, unresolved = load_recipient_endpoints()

    print(f"route table:     {len(rt['routes'])} routes")
    print(f"policy classes:  {', '.join(sorted(pc['classes'].keys()))}")
    print(f"recipients:      {len(resolved)} resolved, {len(unresolved)} unresolved\n")

    for u in unresolved:
        print(f"  [UNRESOLVED] {u['recipient']}: {u['reason']}")
    if unresolved:
        print()

    if not resolved:
        print("VERDICT: CANNOT_GENERATE_NO_RESOLVED_RECIPIENT")
        sys.exit(1)

    blobs = {}
    family = []
    for rec in resolved:
        doc = build_recipient_api(rt, pc, rec, args.local_test_cidr)
        fname = f"api-e1-{rec['slug']}.json"
        blobs[fname] = json.dumps(doc, indent=2)
        family.append({
            "slug": rec["slug"],
            "recipient": rec["recipient"],
            "definition": f"gravitee/generated/{fname}",
            "edge_path": doc["_generated"]["edge_path"],
            "upstream_host": rec["host"],
            "upstream_base_path": rec["base_path"],
            "flows": len(doc["api"]["flows"]),
            "credential_expires": rec["expiration_time"],
            "grants": rec["grants"],
            "dsa_ref": rec["dsa_ref"],
            "dsa_ref_status": rec["dsa_ref_status"],
            "ip_access_list_mode": (rec["ip_access_list"] or {}).get("mode"),
            "not_built": doc["_not_built"],
        })
        print(f"  {rec['slug']:<16} {doc['_generated']['edge_path']:<36} "
              f"-> {rec['host'][:20]}...  ({len(doc['api']['flows'])} flows)")

    sp = build_storage_proxy_api(rt, pc)
    if sp:
        blobs["api-f1-storage-proxy.json"] = json.dumps(sp, indent=2)
        print(f"  {'f1-storage-proxy':<16} {sp['_generated']['edge_path']:<36} "
              f"-> (no static upstream)  (1 flow)")

    manifest = {
        "generated_by": "scripts/29_gen_gravitee_route_family.py",
        "generated_at": now(),
        "conops": "AWOZ-1227 v1.5 §2.3.2 channel E-1",
        "epic": "E2 Task 2.1, borrowed into E1 Task 1.6",
        "shape": "ROUTE_FAMILY_ONE_API_PER_RECIPIENT",
        "shape_because": (
            "The sharing endpoint hostname is per-recipient and the "
            "platform validates the host/token binding: 400 BAD_REQUEST "
            "'Request URL hostname ... does not match with the recipient "
            "id ...'. §2.3.2's single route with a single upstream target "
            "cannot be built. docs/11 B-42, docs/10 D-9."
        ),
        "inputs": {
            "iac/config/route-table.yaml": sha12(ROUTE_TABLE),
            "iac/config/policy-classes.yaml": sha12(POLICY_CLASSES),
            "iac/config/recipients.yaml": sha12(RECIPIENTS),
        },
        "input_hashes_are_for": (
            "T-12's 'redeploy from code to a clean target -> same "
            "configuration'. Same input hashes plus same generator "
            "version must yield byte-identical definitions, which is "
            "what makes the redeploy claim checkable rather than "
            "asserted."
        ),
        "family": family,
        "unresolved": unresolved,
        "retired": {
            "gravitee/api-definition.json": {
                "status": "SUPERSEDED -- CARRIED FORWARD, NOT DELETED (B-19)",
                "sha12": sha12(LEGACY_DEF),
                "superseded_because": (
                    "Its upstream target "
                    "https://<DATABRICKS_HOST>/api/2.0/delta-sharing is "
                    "wrong twice: wrong HOST (the workspace host is not "
                    "the sharing host) and wrong PATH (no issued "
                    "credential contains /api/2.0/delta-sharing; the real "
                    "path is /api/2.0/opensharing/metastores/<id>). This "
                    "is the better explanation for T-01 never having "
                    "produced a read through the gateway."
                ),
                "what_it_still_contributes": (
                    "Its policy identifiers and configuration field names "
                    "were verified against this installation's own "
                    "plugins/policies schema endpoints. That verification "
                    "is carried into policy-classes.yaml, which is why "
                    "the file is superseded rather than discarded."
                ),
                "retire_in_gravitee_by": (
                    "RETRACTED 2026-10-21, before anyone acted on it. "
                    "The live API at /opensharing-demo/ must be stopped, "
                    "its plans closed, and the API DELETED BEFORE the "
                    "family is imported."
                ),
                "retire_in_gravitee_by_superseded_text": (
                    "The two live APIs (/opensharing-demo/ and "
                    "/delta-sharing/) must be stopped and deleted AFTER "
                    "the family imports and T-01 passes, not before -- "
                    "deleting the old route first removes the only "
                    "working comparison."
                ),
                "retire_in_gravitee_by_retracted_because": (
                    "Three observations, each sufficient on its own. "
                    "(1) SEQUENCING: a Gravitee context path is a PREFIX, "
                    "so the existing API at /opensharing-demo/ COLLIDES "
                    "with every /opensharing-demo/<slug> listener in this "
                    "family. The old API does not merely survive the "
                    "import -- it BLOCKS it. On the 2026-10-21 run only "
                    "the F1 storage proxy imported, because /storage-proxy/ "
                    "was the one path with no collision. "
                    "(2) The 'only working comparison' did not exist. That "
                    "API has flows: 0 -- no perimeter policies at all -- "
                    "and its upstream is pinned to the sharing host of a "
                    "credential that EXPIRED 2026-10-18, so it cannot "
                    "produce a successful read for any recipient and never "
                    "could. It has been an unpoliced pass-through to a "
                    "dead host. "
                    "(3) Worse than useless: because it prefix-matches, it "
                    "ANSWERED this family's paths by forwarding them "
                    "upstream with the recipient slug glued into the "
                    "protocol path, producing Databricks 404s that read "
                    "like gateway refusals. That is B-44, and this "
                    "sentence is what kept the blocking object alive long "
                    "enough to cause it."
                ),
                "retraction_note": (
                    "Carried in place rather than edited away (B-19). The "
                    "wrong advice was mine, it was specific, and it was "
                    "the kind that gets followed."
                ),
            }
        },
        "known_incomplete": [
            {
                "id": "RF-1",
                "what": "The deny catch-all (route X) is emitted disabled.",
                "because": "policy-classes.yaml PC-4: terminal-deny policy shape unconfirmed.",
                "today": "Unmatched paths fail closed because nothing matches them -- right outcome, by accident not decision.",
            },
            {
                "id": "RF-2",
                "what": "Class B's json-validation runs the permissive fallback.",
                "because": "iac/gravitee/schemas/query-body.schema.json does not exist (PC-1).",
                "consequence": "T-06 can only return CANNOT_SEE against this build.",
            },
            {
                "id": "RF-3",
                "what": "F1 forwarding is disabled; S8/S9 URL rewrite is NOT_BUILT.",
                "because": "No verified ndjson-aware body-rewrite policy, and no static storage target.",
                "consequence": "T-08 records the OD-1 fallback, not a proxied download.",
            },
            {
                "id": "RF-4",
                "what": "T-07's expanded removeHeaders list is a hypothesis.",
                "because": "Four header names were added after a measured leak and have not been re-tested.",
            },
            {
                "id": "RF-5",
                "what": "GAP-ICEBERG has no route, so /iceberg still falls to the catch-all.",
                "because": "route-table.yaml records it as an OPEN decision for E2, not a route.",
                "consequence": "The rewritten credential's icebergEndpoint points at an edge path that matches nothing.",
            },
            {
                "id": "RF-6",
                "what": "One API per recipient makes recipient onboarding a gateway change.",
                "because": "D-9. §3.4's self-service portal (AC4) assumed adding a recipient was a form submission.",
                "consequence": "AC4's acceptance text needs rewording in v1.6, or the portal needs to call this generator.",
            },
        ],
    }
    blobs["route-family.json"] = json.dumps(manifest, indent=2)

    leaks = assert_no_token_in_output(blobs, resolved)
    print()
    if leaks:
        print("VERDICT: REFUSED_SECRET_IN_GENERATED_OUTPUT")
        for f in leaks:
            print(f"  {f['file']}: {f['leak']}")
        sys.exit(1)
    print(f"secret check:    clean ({len(resolved)} tokens read, 0 reached the output)")

    if args.check:
        changed = []
        for name, text in blobs.items():
            p = OUT / name
            if not p.exists():
                changed.append((name, "NEW"))
            elif p.read_text() != text:
                changed.append((name, "CHANGED"))
        print(f"\n--check: {len(changed)} of {len(blobs)} files would change")
        for n, s in changed:
            print(f"  [{s}] {n}")
        print("\nVERDICT: CHECK_ONLY_NOTHING_WRITTEN")
        return

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in blobs.items():
        (OUT / name).write_text(text + "\n")
    print(f"wrote:           {len(blobs)} files to gravitee/generated/")

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "test_id": "AC6/T-12 material (generation half)",
        "generated_at": now(),
        "verdict": "ROUTE_FAMILY_GENERATED",
        "recipients_resolved": len(resolved),
        "recipients_unresolved": len(unresolved),
        "apis_generated": len([b for b in blobs if b.startswith("api-")]),
        "secret_check": "CLEAN",
        "manifest": "gravitee/generated/route-family.json",
        "what_this_does_not_prove": (
            "Generation is not deployment and deployment is not a read. "
            "This file records that the definitions were produced from the "
            "declared configuration. Whether the gateway accepts them is "
            "scripts/05's result, and whether a recipient can read through "
            "them is T-01's. Reporting this as 'the gateway route works' "
            "would be the §12.4 error."
        ),
    }, indent=2) + "\n")
    print(f"wrote evidence:  {EVIDENCE.relative_to(ROOT)}")

    print(f"\nnot built: {len(manifest['known_incomplete'])} items recorded (RF-1..RF-6)")
    print("VERDICT: ROUTE_FAMILY_GENERATED")
    print("\nNext: python3 scripts/05_import_gravitee_api.py --all")


if __name__ == "__main__":
    main()
