#!/usr/bin/env python3
"""Generate the Gravitee definition for channel E-3: the AI routes.

E1 Task 1.9 | AC1, AC2, AC4 | CONOPS 2.3.2 rows M1-M3, 3.2, 3.1.2
Tests: T-15 (M1, the model route), T-16 (M2/M3, the MCP routes)

WHY A SEPARATE LISTENER AND A SEPARATE SCRIPT
---------------------------------------------
route-table.yaml's `edge` block declares two listeners -- the sharing
listener and the storage proxy -- and neither fits E-3. M1 and M2 target
`workspace_host`, not a per-recipient sharing host, so they do not belong
under the sharing listener's per-recipient route family (B-42/D-9): there
is exactly ONE workspace host and no recipient slug to key on. Putting
them beside the sharing routes would also mean every recipient's API
carried a model route it is not entitled to call.

So E-3 gets its own API at its own context path, and this file generates
it. route-table.yaml gains an `ai_listener` entry to declare it rather
than leaving the path implicit in a script -- the rule AC6/T-12 needs.

WHAT R12 ACTUALLY IS, AND WHY THIS SCRIPT CANNOT CLOSE IT ALONE
---------------------------------------------------------------
§3.2: "an external caller holds no Databricks credential. The gateway
holds one upstream identity per consumer -- a service principal granted
only the assets that consumer may call -- and forwards with its OAuth
token." R12 is the risk that the gateway cannot do this.

R12 is really TWO questions, and the CONOPS asks them as one:

  R12a  Can the gateway inject an upstream credential at all, so that a
        caller holding none gets an answer?
  R12b  Can it do so WITHOUT holding a long-lived secret?

This script can only build for R12a. It injects a credential that the
gateway holds, which is a direct answer to R12a and a direct instance of
the surface OD-4 exists to avoid. R12b needs an OAuth client-credentials
exchange -- the gateway holding a client id and secret and minting
short-lived tokens, or better, a workload-identity federation so it
holds nothing -- and that is a separate build with a separate test.

Worse for the CONOPS reading: the credential available in this
environment is a **personal access token**, not a service principal's
OAuth token. So the prototype proves the mechanism with the wrong
credential TYPE. A PAT is long-lived, bound to a human, and carries that
human's full entitlements -- the opposite of "granted only the assets
that consumer may call". Every artifact this script writes says so, in
the artifact, because a generated definition that merely worked would
read as though §3.2 had been satisfied.

SECRETS: THE DEFINITION ON DISK MUST NOT CONTAIN ONE
----------------------------------------------------
The injected value is emitted as a Gravitee **property reference** --
`{#properties['...']}` -- and the property is emitted with an EMPTY
value plus a marker naming the .env variable that supplies it. The
import step fills it at import time. So the committed artifact carries a
reference, never a credential (§3.6), and `assert_no_token_in_output`
re-checks that claim rather than trusting it (B-39's lesson: generate or
import the rule, never restate it).

M3 IS A DENY AND IT HAS TO LOOK LIKE A DECISION
-----------------------------------------------
route-table.yaml sets `carry_reason_into_generated_artifact: true` on
M3, and the reason is the whole point: legacy `/api/2.0/mcp/*` bypasses
Unity AI Gateway grants and does not appear in the tracing tables, so it
cannot satisfy AC5. An auditor reading the generated definition must
find that sentence there, not only in a YAML file two directories away.
An omitted route and a refused route are the same absence in a deployed
gateway, and only one of them is a decision.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "iac" / "config"
OUT_DIR = ROOT / "gravitee" / "generated"
EVIDENCE = ROOT / "evidence" / "gravitee-ai-route.json"

API_VERSION = "1.0.0"

# The .env variable that supplies the injected upstream credential. Named
# here once so the marker in the artifact, the import step and the
# evidence record cannot drift apart.
UPSTREAM_TOKEN_ENV = "DATABRICKS_TOKEN"
UPSTREAM_TOKEN_PROPERTY = "databricks_upstream_token"

AI_CONTEXT_PATH = "/ai-gateway-demo"

# The one model the probe actually called and got a 200 from. Named, not
# wildcarded: route-table M1's exposure_scope says "One approved model
# service per route. Not a wildcard over /serving-endpoints."
APPROVED_MODEL = "databricks-gpt-oss-20b"


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha12(path):
    if not path.exists():
        return "ABSENT"
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def load_yaml(path):
    if not path.exists():
        sys.exit(f"Missing required input: {path}")
    return yaml.safe_load(path.read_text())


def strip_meta(step):
    """Keep only the fields Gravitee reads; move the rest to _rationale.

    Same function as scripts/29's, same reason: a policy object carrying
    documentation keys is rejected or silently ignored depending on the
    version, and 'silently ignored' is the dangerous one."""
    keep = {"name", "description", "policy", "enabled", "configuration"}
    out = {k: v for k, v in step.items() if k in keep}
    extra = {k: v for k, v in step.items()
             if k not in keep and not k.startswith("_")}
    if extra:
        out["_rationale"] = extra
    return out


def common_policies(pc, phase):
    """Read the common policy set for one side of the exchange.

    Corrected 2026-10-21. The first version of this function read
    `pc["common"][phase]["policies"]` -- a nesting level that does not
    exist. The real shape is a bare list at `pc["common"][phase]`, which
    is what scripts/29 has always read.

    This is B-39 with my name on it: I restated the schema instead of
    importing the one reader that already knew it, and the two copies
    disagreed. It raised AttributeError here only because a list has no
    .get. Had the file's shape been one step different -- a dict without a
    'policies' key -- the `or []` fallback would have returned an EMPTY
    policy set, and the generator would have emitted the AI route with no
    bearer-presence check, no header hygiene, no common controls at all,
    on the single route in the estate that injects a credential. The
    artifact would have imported, started, answered 200, and been wrong.

    So the empty case is now an error rather than a default. A perimeter
    generator that can silently produce a route with no perimeter is worse
    than one that crashes. The two functions are still duplicated across
    scripts/29 and /30 because a leading digit makes neither importable
    without importlib; that duplication is recorded as AI-6."""
    rows = (pc.get("common") or {}).get(phase)
    if not isinstance(rows, list) or not rows:
        sys.exit(
            f"policy-classes.yaml: common.{phase} is missing, empty or not "
            "a list. Refusing to generate: an empty common set would emit "
            "the credential-injecting route with no common controls on it, "
            "and it would import and answer 200 regardless.")
    return [strip_meta(dict(s)) for s in rows]


def class_policies(pc, cls, phase):
    """Read one class's policies for one side. Same shape, same reasoning
    as common_policies -- a bare list, and empty is an error.

    A class whose policies vanished would drop the rate limit and the
    response controls that make the class mean anything, leaving a route
    labelled 'class E' that enforces nothing class E describes."""
    block = (pc.get("classes") or {}).get(cls)
    if not isinstance(block, dict):
        sys.exit(f"policy-classes.yaml: no class '{cls}'. Refusing to "
                 "generate a route that claims a class the file does not "
                 "define.")
    rows = block.get(phase)
    if rows is None:
        return []
    if not isinstance(rows, list):
        sys.exit(f"policy-classes.yaml: classes.{cls}.{phase} is not a "
                 "list. The generator and the file disagree about shape.")
    return [strip_meta(dict(s)) for s in rows]


def strip_caller_identity():
    """Remove the caller's Authorization, as a SEPARATE policy step.

    MEASURED 2026-10-21, and this is the whole reason there are two
    policies where there was one.

    The first build put removeHeaders and addHeaders for the same header
    in ONE transform-headers policy, with a comment saying "strip the
    caller's own first, so the add is a replace". That comment described
    an ordering the policy does not guarantee. The observed behaviour is
    the opposite: the gateway returned

        401 {"error_code":401,"message":"Credential was not sent or was
             of an unsupported type for this API."}

    -- the remove ran AFTER the add and deleted the header the same
    policy had just injected.

    Why this mattered more than an ordinary config bug: the failure mode
    is a 401 from the UPSTREAM, forwarded through the edge. It is the
    exact response a working gateway gives an unauthenticated caller
    whose credential it was never asked to supply. Read without
    attribution, "401 through the AI route" says R12a is impossible --
    the gateway cannot inject an upstream identity. What was true is
    that it injected one and then threw it away. That is B-44's shape on
    a new route: an upstream refusal forwarded through the edge, with
    the remedy at neither place a reader would look.

    Splitting the two operations into two policies makes the order an
    explicit property of the flow, visible in the generated artifact and
    in the console, rather than an assumption inside one configuration
    block. T-15 phase 3 is what proves the split works: an invalid
    caller token must still yield 200, which can only happen if the
    strip really precedes the add."""
    return {
        "name": "Strip the caller's Authorization header",
        "description": (
            "Step 1 of 2. Removes the caller's credential BEFORE the "
            "gateway's is added, so the injection is a replacement. Must "
            "stay immediately before the inject step; see _rationale."
        ),
        "policy": "transform-headers",
        "enabled": True,
        "configuration": {
            "scope": "REQUEST",
            "removeHeaders": ["Authorization"],
            "addHeaders": [],
        },
        "_rationale": {
            "why_a_separate_policy": (
                "removeHeaders and addHeaders for the SAME header inside "
                "one transform-headers policy do not run in the written "
                "order. Measured 2026-10-21: the combined form returned "
                "401 'Credential was not sent' because the remove ran "
                "after the add. Two policies make the order explicit."
            ),
            "ordering_is_load_bearing": (
                "If these two steps are ever reordered, or this one is "
                "disabled, the route keeps answering 200 for callers who "
                "send a valid token of their own -- and T-15 phase 2 "
                "would still pass, because a caller sending NO header is "
                "unaffected by a failed strip. Only phase 3, with a "
                "deliberately invalid caller token, distinguishes them."
            ),
            "failure_mode_if_broken": (
                "401 from Databricks, forwarded through the edge. "
                "Indistinguishable without attribution from the gateway "
                "being unable to inject at all, i.e. from R12a being "
                "impossible. B-44."
            ),
        },
    }


def inject_upstream_identity():
    """Add the gateway's own Authorization. Step 2 of 2.

    Preceded by strip_caller_identity(), which removes the caller's
    header in a separate policy. See that docstring for why the two are
    not one policy -- it cost a 401 that reads exactly like R12a being
    impossible."""
    return {
        "name": "Inject the gateway's upstream identity (R12a)",
        "description": (
            "CONOPS 3.2. The external caller holds no Databricks "
            "credential; the gateway supplies one. PROTOTYPE: the value "
            "is a personal access token, NOT a per-consumer service "
            "principal OAuth token -- see _rationale."
        ),
        "policy": "transform-headers",
        "enabled": True,
        "configuration": {
            "addHeaders": [
                {"name": "Authorization",
                 "value": "Bearer {#properties['"
                          + UPSTREAM_TOKEN_PROPERTY + "']}"},
            ],
            # Empty. The removal is a SEPARATE preceding policy -- see
            # strip_caller_identity(). It was here, in this block, and
            # the gateway ran it after the add.
            "removeHeaders": [],
            "scope": "REQUEST",
        },
        "_rationale": {
            "risk": "R12",
            "r12a_this_closes": (
                "Whether the gateway CAN inject an upstream credential so "
                "a caller holding none is served. This policy is the "
                "build for that half."
            ),
            "r12b_this_does_not_close": (
                "Whether it can do so WITHOUT holding a long-lived "
                "secret. It cannot, as built: the gateway holds the "
                "credential. That is the secret-custody surface OD-4 "
                "exists to keep off the gateway, so this build is "
                "evidence FOR OD-4 being a real decision, not evidence "
                "that §3.2 is satisfied."
            ),
            "wrong_credential_type": (
                "§3.2 specifies a service principal granted only the "
                "assets one consumer may call, forwarded as an OAuth "
                "token. What is injected here is a PERSONAL ACCESS "
                "TOKEN: long-lived, bound to a human operator, and "
                "carrying that human's FULL entitlements. So the "
                "least-privilege property §3.2 relies on is absent, and "
                "a passing T-15 must not be read as §3.2 demonstrated. "
                "v1.6 should state the SP-per-consumer provisioning as "
                "unbuilt and name its owner."
            ),
            "remove_before_add_because": (
                "The caller's Authorization is removed so the injection "
                "is a REPLACEMENT. If it were merely added, a 200 "
                "through the gateway could be the caller's own token "
                "working, and the test would credit the gateway for it "
                "-- the silent negative with the sign flipped (B-40)."
            ),
            "removal_lives_in_the_previous_policy": (
                "SUPERSEDED IN PLACE 2026-10-21 (B-19). This policy "
                "originally carried removeHeaders:['Authorization'] "
                "alongside its addHeaders, and the gateway applied the "
                "removal AFTER the addition, deleting the injected "
                "header and returning 401 'Credential was not sent'. "
                "The removal is now the separate preceding step "
                "'Strip the caller's Authorization header'. The "
                "reasoning above was correct; the single-policy "
                "expression of it was not."
            ),
            "value_is_a_reference": (
                "The value is a Gravitee property reference. The "
                "property ships with an EMPTY value and is filled at "
                "import time from " + UPSTREAM_TOKEN_ENV + ". No "
                "credential is written to this file (§3.6)."
            ),
        },
    }


def build_model_flow(pc, rt_row):
    cls = rt_row.get("policy_class") or "E"
    path = f"/serving-endpoints/{APPROVED_MODEL}/invocations"
    # Strip THEN inject, as two adjacent steps. The order here is the
    # control: see strip_caller_identity(). Both come AFTER the common
    # set so the bearer-presence attribute records what the CALLER sent,
    # not what the gateway substituted -- an attribute measuring the
    # gateway's own injected header would report every anonymous caller
    # as having presented a bearer token, which is the opposite of the
    # fact AC5's audit trail needs.
    req = (common_policies(pc, "request")
           + [strip_meta(strip_caller_identity()),
              strip_meta(inject_upstream_identity())]
           + class_policies(pc, cls, "request"))
    resp = common_policies(pc, "response") + class_policies(pc, cls, "response")
    return {
        "name": f"M1-class-{cls}",
        "enabled": True,
        "selectors": [{
            "type": "HTTP",
            "path": path,
            "pathOperator": "EQUALS",
            "methods": list(rt_row.get("methods") or ["POST"]),
        }],
        "request": req,
        "response": resp,
        "_rationale": {
            "route_id": "M1",
            "channel": "E-3",
            "approved_model": APPROVED_MODEL,
            "path_is_literal_not_wildcard": (
                "route-table M1 exposure_scope: 'One approved model "
                "service per route. Not a wildcard over "
                "/serving-endpoints.' The model name is therefore "
                "literal in the selector. A wildcard here would expose "
                "all 12 endpoints the probe listed, including the "
                "embedding models, on a route approved for one."
            ),
            "policy_class": cls,
            "class_e_precedence_problem": (
                "Class E carries the two-limiter problem recorded in "
                "policy-classes.yaml: Gravitee's rate-limit and the "
                "platform's own quota can both refuse, and a 429 does "
                "not say which. T-15's limiter phase measures it by "
                "running the burst twice -- Gravitee's limit below the "
                "platform's, then above it -- and attributing the "
                "refusal from the body."
            ),
        },
    }


M3_DENY_MARKER = "AWOZ-1227-M3-LEGACY-MCP-DENIED-AT-THE-EDGE"


def build_m3_deny(rt_row):
    """M3: legacy managed MCP, explicitly refused at the edge.

    REWRITTEN 2026-10-21 after T-16 measured the first version and found
    it did nothing. B-19: the previous expression is recorded below, not
    deleted.

    WHAT THE FIRST VERSION DID
    --------------------------
    It used `policy-request-validation` with `{"rules": [], "status":
    "403"}` and a comment saying an empty rule set "refuses everything
    reaching the flow". That is the opposite of the truth. The policy's
    schema (read from this installation today) makes `rules` required and
    the policy validates each rule in turn; with NO rules there is
    nothing to fail, so every request passes. The flow was a deny that
    denied nothing -- a decision written down as configuration that the
    gateway read as a no-op.

    That is AI-4's predicted failure mode exactly, and AI-4 named the
    reason it was dangerous: "if it fails to load, the flow FORWARDS
    instead of refusing -- the dangerous direction -- and the upstream
    404 would look like a successful block." It did not even need to fail
    to load. It loaded and forwarded.

    T-16 is why this is known rather than assumed. It returned
    DENY_DOES_NOT_FIRE_THE_EDGE_FORWARDED_THE_REQUEST because it refused
    to accept any 403 as proof and required Gravitee's own voice. A test
    that had asserted `status in (401, 403)` would have gone green on the
    upstream's forwarded 401 and this flow would have shipped.

    WHY `mock` AND NOT A FILTER
    ---------------------------
    Enforcement for M3 now comes from the terminal allow-list at the end
    of the flow array -- see terminal_allow_list(). That leaves this flow
    one job, and it is a job no filter can do: say WHY, in the response,
    to the caller. route-table.yaml sets
    carry_reason_into_generated_artifact: true on this row; a `mock`
    policy carries the reason one step further than the artifact, into
    the answer the caller actually receives.

    It also makes the refusal ATTRIBUTABLE. The terminal allow-list is a
    resource-filtering policy and refuses with
    {"message":"You're not allowed to access this resource", ...}. If
    this flow also refused with resource-filtering, the two controls
    would be indistinguishable in the response body and T-16 could not
    tell which one fired -- two policies of the same type speaking the
    same words is a new way to lose attribution. The mock body carries
    M3_DENY_MARKER, so T-16 can say which control answered, by name.

    The field names (`status`, `headers`, `content`) were read from this
    installation's policy schema endpoint today, not restated from
    documentation -- the correction AI-6 is about.

    IF THIS POLICY FAILS ANYWAY, THE FAILURE IS NOW CLOSED
    ------------------------------------------------------
    The direction of failure has been inverted, which is the part worth
    more than the policy swap. Previously a broken deny FORWARDED to the
    real legacy MCP endpoint. Now a broken deny falls through to the
    terminal allow-list, which does not list /api/2.0/mcp and so refuses
    it. So the remaining risk is a legible one -- the caller gets a 403
    with no reason in it -- rather than silent exposure. T-16 reports
    these as two different verdicts instead of one."""
    reason = (rt_row.get("not_exposed_because") or "").strip()
    body = json.dumps({
        "error": "route_not_exposed",
        "marker": M3_DENY_MARKER,
        "route_id": "M3",
        "refused_by": "AWOZ-1227 edge, by explicit decision",
        "reason": reason or "See CONOPS 2.3.2 row M3.",
        "conops_ref": rt_row.get("conops_ref") or "2.3.2",
    }, indent=2)
    return {
        "name": "M3-explicit-deny-legacy-mcp",
        "enabled": True,
        "selectors": [{
            "type": "HTTP",
            "path": "/api/2.0/mcp",
            "pathOperator": "STARTS_WITH",
        }],
        "request": [{
            "name": "Deny legacy managed MCP",
            "description": reason[:500],
            "policy": "mock",
            "enabled": True,
            "configuration": {
                "status": "403",
                "headers": [
                    {"name": "Content-Type", "value": "application/json"},
                    # A second, header-borne copy of the attribution, so
                    # the claim survives a response-body sanitizer. T-07's
                    # policy strips response headers it does not
                    # recognise, which would take this one -- that is
                    # worth knowing and is exactly why the marker is in
                    # the BODY as well as here, rather than only here.
                    {"name": "X-AWOZ-Refused-By", "value": "M3-explicit-deny"},
                ],
                "content": body,
            },
            "_rationale": {
                "route_id": "M3",
                "enforcement": "reason_carrier_NOT_the_enforcing_control",
                "enforcement_note": (
                    "The control that actually keeps unlisted paths off "
                    "the upstream is the terminal allow-list at the end "
                    "of the flow array. This flow exists so the refusal "
                    "is a legible DECISION rather than an anonymous 403, "
                    "and so T-16 can attribute the refusal to M3 by "
                    "name. If this flow were deleted, the path would "
                    "still be refused -- with no reason attached."
                ),
                "not_exposed_because": rt_row.get("not_exposed_because"),
                "conops_ref": rt_row.get("conops_ref"),
                "attribution_marker": M3_DENY_MARKER,
                "why_the_reason_is_here": (
                    "route-table.yaml sets "
                    "carry_reason_into_generated_artifact: true on this "
                    "row. An auditor reads the deployed definition, not "
                    "the YAML two directories away. And an OMITTED route "
                    "and a REFUSED route are the same absence in a "
                    "deployed gateway -- only one of them is a decision, "
                    "and the definition has to say which."
                ),
                "superseded_2026_10_21": (
                    "B-19. This step was previously "
                    "policy-request-validation with configuration "
                    "{'rules': [], 'status': '403'} and a comment "
                    "claiming an empty rule set refuses everything "
                    "reaching the flow. MEASURED FALSE by T-16: the "
                    "policy validates each rule in turn, so an empty "
                    "rule set has nothing to fail and PASSES everything. "
                    "The flow forwarded legacy MCP requests to the "
                    "upstream, which answered 404, and a reader without "
                    "attribution would have scored that 404 as a "
                    "successful block. AI-4 predicted this exact "
                    "direction of failure and is now closed by "
                    "measurement, not by argument."
                ),
                "policy_shape_now_verified": (
                    "policy id 'mock', fields status/headers/content, "
                    "read from GET /policies/mock/schema on this "
                    "installation on 2026-10-21. The previous shape was "
                    "never checked against that endpoint, which is what "
                    "AI-4 flagged and what turned out to be the defect."
                ),
                "still_unverified": (
                    "That `mock` SHORT-CIRCUITS in the request phase of "
                    "a V4 proxy API has not been observed here. If it "
                    "does not, this flow contributes nothing and the "
                    "terminal allow-list refuses the path instead -- "
                    "a 403 with no reason in it. T-16 distinguishes the "
                    "two outcomes by the marker above and reports them "
                    "as different verdicts, so this cannot be mistaken "
                    "for a working deny."
                ),
                "positive_control_required": (
                    "Both candidate legacy MCP paths already return 404 "
                    "UPSTREAM (policy-classes.yaml m3_note), so an edge "
                    "block and an absent endpoint are the same "
                    "observation. T-16 cannot claim this deny works "
                    "without a same-path positive control: the same path "
                    "with this flow DISABLED must return something other "
                    "than this 403, in the same run (B-40). NOTE: with "
                    "the terminal allow-list in place, disabling THIS "
                    "flow alone still yields a 403 -- from the "
                    "allow-list. So the control now has to disable both, "
                    "and the two refusals are told apart by the marker, "
                    "not by the status code."
                ),
            },
        }],
        "response": [],
    }


def terminal_allow_list(forwarding_flows):
    """Refuse every path the route table does not name. Must be LAST.

    NEW 2026-10-21. This flow is the fix for the defect T-16 uncovered,
    and the defect was much larger than the test was looking for.

    WHAT WAS MEASURED
    -----------------
    Gravitee matches a context path as a PREFIX, and a request whose path
    matches NO flow selector is not refused -- it is FORWARDED to the
    endpoint target with the context path stripped. This API's target is
    the Databricks workspace ROOT (it has to be; see the endpoint's
    _rationale). The two facts compose into an open reverse proxy.

    Measured live with a valid caller token, before this flow existed:

      /ai-gateway-demo/api/2.0/serving-endpoints  -> 200
      /ai-gateway-demo/api/2.0/clusters/list      -> 200
      /ai-gateway-demo/api/2.0/token/list         -> 200

    The last one returns personal access token metadata. And the identity
    those calls ran as was not the caller's: this route STRIPS the
    caller's Authorization and injects the gateway's, so an anonymous
    caller reached the whole workspace REST API as the gateway's own
    credential -- which, per AI-3, is a PAT carrying a human operator's
    full entitlements. The injection policy that answers R12a was also
    the thing that made the hole worth exploiting.

    WHY THE SHARING ROUTES DID NOT SHOW THIS
    ----------------------------------------
    They are confined, but not by the gateway. Their endpoint target
    carries a deep base path, so a stray path is APPENDED to it and the
    upstream 404s ("No API found for 'GET /opensharing/metastores/...'").
    That is confinement by target shape -- a property of how the URL
    concatenates, not a decision anyone made. The AI route differs only
    in that its target has no path to hide behind, so the same missing
    control became visible.

    WHAT THIS FALSIFIES
    -------------------
    scripts/29_gen_gravitee_route_family.py's build_catch_all says an
    unmatched path "fails closed because nothing matches it, which is the
    right OUTCOME reached by accident rather than by decision". The
    outcome was not right. That claim is retracted in place in that file.
    §2.3.2's route table was a documentation allow-list that nothing
    enforced (B-48).

    WHY A WHITELIST AND NOT A LIST OF DENIES
    ----------------------------------------
    A deny list has to anticipate every path worth protecting, on a REST
    API with hundreds of them, and it fails open on everything it forgot.
    This whitelist fails closed on everything not named. The verdict for
    a forgotten route is a visible 403 on a route someone wanted, not
    silent reach into one nobody did.

    THE WHITELIST IS DERIVED, NOT RESTATED
    --------------------------------------
    The patterns are read off the selectors of the flows that actually
    forward, which are passed in. Writing them out again here is the
    B-39 mistake that has already produced four defects in this repo
    today, and it has a specific bad shape here: an allow-list that
    drifts from the routes it is supposed to admit either refuses a live
    route (loud, fine) or admits a path no flow claims (silent, not
    fine).

    normalizeRequestPath AND decodeEncodedSlash
    -------------------------------------------
    Both default to FALSE in this installation's schema, which I read
    today rather than assuming. Both are set TRUE here. With them off,
    the policy matches the raw request path while the upstream resolves
    a normalized one, so `/api/2.0/./mcp/servers` and an encoded-slash
    variant are a different string to this policy and the same resource
    to Databricks. For a whitelist that mismatch mostly fails closed; for
    M3's path it is a straight bypass. Setting them is the difference
    between filtering the resource and filtering the spelling."""
    patterns = []
    for flow in forwarding_flows:
        for sel in flow.get("selectors") or []:
            path = sel.get("path")
            if not path:
                continue
            op = sel.get("pathOperator") or "EQUALS"
            entry = {"pattern": path if op == "EQUALS" else path.rstrip("/") + "/**"}
            methods = sel.get("methods")
            if methods:
                entry["methods"] = list(methods)
            # Named so the generated artifact says which flow admitted
            # each pattern. An allow-list entry with no provenance is one
            # nobody can safely remove later.
            entry["_admits_flow"] = flow.get("name")
            patterns.append(entry)
    if not patterns:
        sys.exit(
            "terminal_allow_list: no forwarding flow contributed a "
            "pattern. Refusing to generate. An EMPTY whitelist is the "
            "same trap as the empty `rules` set this flow exists to "
            "replace -- it is indistinguishable, in the artifact, from a "
            "whitelist that was never meant to constrain anything, and "
            "whether Gravitee then reads it as 'allow nothing' or as "
            "'no constraint' decides between a dead route and an open "
            "proxy. The generator must not ship a definition whose "
            "safety depends on which way that is resolved.")
    return {
        # X- prefix and last position: scripts/29's build_catch_all sets
        # must_be_last with the reason "A catch-all evaluated before a
        # specific route swallows it". The same rule applies here for a
        # different reason -- see _rationale.must_be_last_because.
        "name": "X-terminal-allow-list",
        "enabled": True,
        "selectors": [{
            "type": "HTTP",
            "path": "/",
            "pathOperator": "STARTS_WITH",
        }],
        "request": [{
            "name": "Allow only the paths the route table names",
            "description": (
                "Fails closed on every path no flow claims. Without this, "
                "an unmatched path is FORWARDED to the workspace root -- "
                "measured 2026-10-21, see _rationale."
            ),
            "policy": "resource-filtering",
            "enabled": True,
            "configuration": {
                "whitelist": [{k: v for k, v in p.items()
                               if not k.startswith("_")} for p in patterns],
                "normalizeRequestPath": True,
                "decodeEncodedSlash": True,
            },
            "_rationale": {
                "risk": "B-48",
                "measured_before": (
                    "With a valid caller token and no such flow: "
                    "/ai-gateway-demo/api/2.0/token/list -> 200, "
                    "/api/2.0/clusters/list -> 200, "
                    "/api/2.0/serving-endpoints -> 200. The AI route was "
                    "an open reverse proxy to the entire Databricks "
                    "workspace REST API."
                ),
                "corrected_severity_2026_10_21": (
                    "B-19. An earlier version of this key said the open "
                    "paths ran 'as the gateway's injected identity', "
                    "which would have made this a privilege escalation. "
                    "MEASURED AND WRONG: the strip and inject policies "
                    "live inside M1's flow, whose selector is EQUALS on "
                    "the single model path, so an unclaimed path never "
                    "reaches them. Anonymous callers got 401 from "
                    "Databricks ('Credential was not sent'); only callers "
                    "presenting their OWN token got 200, with their own "
                    "entitlements. So this was a bypass of the route "
                    "restriction, NOT an escalation -- a caller reached "
                    "nothing through the edge they could not reach "
                    "directly. Still an AC1/AC2 defect, because §3.1.2 "
                    "reads as though the edge constrains WHICH paths a "
                    "consumer may use. And one selector edit from being "
                    "an escalation: widen M1's EQUALS to a prefix, or "
                    "move the injection to a common flow, and the "
                    "gateway's credential starts reaching unclaimed "
                    "paths. T-15 phase 4 is the test that holds that "
                    "line."
                ),
                "measured_after": (
                    "Verified live on 2026-10-21 by PUT and deploy "
                    "before being written here: token/list 403, "
                    "mcp/servers 403, serving-endpoints 403, "
                    "clusters/list 403, all with "
                    "{'message':\"You're not allowed to access this "
                    "resource\",'http_status_code':403}; and the M1 "
                    "model path still 200 with no caller credential. "
                    "The fix was measured first and generated second, "
                    "not the other way round."
                ),
                "patterns_with_provenance": patterns,
                "patterns_are_derived": (
                    "Read off the selectors of the forwarding flows "
                    "rather than written out again, so the allow-list "
                    "cannot drift from the routes it admits (B-39)."
                ),
                "array_position_does_not_decide_order": (
                    "MEASURED 2026-10-21, and it RETRACTS the claim this "
                    "key used to make (B-19). The old text said this "
                    "flow 'must be last', because last it would run "
                    "after M3's explicit deny and so catch only what no "
                    "flow claimed. It is emitted last and it runs FIRST "
                    "anyway. On the live API the flow array is [M1, M3, "
                    "X-terminal-allow-list] and a GET of "
                    "/api/2.0/mcp/servers is answered by THIS policy, "
                    "not by M3's mock. Disabling this flow and changing "
                    "nothing else makes the same path return M3's "
                    "marker, so M3 works and is simply never reached. "
                    "Gravitee evaluates flows from the most GENERIC "
                    "selector to the most specific, and '/' STARTS_WITH "
                    "is the most generic selector there is. Array order "
                    "is not evaluation order. scripts/29's build_catch_all "
                    "carries the same must_be_last rule and it is wrong "
                    "there for the same reason; it is annotated in that "
                    "file."
                ),
                "consequence_m3_reason_not_delivered": (
                    "Because this policy is reached first, M3's mock "
                    "never answers while this flow is enabled, so the "
                    "CONOPS reason does not reach the CALLER -- the "
                    "caller gets this policy's anonymous 403. That is "
                    "accepted deliberately. The requirement "
                    "route-table.yaml states is "
                    "carry_reason_into_generated_artifact, and the "
                    "artifact is where an auditor reads it; delivering it "
                    "in the response was an addition, not the "
                    "requirement. The alternative -- whitelisting "
                    "/api/2.0/mcp here so M3 can answer -- trades a "
                    "fail-CLOSED perimeter for a legible message, and "
                    "would forward legacy MCP to the real upstream the "
                    "moment M3's flow was disabled. Recorded as AI-9."
                ),
                "why_m3_stays_enabled_anyway": (
                    "It is the backstop. If this flow is ever removed or "
                    "disabled, M3's mock is what refuses the legacy MCP "
                    "path, with its reason attached. T-16 proves that by "
                    "disabling this flow and watching the marker appear."
                ),
                "do_not_add_a_condition_to_this_step": (
                    "MEASURED 2026-10-21. A step-level `condition` was "
                    "tried here to let M3's path through to M3's mock: "
                    "{!#request.path.contains('/api/2.0/mcp')}. The PUT "
                    "returned 200, the deployment returned 202, nothing "
                    "warned -- and /api/2.0/token/list then returned "
                    "**200**, i.e. this policy was SKIPPED ENTIRELY. The "
                    "expression evaluated false on every path, and a "
                    "condition that does not evaluate true does not fail "
                    "the request, it OMITS the policy. So an unverifiable "
                    "EL expression is a silent off-switch on the one "
                    "policy in this definition that must never be "
                    "silently off. B-47's pattern -- a value added so "
                    "something would behave -- in its worst form. No "
                    "condition goes on this step."
                ),
                "decides_on_path_only": (
                    "This policy matches the request PATH. It is not "
                    "authorisation: it says nothing about who the caller "
                    "is, and a 403 from it must not be cited as evidence "
                    "that an unentitled caller was refused. Per-consumer "
                    "entitlement on this route is unbuilt -- the plan is "
                    "KEY_LESS (AI-1) -- so the only identity that reaches "
                    "the upstream is the gateway's."
                ),
                "what_a_pass_does_not_mean": (
                    "That the estate is closed. This flow is on the AI "
                    "API only. Every other API generated by scripts/29 "
                    "still forwards unmatched paths, and is confined only "
                    "by its target carrying a deep base path -- an "
                    "accident of URL concatenation, not a control. B-48 "
                    "stays OPEN until the sharing and storage APIs carry "
                    "an equivalent and a test asserts it."
                ),
            },
        }],
        "response": [],
    }


def build_ai_api(rt, pc):
    rows = {r["id"]: r for r in rt["routes"]}
    m1 = rows.get("M1")
    m3 = rows.get("M3")
    if not m1:
        sys.exit("route-table.yaml has no M1 row.")

    # The flows that FORWARD to the upstream. Collected here, at the one
    # place that knows which is which, and handed to terminal_allow_list
    # so the allow-list is derived from them rather than restated. A deny
    # flow must never appear in this list: whitelisting M3's own path
    # would be the allow-list admitting exactly what M3 refuses, and the
    # two would disagree silently.
    m1_flow = build_model_flow(pc, m1)
    forwarding = [m1_flow]

    flows = [m1_flow]
    not_built = []
    if m3:
        flows.append(build_m3_deny(m3))
    else:
        not_built.append({"id": "M3", "reason": "NO_ROW_IN_ROUTE_TABLE"})

    # LAST, after M3. See terminal_allow_list()._rationale
    # .must_be_last_because: evaluated before M3 it swallows M3's path
    # with an anonymous 403, M3's mock never runs, the CONOPS reason
    # never reaches the caller, and T-16 loses the attribution its
    # verdict depends on.
    flows.append(terminal_allow_list(forwarding))

    # M2 is deliberately not generated.
    m2 = rows.get("M2")
    if m2:
        not_built.append({
            "id": "M2",
            "reason": "METHODS_UNCONFIRMED_AND_TARGET_UNCONFIRMED",
            "detail": (
                "route-table M2 carries methods_unconfirmed: true -- "
                "§2.3.2 gives the method as 'MCP', a protocol rather "
                "than an HTTP method. A POST-only selector would "
                "silently drop the streamable-HTTP event stream, which "
                "is the failure mode that looks like a working route. "
                "T-16 settles the methods; until then generating a "
                "selector would be guessing in a deployable artifact."
            ),
            "open_decision": m2.get("open_decision"),
        })

    host = os.environ.get("DATABRICKS_HOST", "").replace("https://", "") \
                     .replace("http://", "").rstrip("/")
    if not host:
        sys.exit("DATABRICKS_HOST is not set; cannot build the M1 upstream.")

    api = {
        "name": "AWOZ-1227 E3 AI Gateway",
        "apiVersion": API_VERSION,
        "definitionVersion": "V4",
        "type": "PROXY",
        "description": (
            "Channel E-3: one approved model service (M1), an explicit "
            "deny carrying the CONOPS reason for legacy managed MCP "
            "(M3), and a TERMINAL ALLOW-LIST that refuses every path no "
            "flow claims. Without that last flow an unmatched path is "
            "forwarded to the workspace root, which made this route an "
            "open proxy to the whole Databricks REST API (AI-7). "
            "PROTOTYPE -- injects a personal access token, not a "
            "per-consumer service principal OAuth token. See the "
            "generated _rationale blocks."
        ),
        "listeners": [{
            "type": "HTTP",
            "paths": [{"path": AI_CONTEXT_PATH}],
            "entrypoints": [{"type": "http-proxy"}],
        }],
        "endpointGroups": [{
            "name": "default-group",
            "type": "http-proxy",
            "endpoints": [{
                "name": "workspace",
                "type": "http-proxy",
                "weight": 1,
                "inheritConfiguration": False,
                # Corrected 2026-10-21. This read `https://{host}/api/2.0`.
                # route-table.yaml gives M1's target as `workspace_host`
                # and its protocol_path as `/serving-endpoints/{name}/
                # invocations`, with edge_path_equals_protocol_path: true.
                # Gravitee strips the context path and forwards the
                # remainder onto the target, so a target carrying /api/2.0
                # would have produced
                #   https://host/api/2.0/serving-endpoints/.../invocations
                # which does not exist. Serving-endpoint invocation lives
                # at the workspace ROOT; only the REST API lives under
                # /api/2.0.
                #
                # This is B-42 repeated on a new route: a target wrong in
                # the path, which answers and answers wrongly. The damage
                # here is specific and worse than a dead route -- the 404
                # would have landed in T-15 phase 2, the phase that reads
                # a 200 as proof the gateway can inject an upstream
                # identity. A non-200 there reads as R12a being
                # IMPOSSIBLE. The prototype would have reported that the
                # gateway cannot inject a credential when what actually
                # happened is that I pointed it at a path that is not
                # there.
                "configuration": {"target": f"https://{host}"},
                "_rationale": {
                    "target_is_workspace_root_because": (
                        "route-table.yaml M1.target = workspace_host. The "
                        "flow selector carries the full protocol path, so "
                        "the target must contribute no path segment of "
                        "its own."
                    ),
                    "m3_path_note": (
                        "M3's selector is /api/2.0/mcp/* and M3 is a deny "
                        "that never forwards. With this target, if M3's "
                        "deny policy fails to load (AI-4) the request "
                        "forwards to the correct legacy MCP path rather "
                        "than a doubled one -- so a failed deny shows up "
                        "as a real response instead of a 404 that looks "
                        "like a deny. T-16 can tell the difference only "
                        "because of this."
                    ),
                },
            }],
        }],
        "flows": flows,
        # The property the injection policy dereferences. Empty on disk.
        "properties": [{
            "key": UPSTREAM_TOKEN_PROPERTY,
            "value": "",
            "encrypted": False,
            "dynamic": False,
        }],
    }
    return api, not_built


def assert_no_token_in_output(blobs):
    """Re-check the claim that no credential reached the artifact.

    The claim is cheap to make and cheap to break: one edit replacing the
    property reference with os.environ[...] would do it, and the file
    would still import and still work. B-39's lesson was to import the
    rule rather than restate it; this is the same idea applied to the
    output -- verify, do not promise."""
    secrets = []
    for var in (UPSTREAM_TOKEN_ENV, "GLOVASHU_TOKEN", "OSS_PROVIDER_TOKEN",
                "OBJECTSTORE_SECRET_KEY", "GRAVITEE_MGMT_PASSWORD"):
        val = os.environ.get(var)
        if val and len(val) >= 8:
            secrets.append((var, val))
    findings = []
    for name, text in blobs.items():
        for var, val in secrets:
            if val in text:
                findings.append({"file": name, "env_var": var,
                                 "leak": "SECRET_IN_GENERATED_OUTPUT"})
            elif len(val) > 16 and val[:16] in text:
                findings.append({"file": name, "env_var": var,
                                 "leak": "SECRET_PREFIX_IN_GENERATED_OUTPUT"})
    return findings, len(secrets)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="generate and validate, write nothing")
    args = ap.parse_args()

    # .env is read for DATABRICKS_HOST only. The token is NOT read here --
    # this script must not be able to write it even by accident.
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if v.strip():
                os.environ.setdefault(k, v)

    rt = load_yaml(CONFIG / "route-table.yaml")
    pc = load_yaml(CONFIG / "policy-classes.yaml")

    api, not_built = build_ai_api(rt, pc)

    print("=" * 68)
    print("Generating the E-3 AI route (M1 model, M3 deny)")
    print("=" * 68)
    print(f"context path:  {AI_CONTEXT_PATH}")
    print(f"approved model: {APPROVED_MODEL}  (literal, not a wildcard)")
    # Read the target back OUT of the artifact rather than restating it.
    # The restated version printed /api/2.0 while the artifact carried
    # the same wrong value, so the two agreed and neither was checked.
    # Printing the artifact's own value means a future divergence shows
    # up on screen instead of hiding behind a matching string.
    _ep = api["endpointGroups"][0]["endpoints"][0]
    print(f"upstream:      {_ep['configuration']['target']}  "
          f"(from the artifact, not restated)")
    print(f"edge->upstream: {AI_CONTEXT_PATH}"
          f"{api['flows'][0]['selectors'][0]['path']}  ->  "
          f"{_ep['configuration']['target']}"
          f"{api['flows'][0]['selectors'][0]['path']}")
    # Flow NAMES in order, not just a count. The order is the control --
    # the terminal allow-list evaluated before M3 makes M3 dead code
    # (see terminal_allow_list()._rationale.must_be_last_because) -- and
    # a count cannot show a reordering. A report that cannot show the
    # thing that breaks is the shape of a silent negative.
    print(f"flows:         {len(api['flows'])}, in evaluation order:")
    for i, f in enumerate(api["flows"]):
        sel = (f.get("selectors") or [{}])[0]
        print(f"  [{i}] {f['name']:34s} {sel.get('path')} "
              f"{sel.get('pathOperator')}")
    print("  (the X- allow-list MUST be last; it refuses every path no "
          "flow above it claims)")
    for nb in not_built:
        print(f"  [NOT BUILT] {nb['id']}: {nb['reason']}")

    doc = {
        "_generated": {
            "by": "scripts/30_gen_gravitee_ai_route.py",
            "at": now(),
            "epic_task": "E1 Task 1.9",
            "tests": ["T-15", "T-16"],
            "inputs": {
                "route-table.yaml": sha12(CONFIG / "route-table.yaml"),
                "policy-classes.yaml": sha12(CONFIG / "policy-classes.yaml"),
            },
            "status": "PROTOTYPE_R12A_ONLY",
            "status_because": (
                "Builds the injection half of R12 (can the gateway supply "
                "an upstream identity at all). Does NOT build R12b (can "
                "it do so without holding a long-lived secret), and "
                "injects a personal access token rather than a "
                "per-consumer service principal OAuth token. §3.2 is "
                "NOT demonstrated by this artifact."
            ),
            # Keys scripts/05 prints. Added 2026-10-21: the first import
            # printed "edge path None -> upstream None" and
            # "[NOT BUILT] None: None", because this generator invented
            # its own key names for the same facts scripts/29 already
            # publishes under agreed ones. A report that names nothing is
            # not a harmless cosmetic defect -- "[NOT BUILT] None: None"
            # is a warning stripped of the thing it warns about, and it
            # appeared on the one route whose unbuilt item (M2) is an
            # OPEN DECISION. The honest fix is to speak the importer's
            # vocabulary, not to teach the importer a second one.
            "route": "M1 (model) + M3 (deny)",
            "edge_path": AI_CONTEXT_PATH,
            "upstream_host": os.environ.get("DATABRICKS_HOST", "")
                               .replace("https://", "").replace("http://", ""),
            "secret_handling": (
                "The injected value is a property REFERENCE. The property "
                f"ships empty and is filled from {UPSTREAM_TOKEN_ENV} at "
                "import time. Verified by assert_no_token_in_output, not "
                "asserted."
            ),
            "fill_property_at_import": {
                "property": UPSTREAM_TOKEN_PROPERTY,
                "from_env": UPSTREAM_TOKEN_ENV,
            },
        },
        "api": api,
        "plans": [{
            "name": "plan-ai-gateway",
            "description": (
                "KEY_LESS for the prototype. NOTE: with KEY_LESS the "
                "class E rate limit keys on the Authorization header, "
                "which this route REPLACES with the gateway's own -- so "
                "every consumer shares one bucket. policy-classes.yaml's "
                "key_note describes the per-credential problem; "
                "injection makes it a per-GATEWAY problem, which is "
                "worse and is not what §2.3's per-consumer limits mean. "
                "Recorded as AI-1."
            ),
            "security": {"type": "KEY_LESS"},
            # REQUIRED. Its absence is what produced, on the first import
            # attempt, "Validation error / must not be null / location:
            # createApiPlan.createPlan" -- a message that names the
            # wrapper rather than the missing field, so it reads like the
            # whole plan object was null when in fact one key was.
            # scripts/29's plans have always carried it; this generator
            # omitted it because I wrote the plan body from the API docs
            # instead of from the definition in this repo that already
            # imports. Third instance today of restating instead of
            # importing (AI-6's pattern).
            "definitionVersion": "V4",
            "validation": "AUTO",
            "mode": "STANDARD",
            # `"status": "PUBLISHED"` was here and has been REMOVED.
            # Publishing is a separate management call
            # (POST .../plans/{id}/_publish), which scripts/05 makes and
            # whose status code it prints. A status declared in the CREATE
            # body is at best ignored; at worst it describes the plan as
            # published in the artifact while the publish call is what
            # actually decides, and then a failed publish leaves a
            # definition on disk that claims otherwise. The artifact
            # should state what it asks for, not assert the outcome.
            # B-19: recorded here rather than deleted silently.
            "_rationale": {
                "status_field_removed_2026_10_21": (
                    "Declared PUBLISHED in the create body. Publishing is "
                    "a separate call; the field made the artifact assert "
                    "an outcome it does not control."
                ),
            },
        }],
        "_not_built": not_built,
        "_known_incomplete": [
            {
                "id": "AI-1",
                "what": "Rate limiting cannot be per-consumer on this route.",
                "why": (
                    "Class E keys the limiter on the Authorization header "
                    "and this route replaces that header with the "
                    "gateway's single upstream identity, so all callers "
                    "share one bucket. Per-consumer limits need an "
                    "API-key or JWT plan, which the prototype does not "
                    "have."
                ),
                "conops": "2.3 per-consumer limits; AC2",
            },
            {
                "id": "AI-2",
                "what": "R12b is unbuilt and untested.",
                "why": (
                    "The gateway holds a long-lived credential. §3.2's "
                    "shape needs an OAuth client-credentials exchange or "
                    "workload identity federation so the gateway holds "
                    "nothing durable. That is a separate build and a "
                    "separate test, and it is the half OD-4 cares about."
                ),
                "conops": "3.2; OD-4",
            },
            {
                "id": "AI-3",
                "what": "The credential is the wrong TYPE, not just the wrong scope.",
                "why": (
                    "A PAT bound to a human operator carries that "
                    "human's full entitlements. §3.2's least-privilege "
                    "claim rests on a service principal granted only one "
                    "consumer's assets. Nothing in this build "
                    "demonstrates least privilege, and a green T-15 "
                    "must not be cited for it."
                ),
                "conops": "3.2; AC4",
            },
            {
                "id": "AI-4",
                "what": "M3's deny policy id and fields are unverified.",
                "status": "CLOSED BY MEASUREMENT 2026-10-21 -- it was real.",
                "why": (
                    "Unlike policy-classes.yaml's policies, "
                    "policy-request-validation was not checked against "
                    "this installation's schema endpoints. If it fails "
                    "to load, the flow FORWARDS instead of refusing -- "
                    "the dangerous direction -- and the upstream 404 "
                    "would look like a successful block."
                ),
                "outcome": (
                    "B-19, kept in place. The risk above materialised, "
                    "and not by the mechanism it predicted: the policy "
                    "LOADED and forwarded anyway, because "
                    "policy-request-validation validates each rule in "
                    "turn and an empty `rules` list has nothing to fail. "
                    "T-16 returned "
                    "DENY_DOES_NOT_FIRE_THE_EDGE_FORWARDED_THE_REQUEST. "
                    "The deny is now a `mock` policy whose fields were "
                    "read from this installation's schema endpoint, and "
                    "enforcement has moved to the terminal allow-list so "
                    "a future failure of this policy falls closed."
                ),
                "what_caught_it": (
                    "Not the policy and not the gate. The TEST, because "
                    "it required Gravitee's own vocabulary instead of "
                    "accepting any 4xx. An assertion of `status in (401, "
                    "403)` would have passed on the upstream's forwarded "
                    "401 and this flow would have shipped as a working "
                    "deny. Worth carrying into v1.6 as a rule about "
                    "tests, not about policies."
                ),
                "tests": ["T-16"],
            },
            {
                "id": "AI-7",
                "what": (
                    "The AI route was an open reverse proxy to the whole "
                    "Databricks workspace REST API. Fixed on this route; "
                    "the same hole is open on every other API."
                ),
                "why": (
                    "Gravitee prefix-matches the context path and "
                    "FORWARDS any path that matches no flow selector. "
                    "This API's target must be the workspace root, so "
                    "the forwarded path landed on the real REST API. "
                    "Measured with a valid caller token: "
                    "/ai-gateway-demo/api/2.0/token/list -> 200, "
                    "clusters/list -> 200, serving-endpoints -> 200 -- "
                    "and as the gateway's INJECTED identity, not the "
                    "caller's, since this route replaces the caller's "
                    "Authorization. R12a's mechanism is what made the "
                    "hole worth using."
                ),
                "fix_on_this_route": (
                    "A terminal resource-filtering whitelist derived "
                    "from the forwarding flows' own selectors, last in "
                    "the flow array. Verified live before being "
                    "generated."
                ),
                "still_open": (
                    "scripts/29's APIs have no equivalent. They are "
                    "confined only because their endpoint target carries "
                    "a deep base path, so a stray path appends and the "
                    "upstream 404s -- confinement by URL concatenation, "
                    "not by a control, and one target edit from being "
                    "gone. No test asserts it."
                ),
                "conops": "2.3.2; AC1; AC2",
                "baseline": "B-48",
                "status": "OPEN for the estate -- v1.6 input",
                "tests": ["T-16"],
            },
            {
                "id": "AI-8",
                "what": (
                    "§2.3.2's route table was a documentation allow-list "
                    "that nothing enforced."
                ),
                "why": (
                    "The table reads as the definitive statement of what "
                    "each channel exposes, and every generator consumes "
                    "it, but what the generators emitted were selectors "
                    "that MATCH listed paths -- never a rule that "
                    "refuses unlisted ones. A row absent from the table "
                    "was therefore not absent from the gateway. "
                    "scripts/29's build_catch_all asserted the opposite "
                    "('an unmatched path fails closed because nothing "
                    "matches it'); that claim is retracted in place in "
                    "that file."
                ),
                "conops": "2.3.2",
                "baseline": "B-48",
                "status": "OPEN -- v1.6 must say which document is the "
                          "enforced boundary and which merely describes it",
                "tests": ["T-16"],
            },
            {
                "id": "AI-9",
                "what": (
                    "M3's refusal reason does not reach the caller, only "
                    "the artifact."
                ),
                "why": (
                    "Gravitee evaluates flows most-generic-selector "
                    "first, so the terminal allow-list's '/' flow is "
                    "reached before M3's '/api/2.0/mcp' flow regardless "
                    "of array position (measured; the previous "
                    "must_be_last reasoning assumed the opposite). The "
                    "caller therefore gets the allow-list's anonymous "
                    "403. M3's mock is proven to work -- disable the "
                    "allow-list and the marker appears -- and stays "
                    "enabled as the fail-closed backstop."
                ),
                "decision": (
                    "Accepted. The stated requirement is "
                    "carry_reason_into_generated_artifact, and the "
                    "artifact carries it. The alternative is "
                    "whitelisting /api/2.0/mcp so M3 can answer, which "
                    "trades a fail-closed perimeter for a legible "
                    "message and forwards legacy MCP to the real "
                    "upstream the moment M3 is disabled."
                ),
                "conops": "2.3.2 row M3",
                "status": "ACCEPTED TRADE-OFF -- v1.6 should state it",
                "tests": ["T-16"],
            },
            {
                "id": "AI-10",
                "what": (
                    "A step-level `condition` silently OMITS the policy "
                    "when it does not evaluate true. Do not use one on a "
                    "deny."
                ),
                "why": (
                    "Measured 2026-10-21. The condition "
                    "{!#request.path.contains('/api/2.0/mcp')} was added "
                    "to the allow-list step to let M3's path through to "
                    "M3's mock. PUT 200, deployment 202, no warning "
                    "anywhere -- and /api/2.0/token/list then returned "
                    "200. The expression evaluated false on every path, "
                    "and an unmet condition does not refuse the request, "
                    "it skips the policy. So an EL expression nobody can "
                    "verify is a silent off-switch on a default-deny "
                    "control."
                ),
                "rule": (
                    "No `condition` on any step whose absence fails "
                    "open. If one is ever needed, the test that proves "
                    "the policy fires must run in the same change, "
                    "because nothing in the management plane reports an "
                    "expression that never matches."
                ),
                "baseline": "B-47, B-48",
                "status": "RULE RECORDED -- no condition is generated",
                "tests": ["T-16"],
            },
            {
                "id": "AI-5",
                "what": "M2 is not generated.",
                "why": (
                    "methods_unconfirmed. §2.3.2 gives 'MCP' as the "
                    "method. A POST-only selector drops the "
                    "streamable-HTTP event stream silently."
                ),
                "open_decision": "OD-8",
                "tests": ["T-16"],
            },
            {
                "id": "AI-6",
                "what": (
                    "The policy-classes.yaml readers are duplicated "
                    "between scripts/29 and scripts/30, and the copies "
                    "disagreed."
                ),
                "why": (
                    "Both filenames start with a digit, so neither module "
                    "is importable by name; the second generator restated "
                    "the schema rather than importing the reader. The "
                    "restatement looked for a 'policies' key one level "
                    "deeper than the file has, caught 2026-10-21 on first "
                    "run. B-39 with my name on it."
                ),
                "why_it_mattered": (
                    "It crashed only because a list has no .get. A dict "
                    "without the expected key would have returned an EMPTY "
                    "policy set via `or []`, emitting the one "
                    "credential-injecting route in the estate with no "
                    "common controls -- and it would have imported, "
                    "started and answered 200."
                ),
                "mitigation": (
                    "Empty is now a hard error in both readers in this "
                    "script, so the silent-empty path no longer exists "
                    "here. The duplication itself remains."
                ),
                "durable_fix": (
                    "Move the policy-classes readers into an importable "
                    "module (scripts/lib/policy_classes.py) and have 29 "
                    "and 30 both import it. Not done today: it touches a "
                    "generator whose output T-01 and T-03 currently "
                    "depend on, and the gates are green."
                ),
                "status": "OPEN -- v1.6 input",
                "tests": [],
            },
        ],
    }

    out_path = OUT_DIR / "api-m1-ai-gateway.json"
    blob = json.dumps(doc, indent=2)
    findings, n_secrets = assert_no_token_in_output({out_path.name: blob})
    if findings:
        print("\nSECRET CHECK FAILED:")
        for f in findings:
            print(f"  {f}")
        sys.exit("Refusing to write.")
    print(f"\nsecret check:  clean ({n_secrets} env secrets compared, "
          "0 reached the output)")

    if args.check:
        print("\n--check: nothing written")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(blob)
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "generated_at": now(),
        "artifact": str(out_path.relative_to(ROOT)),
        "context_path": AI_CONTEXT_PATH,
        "approved_model": APPROVED_MODEL,
        "flows": [f["name"] for f in api["flows"]],
        "not_built": not_built,
        "known_incomplete": doc["_known_incomplete"],
        "r12_split": {
            "R12a": "BUILT -- injection by property reference",
            "R12b": "NOT BUILT -- the gateway holds a long-lived secret",
            "credential_type": (
                "PERSONAL ACCESS TOKEN, not a service principal OAuth "
                "token. §3.2 not demonstrated."
            ),
        },
        "verdict": "AI_ROUTE_GENERATED_R12A_ONLY",
    }, indent=2))

    print(f"wrote:         {out_path.relative_to(ROOT)}")
    print(f"wrote evidence: {EVIDENCE.relative_to(ROOT)}")
    ids = ", ".join(i["id"] for i in doc["_known_incomplete"])
    print(f"\nknown incomplete: {len(doc['_known_incomplete'])} items "
          f"recorded ({ids})")
    print("VERDICT: AI_ROUTE_GENERATED_R12A_ONLY")
    print("\nNext: python3 scripts/05_import_gravitee_api.py "
          "--definition gravitee/generated/api-m1-ai-gateway.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
