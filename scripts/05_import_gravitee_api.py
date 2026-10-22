#!/usr/bin/env python3
"""
T-12 material: "redeploy the configuration from code to a clean target ->
same configuration, no manual steps." This script is that redeploy path --
it is what Infrastructure-as-Code / Configuration-as-Code (1227-E6, AC6)
looks like for Gravitee in this demo.

It substitutes <DATABRICKS_HOST> and <STORAGE_HOST> in
gravitee/api-definition.json from your .env, then creates/starts the API
and its plan against the local Gravitee Management API.

This targets Gravitee APIM 4.12.23's actual REST shape, confirmed
empirically against a running instance (see README for how that was
verified): API definitions are created via
  POST /management/v2/organizations/{org}/environments/{env}/apis
with listeners/endpointGroups/flows embedded directly in the body --
NOT via the older /management/organizations/.../apis/_import endpoint,
which only understands the legacy V2 gateway definition shape. Plans are
created and published as separate calls, not embedded in the API body.

Run this any time you `docker compose down -v && docker compose up -d`
to prove the environment is reproducible from code (T-12), not manually
clicked together in the Console.
"""
import json
import argparse
import os
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------
# 2026-10-21: --definition / --all added for the generated route family.
#
# This script used to import exactly one hand-maintained file,
# gravitee/api-definition.json. That file is now SUPERSEDED (carried
# forward, not deleted -- B-19): its upstream target was wrong in both
# the host and the path, which is why no read ever succeeded through the
# gateway. The replacement is a generated family, one definition per
# recipient, because the sharing host is per-recipient and the platform
# validates the host/token binding (docs/11 B-42, docs/10 D-9).
#
# The import MECHANISM below is unchanged and deliberately so. It is the
# half that was verified empirically against APIM 4.12.23, and it is the
# T-12 redeploy path. Only the choice of which file to feed it is new.
# ---------------------------------------------------------------------
GENERATED_DIR = Path(__file__).resolve().parent.parent / "gravitee" / "generated"


def strip_rationale(node):
    """The generated definitions carry documentation siblings --
    `_rationale`, `_provenance`, `_generated`, `_not_built` -- so a
    reader of the deployed artifact can see WHY a policy is disabled
    without opening four config files. Gravitee ignores unknown keys in
    some versions and rejects them in others, and "sometimes ignored" is
    not a property worth deploying on, so they are stripped here rather
    than omitted from the generator. The file on disk stays explanatory;
    the body on the wire stays minimal."""
    if isinstance(node, dict):
        return {k: strip_rationale(v) for k, v in node.items()
                if not k.startswith("_")}
    if isinstance(node, list):
        return [strip_rationale(v) for v in node]
    return node

def context_paths(api_body):
    """Every context path this definition will try to claim."""
    out = []
    for lis in api_body.get("listeners", []):
        for p in lis.get("paths", []):
            if p.get("path"):
                out.append(p["path"])
    return out


def norm(p):
    return "/" + (p or "").strip("/")


def preflight_collisions(session, base, api_body):
    """A Gravitee context path is a PREFIX, not an exact match.

    This check exists because its absence cost a run. The 2026-10-21
    import of the route family silently placed only 1 of 4 APIs: the
    three /opensharing-demo/<slug> listeners collided with a
    pre-existing API at /opensharing-demo/, and /storage-proxy/ went in
    because it was the one path with no collision. The import reported
    per-API failures, but nothing said WHY, so the diagnosis came from
    reading the gateway by hand afterwards.

    Worse, the colliding API did not sit quietly: it prefix-matched the
    new paths and forwarded them upstream with the recipient slug glued
    into the protocol path. The resulting upstream 404s read exactly
    like gateway refusals (docs/11 B-44).

    So: look before importing, and name the blocker."""
    wanted = [norm(p) for p in context_paths(api_body)]
    if not wanted:
        return []
    try:
        resp = session.get(f"{base}/apis", params={"perPage": 200}, timeout=30)
        if resp.status_code != 200:
            return [{"check": "PREFLIGHT_CANNOT_SEE",
                     "detail": f"listing APIs returned {resp.status_code}"}]
        items = resp.json().get("data", [])
    except Exception as e:  # noqa: BLE001
        return [{"check": "PREFLIGHT_CANNOT_SEE", "detail": repr(e)}]

    hits = []
    for item in items:
        if item.get("name") == api_body.get("name"):
            continue  # same API; import_one already replaces it
        existing = [norm(p) for p in context_paths(item)]
        if not existing:
            detail = session.get(f"{base}/apis/{item['id']}", timeout=30)
            if detail.status_code == 200:
                existing = [norm(p) for p in context_paths(detail.json())]
        for e in existing:
            for w in wanted:
                if w == e or w.startswith(e + "/") or e.startswith(w + "/"):
                    hits.append({
                        "blocking_api": item.get("name"),
                        "blocking_api_id": item.get("id"),
                        "blocking_context_path": e,
                        "wanted_context_path": w,
                        "relation": ("IDENTICAL" if w == e else
                                     "EXISTING_IS_A_PREFIX_OF_WANTED"
                                     if w.startswith(e + "/") else
                                     "WANTED_IS_A_PREFIX_OF_EXISTING"),
                    })
    return hits


def retire_api(session, base, api_id, name):
    """Stop, close plans, delete -- in that order, because a published
    plan blocks the delete and a started API blocks the plan close."""
    print(f"    retiring blocking API '{name}' (id={api_id})")
    session.post(f"{base}/apis/{api_id}/_stop", timeout=30)
    plans = session.get(f"{base}/apis/{api_id}/plans", timeout=30)
    if plans.status_code == 200:
        body = plans.json()
        rows = body.get("data", body if isinstance(body, list) else [])
        for p in rows:
            session.post(f"{base}/apis/{api_id}/plans/{p['id']}/_close", timeout=30)
    time.sleep(1)
    d = session.delete(f"{base}/apis/{api_id}", timeout=30)
    print(f"      delete -> {d.status_code}")
    return d.status_code in (204, 200, 404)


def load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A blank value is an ABSENCE, not a value -- see docs/11
        # B-10b, where a placeholder `AWS_PROFILE=` in .env reached
        # botocore as a request for a profile named "".
        if not v.strip():
            continue
        os.environ.setdefault(k, v)

def fill_properties_from_env(api_body, gen):
    """Fill an API property's value from the environment, at import time.

    A definition that needs an upstream credential has two bad options and
    one good one. It can carry the secret literally, which puts it in git.
    It can carry nothing and have the policy fail at runtime, which looks
    exactly like the capability being impossible rather than the harness
    being incomplete -- the silent negative again. Or it can carry a
    property REFERENCE, ship the property empty, and have the import step
    fill it from the environment. That is this function.

    The contract is declared by the generator, not guessed here:
    `_generated.fill_property_at_import = {property, from_env}`. If the
    named environment variable is absent, this REFUSES the import rather
    than importing a route whose injected header resolves to "Bearer ".
    A route that fails for a missing secret and a route that fails because
    the gateway cannot inject are indistinguishable from the outside, and
    T-15 would read the second where the first is true.

    Returns a list of note dicts for the result record. The value itself is
    never printed, never returned, and never written back to def_path.
    """
    spec = (gen or {}).get("fill_property_at_import")
    if not spec:
        return []
    if isinstance(spec, dict):
        spec = [spec]
    notes = []
    props = api_body.get("properties")
    # Gravitee accepts either a bare list or {"properties": [...]}.
    plist = props.get("properties") if isinstance(props, dict) else props
    if not isinstance(plist, list):
        raise SystemExit(
            f"{def_path_name(api_body)}: _generated.fill_property_at_import "
            "names properties to fill, but the definition has no properties "
            "list. The generator and the importer disagree about the "
            "contract; fix the generator rather than skipping the fill.")
    for item in spec:
        key = item["property"]
        var = item["from_env"]
        val = os.environ.get(var, "").strip()
        if not val:
            raise SystemExit(
                f"Refusing to import: property '{key}' must be filled from "
                f"${var}, which is unset or empty in the environment. "
                "Importing anyway would stand up a route whose injected "
                "credential is the empty string -- it would fail, and the "
                "failure would look like the gateway being unable to inject "
                "rather than this secret being absent. Set the variable in "
                ".env and re-run.")
        target = next((p for p in plist if p.get("key") == key), None)
        if target is None:
            raise SystemExit(
                f"Refusing to import: property '{key}' is named by "
                f"fill_property_at_import but is not declared in the "
                "definition's properties. The policy reference would "
                "resolve to nothing.")
        if (target.get("value") or "").strip():
            raise SystemExit(
                f"Refusing to import: property '{key}' already carries a "
                "value ON DISK. The whole point of the reference is that "
                "the committed artifact holds no secret. Blank it in the "
                "generator before importing.")
        target["value"] = val
        notes.append({"property": key, "filled_from_env": var,
                      "value_length": len(val),
                      "stage": "SET_IN_THE_REQUEST_BODY",
                      "note": "Set on the object about to be POSTed. NOT "
                              "yet confirmed present on the server -- "
                              "confirm_properties_landed does that. The "
                              "value is not written back to the "
                              "definition file."})
        # Deliberately NOT the word "filled". See
        # confirm_properties_landed for what that word cost.
        print(f"    [PROPERTY] '{key}' set in the request body from ${var} "
              f"({len(val)} chars, value not shown) -- not yet confirmed "
              "on the server")
    return notes


def confirm_properties_landed(session, base, api_id, api_body, spec_notes):
    """Read the properties back off the server, and PUT them if the
    create call dropped them.

    MEASURED 2026-10-21. The create call (POST /apis) accepts a
    `properties` array, returns 201, and SILENTLY DISCARDS it. A
    read-back of the created API showed `properties: []`. A subsequent
    PUT of the full API object sets them and returns 200.

    The important part is not the API quirk. It is what this script
    printed while that was happening:

        [PROPERTY] 'databricks_upstream_token' filled from
        $DATABRICKS_TOKEN (36 chars, value not shown)

    A confident, specific, quantified success message about something
    that never reached the server. The word "filled" described an
    in-memory dict, and every reader -- including me -- took it as a
    statement about the gateway. The route then failed with
    "Unable to apply headers transformation", a 500 that names the
    policy and not the missing property, and the next hour could easily
    have gone into the policy.

    This is the silent negative inverted a third way: not a check that
    could not see, but a REPORT that described an intention as an
    outcome. So nothing here claims success before reading it back, and
    an unconfirmed property is a hard refusal rather than a warning --
    a route whose injected credential is absent answers 500 or 401, and
    both read as the capability being impossible rather than the import
    being incomplete.
    """
    if not spec_notes:
        return []
    want = {n["property"]: n["value_length"] for n in spec_notes}
    out = []

    def read_back():
        r = session.get(f"{base}/apis/{api_id}", timeout=30)
        if r.status_code != 200:
            return None, r
        full = r.json()
        props = full.get("properties")
        plist = props.get("properties") if isinstance(props, dict) else props
        return (full, {p.get("key"): p.get("value") or ""
                       for p in (plist or [])})

    full, live = read_back()
    if live is None:
        raise SystemExit(f"Could not read back API {api_id} to confirm "
                         "its properties.")

    missing = [k for k, n in want.items() if len(live.get(k, "")) != n]
    if missing:
        print(f"    [PROPERTY] create did NOT persist {missing} "
              "(server reports them absent or truncated). Setting them "
              "with a PUT and re-reading.")
        full["properties"] = [
            {"key": p["key"], "value": p["value"],
             "encrypted": p.get("encrypted", False),
             "dynamic": p.get("dynamic", False)}
            for p in api_body_properties(api_body)]
        put = session.put(f"{base}/apis/{api_id}", json=full, timeout=60)
        if put.status_code not in (200, 201):
            raise SystemExit(
                f"Refusing to continue: PUT of properties returned "
                f"{put.status_code}: {put.text[:400]}. The route would "
                "start with an empty credential property and answer 500 "
                "or 401, which reads as the gateway being unable to "
                "inject rather than as this import being incomplete.")
        full, live = read_back()
        missing = [k for k, n in want.items() if len(live.get(k, "")) != n]
        if missing:
            raise SystemExit(
                f"Refusing to continue: properties {missing} are STILL "
                "not present on the server after a successful PUT. Do "
                "not start this API; its credential property is empty.")
        method = "PUT_AFTER_CREATE_DROPPED_THEM"
    else:
        method = "PERSISTED_BY_CREATE"

    for k, n in want.items():
        print(f"    [PROPERTY] '{k}' CONFIRMED on the server "
              f"({len(live[k])} chars) via {method}")
        out.append({"property": k, "confirmed_length": len(live[k]),
                    "expected_length": n, "how": method,
                    "verified_by": "read-back of GET /apis/{id}"})
    return out


def api_body_properties(api_body):
    props = api_body.get("properties")
    plist = props.get("properties") if isinstance(props, dict) else props
    return plist or []


def def_path_name(api_body):
    return api_body.get("name", "<unnamed API>")


def import_one(session, base, def_path, databricks_host, retire_colliding=False):
    raw = def_path.read_text()
    raw = raw.replace("<DATABRICKS_HOST>", databricks_host)
    raw = raw.replace("<STORAGE_HOST>", os.environ.get("STORAGE_HOST", "s3.amazonaws.com"))
    doc = json.loads(raw)
    api_body = strip_rationale(doc["api"])
    plans = strip_rationale(doc.get("plans", []))

    gen = doc.get("_generated")
    if gen:
        print(f"\n--- {def_path.name}")
        print(f"    generated {gen.get('at')} for {gen.get('recipient') or gen.get('route')}")
        print(f"    edge path {gen.get('edge_path')}  ->  upstream {gen.get('upstream_host') or gen.get('upstream')}")
    not_built = doc.get("_not_built") or []
    for nb in not_built:
        # Read under either vocabulary, and if neither is present say so
        # rather than printing None. Hardened 2026-10-21: this line
        # printed "[NOT BUILT] None: None" for a definition that used
        # different key names, which is a warning with its subject and
        # its reason both removed. On that definition the unbuilt item
        # was M2 -- an open decision (OD-8). A warning that cannot name
        # what is missing is indistinguishable from no warning, and this
        # one survived a 400 and a start failure on the same screen.
        ident = nb.get("route_id") or nb.get("id")
        reason = nb.get("warning") or nb.get("reason")
        if not ident or not reason:
            print(f"    [NOT BUILT] <this definition's _not_built entry "
                  f"uses keys this importer does not read: "
                  f"{sorted(nb.keys())}>  raw={json.dumps(nb)[:300]}")
        else:
            print(f"    [NOT BUILT] {ident}: {reason}")

    # Fill any declared property from the environment BEFORE the POST, and
    # refuse the import if the source variable is missing. See the
    # function's docstring for why refusing beats importing-and-failing.
    filled = fill_properties_from_env(api_body, gen)

    # If an API with this name already exists (e.g. from a prior run), stop,
    # close its plans, and delete it first so this script is idempotent --
    # that's the T-12 "clean target, same result" property.
    existing = session.get(f"{base}/apis", params={"q": api_body["name"]}, timeout=30)
    if existing.status_code == 200:
        for item in existing.json().get("data", []):
            if item.get("name") == api_body["name"]:
                old_id = item["id"]
                print(f"Found existing API '{api_body['name']}' (id={old_id}) -- removing it first.")
                session.post(f"{base}/apis/{old_id}/_stop", timeout=30)
                old_plans = session.get(f"{base}/apis/{old_id}/plans", timeout=30)
                if old_plans.status_code == 200:
                    for p in old_plans.json().get("data", old_plans.json() if isinstance(old_plans.json(), list) else []):
                        session.post(f"{base}/apis/{old_id}/plans/{p['id']}/_close", timeout=30)
                time.sleep(1)
                d = session.delete(f"{base}/apis/{old_id}", timeout=30)
                if d.status_code not in (204, 404):
                    print(f"  warning: delete of old API returned {d.status_code}: {d.text[:300]}")

    # Look before importing. See preflight_collisions' docstring for why
    # this is here rather than left to the error message.
    collisions = preflight_collisions(session, base, api_body)
    blocking = [c for c in collisions if c.get("blocking_api_id")]
    if blocking:
        for c in blocking:
            print(f"    [COLLISION] '{c['wanted_context_path']}' vs "
                  f"'{c['blocking_context_path']}' held by "
                  f"'{c['blocking_api']}' ({c['relation']})")
        if retire_colliding:
            for api_id in sorted({c["blocking_api_id"] for c in blocking}):
                name = next(c["blocking_api"] for c in blocking
                            if c["blocking_api_id"] == api_id)
                retire_api(session, base, api_id, name)
            collisions = preflight_collisions(session, base, api_body)
            blocking = [c for c in collisions if c.get("blocking_api_id")]
        if blocking:
            print("    Refusing to import: a context path is a PREFIX in "
                  "Gravitee, so this definition cannot claim its path "
                  "while the API above holds it. Re-run with "
                  "--retire-colliding to stop, close and delete the "
                  "blocker first.")
            return {"definition": def_path.name, "result": "BLOCKED_BY_COLLISION",
                    "collisions": blocking}

    resp = session.post(f"{base}/apis", json=api_body, timeout=30)
    if resp.status_code not in (200, 201):
        print(resp.status_code, resp.text[:1200])
        return {"definition": def_path.name, "result": "API_CREATION_FAILED",
                "status": resp.status_code, "detail": resp.text[:600]}

    api = resp.json()
    api_id = api["id"]
    print(f"    Created API '{api.get('name')}' (id={api_id})")

    # Confirm the credential property actually reached the server, and
    # PUT it if create dropped it. Before _start, because starting an
    # API whose injected credential is empty produces a 500 or a 401
    # that reads as the capability being impossible.
    confirmed = confirm_properties_landed(session, base, api_id,
                                          api_body, filled)
    for note in filled:
        note["stage"] = "SUPERSEDED_BY_CONFIRMATION"

    plan_results = []
    for plan in plans:
        plan_resp = session.post(f"{base}/apis/{api_id}/plans", json=plan, timeout=30)
        if plan_resp.status_code not in (200, 201):
            print(plan_resp.status_code, plan_resp.text[:600])
            plan_results.append({"plan": plan.get("name"), "result": "PLAN_CREATION_FAILED",
                                 "status": plan_resp.status_code})
            continue
        plan_obj = plan_resp.json()
        plan_id = plan_obj["id"]
        pub = session.post(f"{base}/apis/{api_id}/plans/{plan_id}/_publish", timeout=30)
        print(f"    Created + published plan '{plan.get('name')}' (publish={pub.status_code})")
        plan_results.append({"plan": plan.get("name"), "result": "PUBLISHED",
                             "publish_status": pub.status_code})

    # Do not start an API whose plans did not all get created and
    # published. Added 2026-10-21 after the AI route's plan failed
    # validation (400) and this script went on to call _start anyway.
    #
    # Here the start also failed, so nothing was exposed -- but that was
    # Gravitee refusing to start a planless API, not this script
    # declining to ask. The dangerous shape is an API with SEVERAL plans
    # where one fails: the others exist, the API starts, the result reads
    # IMPORTED, and the route is live with part of its access control
    # missing. Nothing downstream would notice, because every test in
    # this repo asks what a route DOES, and a route missing one plan
    # still answers.
    failed_plans = [p for p in plan_results if p["result"] != "PUBLISHED"]
    if failed_plans:
        print(f"    Refusing to start: {len(failed_plans)} of "
              f"{len(plan_results)} plans did not publish "
              f"({', '.join(str(p.get('plan')) for p in failed_plans)}). "
              "An API that starts with part of its plan set missing is "
              "live with part of its access control absent, and it would "
              "report success. Fix the plan body and re-import; this "
              "script removes the half-built API by name on the next run.")
        return {"definition": def_path.name,
                "result": "PLAN_FAILED_NOT_STARTED",
                "api_id": api_id, "api_name": api.get("name"),
                "plans": plan_results,
                "left_behind": (
                    "The API object was created and is NOT started. It "
                    "will be stopped, closed and deleted by name on the "
                    "next import of this definition."),
                "edge_path": (doc.get("_generated") or {}).get("edge_path"),
                "not_built": not_built,
                "properties_requested": filled,
                "properties_confirmed": confirmed}

    start = session.post(f"{base}/apis/{api_id}/_start", timeout=30)
    print(f"    Start response: {start.status_code}")

    # A definition changed by PUT after create needs an explicit
    # deployment before the GATEWAY sees it; _start publishes the API
    # but does not by itself redeploy a definition edited afterwards.
    # Measured 2026-10-21: the property was present via the management
    # API while the edge was still answering 500 from the previous
    # deployment -- the management plane and the data plane disagreed,
    # and only the management plane was being read.
    deploy_status = None
    if confirmed:
        dep = session.post(f"{base}/apis/{api_id}/deployments",
                           json={"deploymentLabel":
                                 "property fill at import"}, timeout=60)
        deploy_status = dep.status_code
        print(f"    Deployment after property fill: {deploy_status}")
        if deploy_status not in (200, 201, 202):
            print("    WARNING: the deployment call did not succeed. The "
                  "management API may report the property while the "
                  "gateway still runs the previous definition. Any test "
                  "run now measures the OLD deployment.")
    return {
        "definition": def_path.name,
        "result": "IMPORTED" if start.status_code in (200, 204) else "IMPORTED_NOT_STARTED",
        "api_id": api_id,
        "api_name": api.get("name"),
        "start_status": start.status_code,
        "plans": plan_results,
        "edge_path": (doc.get("_generated") or {}).get("edge_path"),
        "not_built": not_built,
        "properties_requested": filled,
        "properties_confirmed": confirmed,
        "deployment_after_property_fill": deploy_status,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--definition", help="path to one definition file")
    ap.add_argument("--all", action="store_true",
                    help="import every gravitee/generated/api-*.json (the route family)")
    ap.add_argument("--legacy", action="store_true",
                    help="import the SUPERSEDED gravitee/api-definition.json. Kept so the "
                         "old route can be stood back up for comparison; its target is "
                         "wrong in both host and path, so a read through it will fail")
    ap.add_argument("--retire-colliding", action="store_true",
                    help="stop, close plans and DELETE any existing API whose "
                         "context path collides (prefix-wise) with one this "
                         "import needs. Required to replace the legacy "
                         "/opensharing-demo/ API, which blocks the family")
    args = ap.parse_args()

    load_env()
    base_root = os.environ.get("GRAVITEE_MGMT_API_URL", "http://localhost:8083")
    user = os.environ.get("GRAVITEE_MGMT_USER", "admin")
    pwd = os.environ.get("GRAVITEE_MGMT_PASSWORD", "admin")
    databricks_host = os.environ["DATABRICKS_HOST"].replace("https://", "").replace("http://", "")

    repo = Path(__file__).resolve().parent.parent
    if args.definition:
        targets = [Path(args.definition)]
        if not targets[0].is_absolute():
            targets = [repo / args.definition]
    elif args.all:
        targets = sorted(GENERATED_DIR.glob("api-*.json"))
        if not targets:
            sys.exit("No generated definitions found. Run "
                     "scripts/29_gen_gravitee_route_family.py first.")
    elif args.legacy:
        targets = [repo / "gravitee" / "api-definition.json"]
    else:
        # No default. The old default was gravitee/api-definition.json,
        # whose target is wrong in both host and path -- importing it by
        # accident stands up a route that cannot work and looks like it
        # should, which is exactly the kind of silent wrong answer this
        # repository keeps finding. Make the caller choose.
        sys.exit("Choose one: --all (the generated route family), "
                 "--definition <path>, or --legacy (the superseded "
                 "single definition, kept for comparison only).")

    for t in targets:
        if not t.exists():
            sys.exit(f"Definition not found: {t}")

    base = f"{base_root}/management/v2/organizations/DEFAULT/environments/DEFAULT"
    session = requests.Session()
    session.auth = (user, pwd)

    results = [import_one(session, base, t, databricks_host,
                          retire_colliding=args.retire_colliding)
               for t in targets]

    print("\n" + "=" * 60)
    ok = [r for r in results if r["result"] == "IMPORTED"]
    print(f"{len(ok)}/{len(results)} definitions imported and started")
    for r in results:
        print(f"  [{r['result']}] {r['definition']}"
              + (f"  edge {r['edge_path']}" if r.get("edge_path") else ""))
    print("\nConsole: http://localhost:8084   Developer portal: http://localhost:8085")
    print("Next: python3 tests/t01_gateway_read.py")
    if len(ok) != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
