#!/usr/bin/env python3
"""
E1 Task 1.4 -- apply the view-based entitlement model, then verify it.

Reads iac/config/entitlements.yaml, which is the only definition of the
model. Creates the views, corrects the share §11.5 found carrying the
BASE TABLE, and then checks five rules against what the platform
actually holds.

WHY THE VERIFY HALF IS LONGER THAN THE APPLY HALF
-------------------------------------------------
B-23: a 200 on a mutation is not the finding; the re-read is. Every
statement below is issued and then its effect is read back out of
`information_schema` or the sharing API. The DDL this script typed is
not evidence of what the metastore holds -- a view created from this
file and replaced by hand afterwards would still be in the share.

THE DEFECT THIS TASK CLOSES
---------------------------
§11.5: `scripts/02_create_share.py` has a docstring claiming it
withholds `internal_notes`. It does not -- it adds the base TABLE, and
`internal_notes` is a column on it. So T-04 ("request a column outside
the grant -> denied") was requesting a column INSIDE the grant and
proving nothing. The view pattern makes the column absent rather than
masked, because §11.4 measured that masks and row filters are refused
outright on any OpenSharing-shared table, at every tier.

RULE 1 IS DELIBERATELY WIDER THAN THIS FILE
-------------------------------------------
The base-table check runs across EVERY share on the metastore, not just
the two defined here. §11.5's defect was a share nobody looked at; a
check scoped to the file's own shares would have passed all the way
through it. And if the share list cannot be read, the result is
CANNOT_SEE -- never PASS. §12.9: a check that could not look must not
produce the output of a check that looked and found nothing.

Usage:
    python3 scripts/24_build_entitlement_model.py --dry-run
    python3 scripts/24_build_entitlement_model.py
    python3 scripts/24_build_entitlement_model.py --allow-base-drift
"""

import argparse
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "iac" / "config" / "entitlements.yaml"
EVIDENCE = REPO / "evidence" / "entitlement-model.json"
UC = "/api/2.1/unity-catalog"


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this script reuses its helpers rather "
                 f"than restating them.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "t24_probe14")
P19 = load_probe("19_probe_token_path_same_pair.py", "t24_probe19")

call = P14.call
redact = P14.redact
err_bits = P14.err_bits
load_env = P19.load_env
find_warehouse = P19.find_warehouse
run_sql = P19.run_sql


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def run_sql_full(host, token, warehouse_id, statement, error_budget=2000):
    """run_sql with a bigger error budget, and nothing else different.

    scripts/19's run_sql truncates the error at 400 characters. That was
    fine for the probe it was written for and lost something here: the
    platform refused `CREATE OR REPLACE VIEW` on a shared view with

      ... If you just want to update a shared view, please use

    and the sentence naming the remedy was cut off mid-clause. The
    platform told us how to fix it and the evidence file kept only the
    half that says no. scripts/19 is a settled probe and is not edited
    for this; the wrapper lives here instead.
    """
    status, payload = call(
        host, token, "/api/2.0/sql/statements", "POST",
        {"statement": statement, "warehouse_id": warehouse_id,
         "wait_timeout": "50s", "on_wait_timeout": "CANCEL"})
    st = ((payload or {}).get("status") or {})
    state = (st.get("state") or "").upper()
    if status != 200 or state != "SUCCEEDED":
        return None, {
            "http_status": status,
            "state": state or None,
            # B-27: a denied or refused statement returns HTTP 200 with
            # state FAILED. Anything keyed on the status code grades
            # this as a success.
            "error": redact(json.dumps(st.get("error") or {}))[:error_budget],
        }
    return ((payload.get("result") or {}).get("data_array") or []), {
        "http_status": status, "state": state}


def normalise_sql(text):
    """Collapse whitespace and drop backticks so two spellings of the
    same definition compare equal. Case is NOT folded: `'us-east'` and
    `'US-EAST'` are different predicates and must not compare equal."""
    if not isinstance(text, str):
        return ""
    return " ".join(text.replace("`", "").split()).rstrip(";").strip()


def view_exists(host, token, wh, catalog, schema, vid):
    """True, False, or None for 'could not look' -- which is not False.
    The apply strategy branches on this, so a failed look that returned
    False would issue a CREATE against an existing shared view and the
    refusal would be reported as a create failure."""
    rows, _ = run_sql_full(
        host, token, wh,
        f"SELECT 1 FROM {catalog}.information_schema.views "
        f"WHERE table_schema = {sql_lit(schema)} "
        f"AND table_name = {sql_lit(vid)}")
    if rows is None:
        return None
    return bool(rows)


def sql_lit(text):
    """Single-quoted SQL literal. A DSA reference or a purpose string
    with an apostrophe in it would otherwise end the literal early and
    the COMMENT would be silently truncated -- or the statement would
    fail in a way that looks like a permissions problem."""
    return "'" + str(text).replace("\\", "\\\\").replace("'", "''") + "'"


# =====================================================================
# Pre-apply guards. These run BEFORE anything touches the platform,
# because a bad edit to the config should fail at the edit, not after a
# recipient has read the result.
# =====================================================================

def pre_apply_guards(cfg):
    """EI-2 and EI-5. Returns a list of refusals; empty means proceed."""
    refusals = []
    withheld = set()
    declared = {}
    for t in cfg.get("base_tables") or []:
        cols = t.get("columns") or []
        declared[t["name"]] = [c["name"] for c in cols]
        withheld |= {c["name"] for c in cols if not c.get("entitled")}

    for v in cfg.get("views") or []:
        sel = v.get("select") or []
        if not sel:
            refusals.append(f"{v['id']}: empty select list. A view with no "
                            f"columns is not a narrower grant, it is a "
                            f"broken object.")
        for col in sel:
            if "*" in str(col):
                refusals.append(
                    f"{v['id']}: select entry {col!r} contains '*'. EI-2 "
                    f"forbids it: a view defined by subtraction fails OPEN "
                    f"when the base table gains a column.")
            if col in withheld:
                refusals.append(
                    f"{v['id']}: select list contains withheld column "
                    f"{col!r}. EI-5. This is the §11.5 defect written into "
                    f"config instead of code.")
        base = v.get("base_table")
        known = declared.get(base)
        if known is None:
            refusals.append(f"{v['id']}: base_table {base!r} is not declared "
                            f"in base_tables, so its columns cannot be "
                            f"checked against anything.")
        else:
            unknown = [c for c in sel if c not in known]
            if unknown:
                refusals.append(
                    f"{v['id']}: select list names column(s) {unknown} that "
                    f"are not declared on {base}. Either the file is stale "
                    f"or the column does not exist; both produce a view "
                    f"that fails to create, and the failure would be read "
                    f"as a permissions problem.")
        if v.get("excludes") and set(v["excludes"]) & set(sel):
            refusals.append(f"{v['id']}: a column appears in both select and "
                            f"excludes. The file contradicts itself.")

    # A share must carry views only, and every object it names must exist
    # in this file. An object named here but defined nowhere would be
    # added to the share by name and 404 at read time.
    view_ids = {v["id"] for v in cfg.get("views") or []}
    for sh in cfg.get("shares") or []:
        for obj in sh.get("objects") or []:
            if obj not in view_ids:
                refusals.append(f"share {sh['name']}: object {obj!r} is not a "
                                f"view defined in this file.")
        if not sh.get("objects"):
            refusals.append(f"share {sh['name']}: no objects. An empty share "
                            f"grants nothing and reads as a provisioning "
                            f"failure on the consumer side.")
    return refusals


# =====================================================================
# Base-table drift. A column added to the base table since this file was
# written is the exact case the explicit select list exists to contain,
# so it is reported loudly rather than tolerated quietly.
# =====================================================================

def base_table_drift(host, token, wh, catalog, schema, cfg):
    out = {}
    for t in cfg.get("base_tables") or []:
        name = t["name"]
        declared = [c["name"] for c in (t.get("columns") or [])]
        rows, meta = run_sql(
            host, token, wh,
            f"SELECT column_name FROM {catalog}.information_schema.columns "
            f"WHERE table_schema = {sql_lit(schema)} "
            f"AND table_name = {sql_lit(name)} ORDER BY ordinal_position")
        if rows is None:
            out[name] = {"verdict": "CANNOT_SEE", "api": meta,
                         "means": "The column list could not be read, so "
                                  "drift is UNKNOWN -- not absent."}
            continue
        actual = [r[0] for r in rows]
        added = [c for c in actual if c not in declared]
        gone = [c for c in declared if c not in actual]
        out[name] = {
            "declared": declared,
            "actual": actual,
            "added_since_config": added,
            "missing_from_platform": gone,
            "verdict": ("MATCHES" if not added and not gone
                        else "DRIFTED"),
            "means": (
                "A column present on the base table but not declared here "
                "has no entitlement decision attached to it. It cannot "
                "leak through a view with an explicit select list -- that "
                "is the point of EI-2 -- but it also cannot be audited, "
                "and nobody has said whether it is entitled."),
        }
    return out


# =====================================================================
# Apply
# =====================================================================

def expected_definition(catalog, schema, v):
    cols = ", ".join(v["select"])
    where = f" WHERE {v['where']}" if v.get("where") else ""
    return (f"SELECT {cols} FROM "
            f"{catalog}.{schema}.{v['base_table']}{where}")


def view_comment(v):
    return (f"AWOZ-1227 entitled view. tier={v['tier']} "
            f"dsa_ref={v['dsa_ref']} ({v.get('dsa_ref_status', 'UNKNOWN')}) "
            f"purpose={v['purpose']} row_scope={v.get('row_scope')} "
            f"defined_by=iac/config/entitlements.yaml")


def apply_views(host, token, wh, catalog, schema, cfg, dry):
    """CREATE when absent, ALTER when present.

    `CREATE OR REPLACE VIEW` is not idempotent once the view is in a
    share. Databricks implements the REPLACE as a drop and a create, and
    the drop is blocked:

      INVALID_STATE.DELTA_SHARING_SECURABLE_DELETE_BLOCKED.BY_SHARES
      TABLE ... cannot be deleted because it is being shared via
      OpenSharing. It is shared through the following shares: ...

    So the first run of this script succeeded and the second could not
    repeat it -- an applier that works exactly once, which is the
    opposite of what AC6's redeploy-from-code (T-12) needs. The fix is
    to branch on existence and use `ALTER VIEW ... AS` for the update
    path, with the COMMENT set by a separate `COMMENT ON VIEW`, because
    ALTER VIEW ... AS carries no COMMENT clause.
    """
    results = {}
    for v in cfg["views"]:
        fq = f"{catalog}.{schema}.{v['id']}"
        definition = expected_definition(catalog, schema, v)
        comment = view_comment(v)
        exists = None if dry else view_exists(host, token, wh, catalog,
                                              schema, v["id"])
        create_stmt = (f"CREATE VIEW {fq}\n"
                       f"COMMENT {sql_lit(comment)}\n"
                       f"AS {definition}")
        alter_stmt = f"ALTER VIEW {fq} AS {definition}"
        comment_stmt = f"COMMENT ON VIEW {fq} IS {sql_lit(comment)}"

        if dry:
            print(f"\n  [dry-run] {v['id']}: existence not checked in "
                  f"dry-run, so both paths are shown.")
            print(f"    if absent:  {create_stmt}")
            print(f"    if present: {alter_stmt}")
            print(f"                {comment_stmt}")
            results[v["id"]] = {"verdict": "DRY_RUN",
                                "create_statement": create_stmt,
                                "alter_statement": alter_stmt,
                                "comment_statement": comment_stmt}
            continue

        r = {"full_name": fq, "existed_before": exists,
             "expected_definition": definition, "comment_written": comment}
        if exists is None:
            r["verdict"] = "CANNOT_SEE"
            r["strategy"] = "NONE"
            r["means"] = ("Whether the view exists could not be read, so no "
                          "statement was issued. A CREATE against an "
                          "existing shared view is refused, and the refusal "
                          "would be recorded as a create failure rather than "
                          "as the look that failed first.")
            print(f"  view {v['id']}: CANNOT_SEE (existence check failed)")
            results[v["id"]] = r
            continue

        if not exists:
            r["strategy"] = "CREATE"
            rows, meta = run_sql_full(host, token, wh, create_stmt)
            r["api"] = meta
            r["verdict"] = "CREATED" if rows is not None else "CREATE_FAILED"
        else:
            r["strategy"] = "ALTER"
            r["strategy_because"] = (
                "The view exists and may be in a share. CREATE OR REPLACE "
                "would be refused by "
                "DELTA_SHARING_SECURABLE_DELETE_BLOCKED.BY_SHARES, because "
                "REPLACE drops first.")
            rows, meta = run_sql_full(host, token, wh, alter_stmt)
            r["api_alter"] = meta
            if rows is None:
                r["verdict"] = "ALTER_FAILED"
            else:
                rows2, meta2 = run_sql_full(host, token, wh, comment_stmt)
                r["api_comment"] = meta2
                r["verdict"] = ("UPDATED" if rows2 is not None
                                else "UPDATED_COMMENT_FAILED")
                if rows2 is None:
                    r["comment_failure_means"] = (
                        "The definition was updated and the COMMENT was not. "
                        "EI-4 then fails on the next read, which is the "
                        "correct outcome: a shared object whose DSA "
                        "reference is stale must not look compliant.")
        print(f"  view {v['id']}: {r['verdict']} (strategy {r['strategy']})"
              + ("" if r["verdict"] in ("CREATED", "UPDATED")
                 else f"  {r.get('api_alter') or r.get('api')}"))
        results[v["id"]] = r
    return results


def apply_shares(host, token, catalog, schema, cfg, dry):
    """Create each share if absent; make its object list exactly the one
    the config declares. Removing the base table is a removal like any
    other here -- it falls out of 'exactly the declared list' rather
    than being special-cased, so a different stray object is handled
    too."""
    results = {}
    status, payload = call(host, token, f"{UC}/shares")
    if status != 200:
        return {"__cannot_see__": {
            "http_status": status, "error": redact(json.dumps(payload))[:400],
            "verdict": "CANNOT_SEE",
            "means": "The share list could not be read, so this script does "
                     "not know whether its shares exist. It refuses to "
                     "create them blind: a second share with the same "
                     "purpose is worse than none."}}
    existing = {s.get("name") for s in (payload.get("shares") or [])}

    for sh in cfg["shares"]:
        name = sh["name"]
        r = {"declared_objects": sh["objects"], "actions": []}
        if name not in existing:
            if dry:
                r["actions"].append({"action": "CREATE_SHARE",
                                     "verdict": "DRY_RUN"})
            else:
                st, pl = call(host, token, f"{UC}/shares", "POST",
                              {"name": name,
                               "comment": (sh.get("comment") or "").strip()})
                r["actions"].append({
                    "action": "CREATE_SHARE", "http_status": st,
                    "verdict": "CREATED" if st == 200 else "CREATE_FAILED",
                    "error": (None if st == 200
                              else redact(json.dumps(pl))[:400])})
                print(f"  share {name}: "
                      f"{'CREATED' if st == 200 else f'CREATE FAILED {st}'}")
        else:
            r["actions"].append({"action": "CREATE_SHARE",
                                 "verdict": "ALREADY_EXISTS"})
            print(f"  share {name}: already exists")

        st, pl = call(host, token,
                      f"{UC}/shares/{name}?include_shared_data=true")
        current = ([o.get("name") for o in (pl.get("objects") or [])]
                   if st == 200 else None)
        r["objects_before"] = current
        if current is None:
            r["verdict"] = "CANNOT_SEE"
            r["means"] = ("The share's object list could not be read, so "
                          "what it carries is unknown. No ADD or REMOVE is "
                          "issued against a share whose contents are not "
                          "visible.")
            results[name] = r
            continue

        want = [f"{catalog}.{schema}.{o}" for o in sh["objects"]]
        to_add = [o for o in want if o not in current]
        to_remove = [o for o in current if o not in want]
        updates = ([{"action": "REMOVE", "data_object": {"name": o}}
                    for o in to_remove] +
                   [{"action": "ADD",
                     "data_object": {"name": o, "data_object_type": "VIEW",
                                     "comment": sh.get("purpose", "")}}
                    for o in to_add])
        r["to_add"], r["to_remove"] = to_add, to_remove

        if not updates:
            r["actions"].append({"action": "UPDATE_OBJECTS",
                                 "verdict": "ALREADY_CORRECT"})
        elif dry:
            r["actions"].append({"action": "UPDATE_OBJECTS",
                                 "verdict": "DRY_RUN", "updates": updates})
            print(f"    [dry-run] would add {to_add}, remove {to_remove}")
        else:
            st, pl = call(host, token, f"{UC}/shares/{name}", "PATCH",
                          {"updates": updates})
            code, msg = err_bits(pl)
            r["actions"].append({
                "action": "UPDATE_OBJECTS", "http_status": st,
                "verdict": "APPLIED" if st == 200 else "UPDATE_FAILED",
                "error_code": code or None,
                "error": None if st == 200 else redact(msg)[:400],
                "updates": updates})
            print(f"    objects: +{to_add} -{to_remove} -> "
                  f"{'APPLIED' if st == 200 else f'FAILED {st} {code}'}")

        # B-23: the re-read, not the 200.
        st, pl = call(host, token,
                      f"{UC}/shares/{name}?include_shared_data=true")
        r["objects_after"] = ([o.get("name") for o in (pl.get("objects") or [])]
                              if st == 200 else None)
        r["object_types_after"] = ([o.get("data_object_type")
                                    for o in (pl.get("objects") or [])]
                                   if st == 200 else None)
        r["verdict"] = ("MATCHES_CONFIG"
                        if r["objects_after"] == want else "DIVERGES")
        results[name] = r
    return results


# =====================================================================
# Verify -- five rules, each read back from the platform
# =====================================================================

def rule1_base_table_in_no_share(host, token, catalog, schema, cfg):
    """EI-1. Across EVERY share, not just ours."""
    bases = [f"{catalog}.{schema}.{t['name']}"
             for t in cfg.get("base_tables") or []]
    status, payload = call(host, token, f"{UC}/shares")
    if status != 200:
        return {"verdict": "CANNOT_SEE", "http_status": status,
                "base_tables": bases,
                "means": "The share list could not be read. Whether the base "
                         "table is shared is UNKNOWN. This is not a pass, "
                         "and §12.9 is the reason it is not reported as one."}
    names = [s.get("name") for s in (payload.get("shares") or [])]
    per_share, unreadable, hits = {}, [], []
    for name in names:
        st, pl = call(host, token,
                      f"{UC}/shares/{name}?include_shared_data=true")
        if st != 200:
            unreadable.append({"share": name, "http_status": st})
            per_share[name] = None
            continue
        objs = [o.get("name") for o in (pl.get("objects") or [])]
        per_share[name] = objs
        for b in bases:
            if b in objs:
                hits.append({"share": name, "object": b})
    verdict = ("BASE_TABLE_IN_A_SHARE" if hits
               else "PARTIAL_CANNOT_SEE_ALL_SHARES" if unreadable
               else "BASE_TABLE_IN_NO_SHARE")
    return {
        "verdict": verdict,
        "base_tables": bases,
        "shares_examined": len(names),
        "shares_unreadable": unreadable,
        "objects_by_share": per_share,
        "hits": hits,
        "means": (
            "Every share on this metastore was enumerated and its object "
            "list read. A check scoped to the two shares this config "
            "defines would have passed straight through §11.5's defect, "
            "which was a share nobody looked at."
            if verdict == "BASE_TABLE_IN_NO_SHARE" else
            "At least one share could not be read, so the absence is "
            "bounded by what was visible (B-21)."
            if verdict == "PARTIAL_CANNOT_SEE_ALL_SHARES" else
            "The base table is still in a share. §11.5's defect is live "
            "and T-04 would prove nothing."),
    }


def rules2345_views(host, token, wh, catalog, schema, cfg):
    out = {}
    shared = [v for v in cfg["views"] if v.get("shared")]
    counts = {}

    for v in shared:
        r = {}
        # Rule 2 -- the stored definition, not the one we typed.
        rows, meta = run_sql(
            host, token, wh,
            f"SELECT view_definition FROM {catalog}.information_schema.views "
            f"WHERE table_schema = {sql_lit(schema)} "
            f"AND table_name = {sql_lit(v['id'])}")
        if rows is None or not rows:
            r["rule2_no_star"] = {"verdict": "CANNOT_SEE", "api": meta}
            r["rule2b_definition_matches_config"] = {"verdict": "CANNOT_SEE"}
        else:
            definition = rows[0][0] or ""
            r["rule2_no_star"] = {
                "verdict": "EXPLICIT_SELECT_LIST" if "*" not in definition
                           else "STAR_PRESENT",
                "definition_contains_star": "*" in definition,
                "means": "Read from information_schema.views, so it is what "
                         "the metastore stores. A `SELECT *` here would mean "
                         "the view gains any column the base table gains, "
                         "silently and share-wide.",
            }
            # Rule 2b exists because of what the second run of this
            # script revealed: both ALTER/CREATE statements failed and
            # the old verdict still said VERIFIED, since rules 3 and 4
            # only compare the column set and the COMMENT. A changed
            # WHERE clause passes both. The stored definition has to be
            # compared against the one this config asks for, or "the
            # apply failed but the state is already right" is an
            # assumption rather than a reading.
            want = expected_definition(catalog, schema, v)
            got_n, want_n = normalise_sql(definition), normalise_sql(want)
            r["rule2b_definition_matches_config"] = {
                "expected": want,
                "stored": definition,
                "verdict": ("EXACT" if definition.strip() == want.strip()
                            else "NORMALISED_MATCH" if got_n == want_n
                            else "DIFFERS"),
                "means": "Whitespace and backticks are normalised away; "
                         "letter case is NOT, because 'us-east' and "
                         "'US-EAST' are different predicates over the same "
                         "rows and must never compare equal.",
            }

        # Rule 3 -- the column set, read back.
        rows, meta = run_sql(
            host, token, wh,
            f"SELECT column_name FROM {catalog}.information_schema.columns "
            f"WHERE table_schema = {sql_lit(schema)} "
            f"AND table_name = {sql_lit(v['id'])} ORDER BY ordinal_position")
        if rows is None:
            r["rule3_columns"] = {"verdict": "CANNOT_SEE", "api": meta}
        else:
            actual = [x[0] for x in rows]
            extra = [c for c in actual if c not in v["select"]]
            withheld_present = [c for c in actual
                                if c in (v.get("excludes") or [])]
            r["rule3_columns"] = {
                "declared": v["select"],
                "actual": actual,
                "unexpected": extra,
                "withheld_columns_present": withheld_present,
                "verdict": ("EXACT_MATCH" if actual == v["select"]
                            else "WITHHELD_COLUMN_EXPOSED" if withheld_present
                            else "DIVERGES"),
                "means": "Equality is required, not containment. A view with "
                         "the right columns in the wrong order is fine to "
                         "read and a sign that something other than this "
                         "config last wrote it.",
            }

        # Rule 4 -- the COMMENT carries tier and DSA reference.
        st, pl = call(host, token,
                      f"{UC}/tables/{catalog}.{schema}.{v['id']}")
        comment = (pl.get("comment") or "") if st == 200 else None
        if comment is None:
            r["rule4_dsa_comment"] = {"verdict": "CANNOT_SEE",
                                      "http_status": st}
        else:
            has_tier = f"tier={v['tier']}" in comment
            has_dsa = v["dsa_ref"] in comment
            labelled = (v.get("dsa_ref_status", "") or "") in comment
            r["rule4_dsa_comment"] = {
                "comment": comment,
                "contains_tier": has_tier,
                "contains_dsa_ref": has_dsa,
                "placeholder_status_labelled": labelled,
                "verdict": ("DSA_REF_CARRIED" if has_tier and has_dsa
                            else "MISSING"),
                "means": "§3.3 purpose limitation: a shared object that "
                         "cannot be traced to the agreement that permitted "
                         "it cannot be audited. The COMMENT is the only "
                         "field that travels with the object, and the "
                         "placeholder status travels with the value so "
                         "nobody downstream mistakes it for an executed "
                         "DSA reference.",
            }

        # Row count, for rule 5's comparison.
        rows, meta = run_sql(
            host, token, wh,
            f"SELECT COUNT(*) FROM {catalog}.{schema}.{v['id']}")
        counts[v["id"]] = (int(rows[0][0]) if rows and rows[0] else None)
        r["row_count"] = counts[v["id"]]
        out[v["id"]] = r

    # Rule 5 -- row scope proven by a measured difference.
    full = [v["id"] for v in shared if v.get("row_scope") == "ALL_ROWS"]
    scoped = [v["id"] for v in shared
              if v.get("where") and v.get("row_scope") != "ALL_ROWS"]
    rule5 = {"all_rows_views": full, "scoped_views": scoped,
             "counts": counts}
    if not full or not scoped:
        rule5["verdict"] = "NOT_APPLICABLE"
        rule5["means"] = ("No pair of one unscoped and one scoped view "
                          "exists, so there is nothing to difference.")
    elif any(counts.get(i) is None for i in full + scoped):
        rule5["verdict"] = "CANNOT_SEE"
        rule5["means"] = "At least one count could not be read."
    else:
        base_n = max(counts[i] for i in full)
        bad = [i for i in scoped
               if not (0 < counts[i] < base_n)]
        rule5["verdict"] = "ROW_SCOPE_MEASURED" if not bad else "ROW_SCOPE_NOT_DEMONSTRATED"
        rule5["failing_views"] = bad
        rule5["means"] = (
            "A WHERE clause that matches every row is indistinguishable "
            "from no WHERE clause by reading the DDL, and identical in "
            "effect. So row scope is asserted here only where a scoped "
            "view returns strictly fewer rows than the unscoped one AND "
            "more than zero -- an empty view would also satisfy 'fewer'."
        ) if not bad else (
            "A scoped view returned either the full row set or none of "
            "it. Either way the predicate was not shown to scope "
            "anything.")
    return out, rule5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-base-drift", action="store_true",
                    help="apply even if the base table has columns this "
                         "config does not declare")
    args = ap.parse_args()

    if not CONFIG.exists():
        sys.exit(f"Missing {CONFIG.relative_to(REPO)}")
    try:
        import yaml
    except ImportError:
        sys.exit("pyyaml is required: pip install -r requirements.txt")
    cfg = yaml.safe_load(CONFIG.read_text())

    load_env()
    host = os.environ.get("DATABRICKS_HOST", "").strip().rstrip("/")
    token = os.environ.get("DATABRICKS_TOKEN", "").strip()
    if not host or not token:
        sys.exit("DATABRICKS_HOST and DATABRICKS_TOKEN must be set in .env")
    catalog = os.environ.get("UC_METASTORE_CATALOG", cfg["catalog"])
    schema = os.environ.get("UC_SCHEMA", cfg["schema"])

    print("=" * 70)
    print("E1 Task 1.4 -- view-based entitlement model")
    print("=" * 70)
    print(f"  config:  {CONFIG.relative_to(REPO)}")
    print(f"  target:  {catalog}.{schema}")
    print(f"  mode:    {'DRY RUN' if args.dry_run else 'APPLY'}")

    res = {
        "task": "E1 Task 1.4",
        "run_at": now(),
        "config": str(CONFIG.relative_to(REPO)),
        "catalog": catalog,
        "schema": schema,
        "dry_run": args.dry_run,
        "closes_defects": cfg["conops"]["closes_defects"],
        "model": "view_based_only",
        "masks_and_filters": "FORBIDDEN -- see docs/11 §11.4; refused by the "
                             "platform at every tier, not a tier limit",
    }

    print("\n-- pre-apply guards -------------------------------------------")
    refusals = pre_apply_guards(cfg)
    res["pre_apply_guards"] = {
        "refusals": refusals,
        "verdict": "PASSED" if not refusals else "REFUSED",
        "means": "These run before anything touches the platform. A select "
                 "list containing a withheld column is §11.5's defect "
                 "expressed in config, and it should fail at the edit.",
    }
    for r in refusals:
        print(f"  REFUSED: {r}")
    if refusals:
        res["verdict"] = "REFUSED_BY_PRE_APPLY_GUARDS"
        EVIDENCE.write_text(json.dumps(res, indent=2))
        print(f"\nNothing applied. Wrote {EVIDENCE.relative_to(REPO)}")
        return 1
    print(f"  {len(cfg['views'])} view(s), {len(cfg['shares'])} share(s): "
          f"select lists explicit, no withheld column named.")

    wh = find_warehouse(host, token)
    if not wh:
        sys.exit("No SQL warehouse visible to this token.")
    res["warehouse_id"] = wh

    print("\n-- base table drift ------------------------------------------")
    drift = base_table_drift(host, token, wh, catalog, schema, cfg)
    res["base_table_drift"] = drift
    drifted = [n for n, d in drift.items() if d["verdict"] == "DRIFTED"]
    for n, d in drift.items():
        print(f"  {n}: {d['verdict']}"
              + (f"  added={d.get('added_since_config')} "
                 f"missing={d.get('missing_from_platform')}"
                 if d["verdict"] == "DRIFTED" else ""))
    if drifted and not args.allow_base_drift and not args.dry_run:
        res["verdict"] = "REFUSED_BASE_TABLE_DRIFT"
        res["refusal_means"] = (
            "The base table carries columns this config does not declare, "
            "so no entitlement decision exists for them. They cannot leak "
            "through an explicit select list, but applying now would record "
            "a model that silently omits them. Declare them (entitled true "
            "or false, with a reason) or re-run with --allow-base-drift, "
            "which records the override in this file.")
        EVIDENCE.write_text(json.dumps(res, indent=2))
        print(f"\nREFUSING to apply: {res['refusal_means']}")
        print(f"Wrote {EVIDENCE.relative_to(REPO)}")
        return 1
    if drifted and args.allow_base_drift:
        res["base_drift_override"] = (
            "Applied with --allow-base-drift. The undeclared columns above "
            "have no entitlement decision recorded.")

    print("\n-- apply: views ----------------------------------------------")
    res["views_applied"] = apply_views(host, token, wh, catalog, schema,
                                       cfg, args.dry_run)

    print("\n-- apply: shares ---------------------------------------------")
    res["shares_applied"] = apply_shares(host, token, catalog, schema,
                                         cfg, args.dry_run)

    if args.dry_run:
        res["verdict"] = "DRY_RUN"
        EVIDENCE.write_text(json.dumps(res, indent=2))
        print(f"\n--dry-run: nothing applied, nothing verified. "
              f"Wrote {EVIDENCE.relative_to(REPO)}")
        return 0

    print("\n-- verify ----------------------------------------------------")
    rule1 = rule1_base_table_in_no_share(host, token, catalog, schema, cfg)
    print(f"  rule 1 base table in no share: {rule1['verdict']} "
          f"({rule1.get('shares_examined', '?')} share(s) examined)")
    per_view, rule5 = rules2345_views(host, token, wh, catalog, schema, cfg)
    for vid, r in per_view.items():
        print(f"  {vid}: "
              f"rule2={r['rule2_no_star']['verdict']} "
              f"rule2b={r['rule2b_definition_matches_config']['verdict']} "
              f"rule3={r['rule3_columns']['verdict']} "
              f"rule4={r['rule4_dsa_comment']['verdict']} "
              f"rows={r.get('row_count')}")
    print(f"  rule 5 row scope: {rule5['verdict']}  counts={rule5['counts']}")

    res["verification"] = {
        "rule1_base_table_in_no_share": rule1,
        "rules234_per_view": per_view,
        "rule5_row_scope": rule5,
    }

    # The apply outcome is part of the verdict, which it was not on the
    # first two runs of this script. A run whose statements all failed
    # reported ENTITLEMENT_MODEL_VERIFIED_PROVIDER_SIDE because the
    # verification only reads state, and the state had been left correct
    # by an earlier run. That is a green verdict covering a failed step
    # -- the same shape as §12.4's retracted closure claim, one level
    # down. Three outcomes are now distinguished:
    #
    #   APPLIED          every statement succeeded
    #   NO_CHANGE_NEEDED applies failed AND the stored definition,
    #                    columns and comment already match the config,
    #                    so nothing was lost
    #   FAILED           applies failed and the state does NOT match
    #
    # NO_CHANGE_NEEDED is only available because rule 2b compares the
    # stored definition against the configured one. Without it, this
    # branch would be a guess dressed as a reading.
    applied = res["views_applied"]
    apply_states = {vid: r.get("verdict") for vid, r in applied.items()}
    apply_bad = [vid for vid, st in apply_states.items()
                 if st not in ("CREATED", "UPDATED", "DRY_RUN")]

    good = {"BASE_TABLE_IN_NO_SHARE"}
    view_ok = all(
        r["rule2_no_star"]["verdict"] == "EXPLICIT_SELECT_LIST"
        and r["rule2b_definition_matches_config"]["verdict"]
        in ("EXACT", "NORMALISED_MATCH")
        and r["rule3_columns"]["verdict"] == "EXACT_MATCH"
        and r["rule4_dsa_comment"]["verdict"] == "DSA_REF_CARRIED"
        for r in per_view.values())

    res["apply_outcome"] = {
        "per_view": apply_states,
        "failed_or_blocked": apply_bad,
        "verdict": ("APPLIED" if not apply_bad
                    else "NO_CHANGE_NEEDED" if view_ok
                    else "FAILED"),
        "means": (
            "Every statement succeeded." if not apply_bad else
            "Statements failed, and the stored definition, column set and "
            "COMMENT of every shared view already match this config, so "
            "nothing the config asks for is missing from the platform. The "
            "failures are still recorded in full, and the verdict says "
            "NO_CHANGE_NEEDED rather than APPLIED -- an applier that cannot "
            "repeat itself is a T-12 problem even when the current state "
            "happens to be right." if view_ok else
            "Statements failed and the platform state does not match the "
            "config."),
    }
    shares_ok = all(
        isinstance(v, dict) and v.get("verdict") == "MATCHES_CONFIG"
        for k, v in res["shares_applied"].items()
        if not k.startswith("__"))
    cannot_see = (rule1["verdict"] != "BASE_TABLE_IN_NO_SHARE"
                  and "CANNOT_SEE" in rule1["verdict"]) or any(
        "CANNOT_SEE" in json.dumps(r) for r in per_view.values())

    state_ok = (rule1["verdict"] in good and view_ok and shares_ok
                and rule5["verdict"] in ("ROW_SCOPE_MEASURED",
                                         "NOT_APPLICABLE"))
    if state_ok and not apply_bad:
        res["verdict"] = "ENTITLEMENT_MODEL_VERIFIED_PROVIDER_SIDE"
    elif state_ok:
        # The state is right and the applier could not reproduce it.
        # Reported as its own verdict rather than folded into either
        # neighbour: calling it VERIFIED hides a T-12 defect, and
        # calling it DIVERGES would say the platform is wrong when it
        # is not.
        res["verdict"] = "VERIFIED_PROVIDER_SIDE_APPLY_NOT_REPEATABLE"
    elif cannot_see:
        res["verdict"] = "PARTIAL_CANNOT_SEE"
    else:
        res["verdict"] = "ENTITLEMENT_MODEL_DIVERGES"

    # The honest boundary of what the above establishes.
    res["scope"] = (
        "PROVIDER-SIDE ONLY. What is demonstrated: the shares carry views "
        "and nothing else, the base table is in no share on this metastore, "
        "each view's stored definition has an explicit select list, each "
        "view's column set read back from the platform equals its declared "
        "one exactly, each carries its tier and DSA reference where an "
        "auditor can find them, and row scope is a measured row-count "
        "difference rather than the presence of a WHERE clause. What is NOT "
        "demonstrated: what a RECIPIENT's Delta Sharing client receives when "
        "it asks for table metadata through the issued credential. Task "
        "1.4's verify clause says the recipient sees no internal_notes "
        "column at all -- absent, not masked -- and that half is EKI-1, "
        "owned by Task 1.7 where T-04 is rebuilt.")
    res["conops_change_required"] = (
        "§3.1, §2.3.1 and §3.4 step 2 each offer column masks and row "
        "filters as an alternative to a view. That alternative does not "
        "exist for OpenSharing tables at any tier (§11.4). v1.6 should "
        "strike the clause and state the view pattern as the only "
        "mechanism, with the platform error attached as evidence. This "
        "closes D-1. D-2 closes when Task 1.7 rebuilds T-04 against a "
        "share that no longer contains the column it requests.")
    res["defect_history"] = {
        "D-1": "CLOSED_BY_MEASUREMENT -- masks and filters refused; view "
               "pattern adopted and applied.",
        "D-2": "HALF_CLOSED -- the share no longer carries the column T-04 "
               "requests, so T-04 can now be meaningful. T-04 itself is "
               "rebuilt in Task 1.7; until then D-2 stays open, labelled, "
               "not deleted (B-19).",
    }

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(res, indent=2))
    print(f"\n  apply:   {res['apply_outcome']['verdict']}")
    print(f"  VERDICT: {res['verdict']}")
    print(f"  Wrote {EVIDENCE.relative_to(REPO)}")
    print("\nNext: python3 scripts/25_gen_databricks_tf.py   (same config "
          "-> Terraform, for AC6 / T-12)")
    return 0 if res["verdict"].startswith(
        ("ENTITLEMENT_MODEL_VERIFIED", "VERIFIED_PROVIDER_SIDE")) else 1


if __name__ == "__main__":
    sys.exit(main())
