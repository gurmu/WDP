#!/usr/bin/env python3
"""
E1 Task 1.11: generate iac/databricks/access-matrix.tf from
iac/config/access-matrix.yaml.

Same shape as scripts/25_gen_databricks_tf.py and for the same reason
(AC6 / T-12): the YAML is the definition, the .tf is rendered, and
neither is hand-edited beside the other.

WHAT MAKES THIS GENERATOR DIFFERENT FROM 25
-------------------------------------------
It reads TWO config files and its main job is to disagree with one of
them. access-matrix.yaml names Unity Catalog objects by REFERENCE
(`view:v_entitled_t2`, `table:test_dataset`, `catalog:default`), and
this script resolves each reference against entitlements.yaml. A
reference that does not resolve is a hard exit, not a warning and not a
pass-through of the literal string.

That is the only interesting thing here. The first draft of
access-matrix.yaml spelled object names out in full and got three wrong:
a catalog that does not exist on this workspace and a view name invented
from memory. Terraform would have accepted all three happily --
`databricks_grants` takes a name string -- and produced a reviewable
file granting privileges on nothing, which is the most dangerous kind of
wrong output because it reviews as correct. B-39's sixth appearance.

WHAT THIS FILE IS NOT
---------------------
STATUS: PLAN_ONLY_NOT_APPLIED, and more firmly so than entitlement.tf.
Four of the six principals are ACCOUNT-level objects -- groups and
service principals -- and Free Edition exposes no account console and no
account-level API. The generated resources therefore name principals
that do not exist on this tier, and that is emitted into the output as a
header, not left to a reader's assumption that a .tf file in a repo
runs.

The matrix is also PROVISIONAL (input 1694-G1 has not arrived). The
generator refuses to emit anything unless the YAML still says so: a
provisional matrix that quietly loses its provisional label while
becoming a .tf file is how a proposal becomes an agreed control without
anyone agreeing to it.

Usage:
    python3 scripts/31_gen_access_matrix_tf.py
    python3 scripts/31_gen_access_matrix_tf.py --dry-run
"""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
MATRIX = REPO / "iac" / "config" / "access-matrix.yaml"
ENTITLEMENTS = REPO / "iac" / "config" / "entitlements.yaml"
OUT = REPO / "iac" / "databricks" / "access-matrix.tf"
EVIDENCE = REPO / "evidence" / "access-matrix.json"

EXPECTED_STATUS_PREFIX = "provisional"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def tf_id(s):
    """A Terraform-legal resource label."""
    return re.sub(r"[^a-z0-9_]+", "_", str(s).lower()).strip("_")


def hcl(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def load():
    for p in (MATRIX, ENTITLEMENTS):
        if not p.exists():
            sys.exit(f"Missing {p.relative_to(REPO)}.")
    m = yaml.safe_load(MATRIX.read_text())
    e = yaml.safe_load(ENTITLEMENTS.read_text())
    status = str(m.get("status", ""))
    if not status.startswith(EXPECTED_STATUS_PREFIX):
        sys.exit(
            "access-matrix.yaml's `status` no longer starts with "
            f"'{EXPECTED_STATUS_PREFIX}' (it reads: {status!r}).\n"
            "If 1694-G1 has arrived, this generator needs updating "
            "deliberately -- including the header it writes into the .tf "
            "and the ARB package's first-page caveat. It refuses to "
            "drop the provisional label on its own, because a proposal "
            "that silently becomes a generated control is a proposal "
            "nobody agreed to.")
    return m, e


class Resolver:
    """Resolve access-matrix object references against entitlements.yaml.

    Every unresolved reference is collected and reported together rather
    than failing on the first one: three wrong names found one run at a
    time is three runs, and the person fixing them cannot see whether
    they share a cause.
    """

    def __init__(self, matrix, ent):
        self.catalog = ent["catalog"]
        self.schema = ent["schema"]
        self.tables = {t["name"] for t in ent.get("base_tables", [])}
        self.views = {v["id"] for v in ent.get("views", [])}
        self.schemas = {}
        for key, row in (matrix.get("schemas") or {}).items():
            self.schemas[key] = row["name"]
        self.errors = []
        self.resolved = {}

    def resolve(self, ref, where):
        ref = str(ref)
        if ref == "current":
            self.resolved[ref] = "metastore:current"
            return "current", "metastore"
        if ref == "catalog:default":
            out = self.catalog
            self.resolved[ref] = out
            return out, "catalog"
        if ref == "schema:default":
            out = f"{self.catalog}.{self.schema}"
            self.resolved[ref] = out
            return out, "schema"
        if ref.startswith("schema:"):
            key = ref.split(":", 1)[1]
            if key not in self.schemas:
                self.errors.append(
                    f"{where}: `{ref}` names no entry under `schemas:` in "
                    "access-matrix.yaml. Declare it there (with whether "
                    "it exists locally) or correct the reference.")
                return None, "schema"
            out = f"{self.catalog}.{self.schemas[key]}"
            self.resolved[ref] = out
            return out, "schema"
        if ref.startswith("table:"):
            name = ref.split(":", 1)[1]
            if name not in self.tables:
                self.errors.append(
                    f"{where}: `{ref}` is not a base table in "
                    f"entitlements.yaml. Known: "
                    f"{sorted(self.tables)}.")
                return None, "table"
            out = f"{self.catalog}.{self.schema}.{name}"
            self.resolved[ref] = out
            return out, "table"
        if ref.startswith("view:"):
            vid = ref.split(":", 1)[1]
            if vid not in self.views:
                self.errors.append(
                    f"{where}: `{ref}` is not a view id in "
                    f"entitlements.yaml. Known: {sorted(self.views)}. "
                    "This is the exact defect the reference syntax "
                    "exists to catch (B-39).")
                return None, "view"
            out = f"{self.catalog}.{self.schema}.{vid}"
            self.resolved[ref] = out
            return out, "view"
        # A literal. Allowed, but recorded as such so a reviewer can see
        # which object names in the output were NOT cross-checked.
        self.resolved[ref] = f"{ref} (literal, unchecked)"
        return ref, "literal"


HEADER = """\
# =====================================================================
# GENERATED FILE -- DO NOT HAND-EDIT.
# =====================================================================
#
# Produced by scripts/31_gen_access_matrix_tf.py from
# iac/config/access-matrix.yaml, with every Unity Catalog object name
# resolved against iac/config/entitlements.yaml. Edit the YAML and
# re-run; an edit here is overwritten and, in the meantime, diverges
# from the matrix the ARB package cites.
#
# STATUS: PLAN_ONLY_NOT_APPLIED
# STATUS: {status}
#
# TWO SEPARATE CAVEATS, AND THEY ARE DIFFERENT SIZES.
#
# 1. PROVISIONAL. CONOPS §3.1 presents this matrix and then says it is
#    "for Data Governance to confirm (input 1694-G1)". That input has
#    not arrived (assumption A1). Every grant below is what the CONOPS
#    PROPOSES. Do not cite this file as an agreed control.
#
# 2. NEVER APPLIED, and for four of six principals NOT APPLIABLE on
#    this tier. {acct} of the {total} principals are ACCOUNT-level
#    objects -- groups and service principals -- and Free Edition
#    exposes no account console and no account-level API. The
#    `databricks_group` and `databricks_service_principal` resources
#    below name principals that DO NOT EXIST here. T-12 stays NOT_RUN.
#
# WHAT A REVIEWER SHOULD TAKE FROM THIS FILE
# ------------------------------------------
# Not "the access model is deployed". Rather: this is the access model
# written down precisely enough to be disagreed with, with each row
# labelled by whether the platform can express it, and with the deny
# rows -- the half of a matrix that makes it falsifiable -- marked by
# whether any test covers them. Today, of {denies} deny rows, {tested}
# have a test with no residual gap, {tested_with_gap} have a test that
# verified its own probe and still names a residual gap, and the rest
# have no test at all. Those three are deliberately not collapsed into
# two: a row whose probe was proven to move is not in the same state as
# a row nobody has looked at, and a count that cannot tell them apart
# invites the reader to discount both.
#
# Generated: {at}
# Sources:   iac/config/access-matrix.yaml (schema_version {sv})
#            iac/config/entitlements.yaml  (object names resolved)
"""


def emit(matrix, ent):
    res = Resolver(matrix, ent)
    principals = matrix["principals"]
    body = []
    # Three states, not two. The original count was
    #     tested_by present AND no gap  ->  tested
    #     everything else               ->  not tested
    # which made a deny row with a VERIFIED probe and a named residual
    # gap indistinguishable from a deny row nobody has ever looked at.
    # The base-table row is the case that exposed it: E-2 proves the
    # column and row boundary and proves its own grant probe moves, and
    # still carries gap: partial because consumer identity is not
    # observable on this tier. Counted the old way that row read as
    # untested, which understates the evidence and -- worse -- cannot be
    # told apart from the nine rows that really have no test. A count too
    # coarse to name the state is the same defect as a verdict too coarse
    # to name the cause.
    denies = tested = tested_with_gap = 0
    grant_blocks = []

    for p in principals:
        pid = p["id"]
        kind = p["kind"]
        for row in p.get("must_not", []):
            denies += 1
            tb = str(row.get("tested_by", "NONE"))
            if tb != "NONE" and not row.get("gap"):
                tested += 1
            elif tb != "NONE":
                tested_with_gap += 1
        for g in p.get("grants", []):
            name, otype = res.resolve(g["object"], f"{pid}.grants")
            if name is None:
                continue
            grant_blocks.append((pid, kind, p, otype, name, g))

    if res.errors:
        print("UNRESOLVED OBJECT REFERENCES -- nothing was written.\n")
        for e in res.errors:
            print(f"  * {e}")
        print("\nThe generator stops rather than emitting Terraform that "
              "grants privileges on names nobody checked. A .tf file is "
              "read by people who assume it is correct.")
        sys.exit(1)

    acct = sum(1 for p in principals
               if p["kind"] in ("account_group", "service_principal"))
    body.append(HEADER.format(
        status=matrix["status"], acct=acct, total=len(principals),
        tested=tested, tested_with_gap=tested_with_gap,
        denies=denies, at=now(),
        sv=matrix.get("schema_version")))

    # --- principals ---------------------------------------------------
    body.append("\n# " + "-" * 69)
    body.append("# Principals")
    body.append("# " + "-" * 69)
    for p in principals:
        pid, kind = p["id"], p["kind"]
        label = tf_id(pid)
        body.append("")
        body.append(f"# {p['conops_name']} -- CONOPS §3.1")
        for line in _wrap(p["description"]):
            body.append(f"#   {line}")
        if not p.get("implementable", True):
            body.append("#")
            body.append("#   NOT IMPLEMENTABLE ON THIS TIER:")
            for line in _wrap(p.get("implementable_because", "")):
                body.append(f"#     {line}")
        if p.get("local_substitute"):
            body.append("#   LOCAL SUBSTITUTE (not an implementation):")
            for line in _wrap(str(p["local_substitute"])):
                body.append(f"#     {line}")
        if kind == "account_group":
            body.append(f'resource "databricks_group" "{label}" {{')
            body.append(f'  display_name = {hcl(p["group_name"])}')
            body.append("}")
        elif kind == "service_principal":
            body.append(
                f'resource "databricks_service_principal" "{label}" {{')
            body.append(f'  display_name = {hcl(p["conops_name"])}')
            body.append("}")
        elif kind == "delta_sharing_recipient":
            body.append(
                "# No resource. A Delta Sharing recipient is created by")
            body.append(
                "# scripts/03 and defined in iac/config/recipients.yaml;")
            body.append(
                "# duplicating it here would give two definitions of one")
            body.append(
                "# object, which is the drift T-12 exists to detect.")
            body.append("# Local instances, verified live:")
            for inst in p.get("local_instances", []):
                body.append(f"#   {inst}")

    # --- grants -------------------------------------------------------
    body.append("")
    body.append("# " + "-" * 69)
    body.append("# Grants")
    body.append("# " + "-" * 69)
    body.append("# Object names below were RESOLVED from "
                "entitlements.yaml, not")
    body.append("# transcribed. The reference each one came from is in "
                "the comment.")
    seen = {}
    for pid, kind, p, otype, name, g in grant_blocks:
        key = (otype, name)
        seen.setdefault(key, []).append((pid, kind, p, g))
    for (otype, name), rows in seen.items():
        if otype in ("metastore", "literal"):
            body.append("")
            body.append(f"# NOT EXPRESSIBLE as a databricks_grants "
                        f"block: {name} ({otype}).")
            for pid, kind, p, g in rows:
                body.append(f"#   {pid} would hold "
                            f"{', '.join(g['privileges'])}")
            if otype == "metastore":
                body.append("#   CREATE_SHARE / CREATE_RECIPIENT are "
                            "metastore-level privileges and")
                body.append("#   need the account API this tier does "
                            "not expose.")
            else:
                body.append("#   This object is outside Unity Catalog "
                            "(a serving endpoint); its")
                body.append("#   permission is a databricks_permissions "
                            "resource, and on this tier")
                body.append("#   the identity holding it is a PAT, "
                            "not a principal (R12b).")
            continue
        label = tf_id(f"{otype}_{name}")
        body.append("")
        body.append(f'resource "databricks_grants" "{label}" {{')
        body.append(f'  {otype} = {hcl(name)}')
        for pid, kind, p, g in rows:
            ref = g["object"]
            body.append(f"  # {pid}  (from `{ref}`)")
            principal = (p.get("group_name") or p["conops_name"])
            body.append("  grant {")
            body.append(f"    principal  = {hcl(principal)}")
            body.append(f"    privileges = "
                        f"[{', '.join(hcl(x) for x in g['privileges'])}]")
            body.append("  }")
        body.append("}")

    # --- deny rows ----------------------------------------------------
    body.append("")
    body.append("# " + "-" * 69)
    body.append("# Deny rows -- what each principal must NOT hold")
    body.append("# " + "-" * 69)
    body.append("# Terraform has no resource for 'this principal must "
                "not hold X'. The")
    body.append("# absence of a grant is the only expression available, "
                "and absence is")
    body.append("# not an assertion -- it is indistinguishable from "
                "forgetting. So each")
    body.append("# row below is emitted as a comment WITH its test, "
                "and a row whose")
    body.append("# test is NONE is a gap this file makes visible "
                "rather than closes.")
    for p in principals:
        rows = p.get("must_not", [])
        if not rows:
            continue
        body.append("")
        body.append(f"# {p['id']}:")
        for row in rows:
            tb = str(row.get("tested_by", "NONE"))
            mark = "GAP " if row.get("gap") or tb == "NONE" else "TESTED"
            body.append(f"#   [{mark}] must not {row['what']}")
            if row.get("why"):
                for line in _wrap(row["why"], 64):
                    body.append(f"#            {line}")
            body.append(f"#            test: {tb}")
            if row.get("verdict"):
                body.append(f"#            verdict: {row['verdict']}")
            if row.get("severity"):
                body.append(f"#            severity: {row['severity']}")

    # --- not expressible ----------------------------------------------
    body.append("")
    body.append("# " + "-" * 69)
    body.append("# not_expressible -- carried from the config, verbatim")
    body.append("# " + "-" * 69)
    for item in matrix.get("not_expressible", []):
        body.append(f"# * {item['item']}")
        for line in _wrap(item["why"], 66):
            body.append(f"#     why: {line}" if line == _wrap(
                item["why"], 66)[0] else f"#          {line}")
        for line in _wrap(item["consequence"], 66):
            body.append(f"#     consequence: {line}" if line == _wrap(
                item["consequence"], 66)[0] else f"#                  {line}")
        body.append("#")

    return "\n".join(body) + "\n", res, denies, tested, tested_with_gap


def _wrap(text, width=66):
    words = " ".join(str(text).split()).split(" ")
    lines, cur = [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    matrix, ent = load()
    text, res, denies, tested, tested_with_gap = emit(matrix, ent)

    print("=" * 70)
    print("E1 Task 1.11: the §3.1 access matrix, as configuration")
    print("=" * 70)
    print(f"status        : {matrix['status']}")
    print(f"principals    : {len(matrix['principals'])}  "
          f"(implementable here: "
          f"{sum(1 for p in matrix['principals'] if p.get('implementable'))})")
    print(f"deny rows     : {denies}  (tested, no gap: {tested}; "
          f"tested with a named gap: {tested_with_gap}; "
          f"no test: {denies - tested - tested_with_gap})")
    print(f"refs resolved : {len(res.resolved)}  (0 unresolved, or this "
          f"would have exited)")
    for ref, val in sorted(res.resolved.items()):
        print(f"    {ref:28s} -> {val}")
    print()

    if args.dry_run:
        print("--dry-run: nothing written.")
        return 0

    OUT.write_text(text)
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "task": "E1 1.11",
        "at": now(),
        "status": matrix["status"],
        "awaiting_input": matrix["provisional_because"]["input"],
        "principals": [
            {"id": p["id"], "kind": p["kind"],
             "implementable": p.get("implementable"),
             "implemented_locally": p.get("implemented_locally"),
             "deny_rows": len(p.get("must_not", [])),
             "deny_rows_tested": sum(
                 1 for r in p.get("must_not", [])
                 if str(r.get("tested_by", "NONE")) != "NONE"
                 and not r.get("gap"))}
            for p in matrix["principals"]],
        "deny_rows_total": denies,
        "deny_rows_tested": tested,
        "deny_rows_tested_with_named_gap": tested_with_gap,
        "deny_rows_untested": denies - tested - tested_with_gap,
        "why_three_counts": (
            "deny_rows_tested counts rows with a test and no residual "
            "gap. A row with a verified probe and a named gap is "
            "counted separately rather than folded into either side: "
            "folded up it overstates coverage, folded down it is "
            "indistinguishable from a row nobody has tested. The "
            "base-table deny row is the case that forced the "
            "distinction -- tests/e2_egress_d2d.py proves the column "
            "and row boundary AND proves its own grant probe moves, "
            "and still cannot observe consumer identity on this tier."),
        "object_references_resolved": res.resolved,
        "generated": str(OUT.relative_to(REPO)),
        "what_this_is": (
            "The matrix written down precisely enough to be disagreed "
            "with. PLAN_ONLY_NOT_APPLIED and PROVISIONAL are separate "
            "caveats: the first is a tier limit that a paid account "
            "removes, the second is a missing governance input that it "
            "does not."),
        "what_this_is_not": (
            f"Not a deployed control. "
            f"{denies - tested - tested_with_gap} of {denies} deny rows "
            "have no test at all, and they are the separation-of-duty "
            "rows -- untestable in a prototype where one operator wears "
            "every hat. This sentence previously counted "
            f"{denies - tested} rows as untested, which was wrong once a "
            "deny row acquired a verified probe AND a named residual "
            "gap: that row has a test, and saying otherwise understated "
            "the one piece of internal-channel evidence E1 actually "
            "produced. The ARB package must distinguish three states, "
            "not two -- measured and clean, measured with a named gap, "
            "and a sentence nobody has tested."),
    }, indent=2))
    print(f"Wrote {OUT.relative_to(REPO)}")
    print(f"Wrote {EVIDENCE.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
