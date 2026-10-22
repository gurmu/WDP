#!/usr/bin/env python3
"""
E1 Task 1.3 and 1.4 verification -- assert the CaC config files.

Covers iac/config/channels.yaml, iac/config/route-table.yaml and
iac/config/entitlements.yaml. STATIC ONLY: it never contacts the
platform, so a clean result says the files agree with the CONOPS lists
and with each other, NOT that the live metastore matches them. The live
half of the entitlement model is scripts/24_build_entitlement_model.py.

Task 1.3's "verify" clause is: every channel in CONOPS 2.1 and every
route in 2.3.2 appears exactly once, and E2 can generate the Gravitee
flows from these files without consulting the docx. This script is that
assertion, run as code rather than read by eye, because the failure mode
it guards is a quiet one: a route table with fifteen of sixteen rows
generates fifteen flows and reports success.

It checks the invariants the two files declare about themselves, so the
`invariants:` block in route-table.yaml is executable rather than
decorative. If an invariant is edited there, it must be edited here too
-- and the test for that is the last check below, which compares the
counts.

Exit 0 only if every check passes. Writes evidence/cac-config-check.json.

Usage:
    python3 scripts/22_check_cac_config.py
    python3 scripts/22_check_cac_config.py --quiet
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml --break-system-packages")

REPO = Path(__file__).resolve().parents[1]
CHANNELS = REPO / "iac" / "config" / "channels.yaml"
ROUTES = REPO / "iac" / "config" / "route-table.yaml"
ENTITLEMENTS = REPO / "iac" / "config" / "entitlements.yaml"
RECIPIENTS = REPO / "iac" / "config" / "recipients.yaml"
EVIDENCE = REPO / "evidence" / "cac-config-check.json"

# CONOPS v1.5 §2.1 and §2.3.2, transcribed here ONCE so the check has
# something independent to compare the files against. If these lists are
# wrong the check is worthless, so they carry their source.
CONOPS_CHANNELS = ["E-1", "E-2", "E-3", "I-1", "I-2"]
CONOPS_ROUTES = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9",
                 "S10", "F1", "M1", "M2", "M3", "A1", "X"]
CONOPS_CLASSES = {
    "A": ["S1", "S2", "S3", "S4", "S5", "S6", "S7"],
    "B": ["S8", "S9"],
    "C": ["S10"],
    "D": ["F1"],
    "E": ["M1", "M2"],
}
NOT_EXPOSED = ["M3", "A1", "X"]


def now():
    return datetime.now(timezone.utc).isoformat()


def check_recipients(c):
    """E1 Task 1.5's static half.

    The live half belongs to scripts/27. These checks matter more than
    Task 1.4's equivalents, for one reason: creating a TOKEN recipient
    MINTS a credential in the same call, so an error in this file is not
    caught by applying it and looking -- applying it has already issued
    something. The static pass is the only point at which a mistake here
    costs nothing.

    Returns the parsed document, or None if absent. Absence is a check,
    not a crash.
    """
    if not RECIPIENTS.exists():
        c.add("recipients.yaml exists (Task 1.5)", False,
              "iac/config/recipients.yaml is missing; Task 1.5's static "
              "checks did not run. This is NOT a pass for them.")
        return None
    doc = yaml.safe_load(RECIPIENTS.read_text())
    c.add("recipients.yaml exists (Task 1.5)", True)

    recips = doc.get("recipients") or []
    c.add("recipients: at least one is defined", bool(recips))

    # The OD-5 guard. This is the check that stops a laptop convenience
    # from being read back as an agreed control.
    tp = doc.get("token_policy") or {}
    c.add("token_policy is labelled a prototype default, not a policy",
          tp.get("status") == "PROTOTYPE_DEFAULT_NOT_POLICY",
          "an unlabelled default becomes a decision by being found in a "
          "file; OD-5 is OPEN and owned by Data Governance")
    c.add("token_policy names its decision owner",
          bool(tp.get("decision_owner")))
    subs = tp.get("sub_decisions") or []
    c.add("token_policy carries all five OD-5 sub-decisions",
          len(subs) >= 5, f"{len(subs)} present; §3.1.1 lists five")
    for sd in subs:
        sid = sd.get("id")
        c.add(f"{sid}: states whether it is genuinely open",
              isinstance(sd.get("genuinely_open"), bool),
              "a sub-decision that does not say whether it is open cannot "
              "be escalated or closed")
        c.add(f"{sid}: carries a question", bool(sd.get("question")))

    lifetime = next((sd.get("local_days") for sd in subs
                     if sd.get("id") == "OD5-2"), None)
    c.add("OD5-2: configured token lifetime is inside the documented "
          "one-year platform bound",
          isinstance(lifetime, int) and 0 < lifetime <= 365,
          f"local_days={lifetime}; the platform maximum is 365 days")

    # The sign-in branch has to say what it is NOT building and what
    # swapping would cost, or §13.2's "substitution not redesign" claim
    # is unsupported.
    si = doc.get("sign_in") or {}
    branches = si.get("branches") or []
    built = [b for b in branches if str(b.get("status", "")).startswith("BUILT")]
    unbuilt = [b for b in branches
               if not str(b.get("status", "")).startswith("BUILT")]
    c.add("sign_in: exactly one branch is built", len(built) == 1,
          f"{len(built)} branches marked BUILT; one branch built completely "
          f"is what docs/13 §13.2 asks for")
    c.add("sign_in: the unbuilt branch records what changes if chosen",
          bool(unbuilt) and all(b.get("what_changes_if_chosen") for b in unbuilt),
          "without it, OD-5 is a redesign rather than a substitution")
    c.add("sign_in: the unbuilt branch records why it is not built",
          all(b.get("not_built_because") for b in unbuilt))

    # Platform facts must separate measured from documented. §12.9's rule
    # applied to provenance rather than to verdicts.
    facts = doc.get("platform_facts") or []
    c.add("platform_facts: at least five are recorded", len(facts) >= 5)
    allowed_status = {"MEASURED", "DOCUMENTED_NOT_MEASURED",
                      "PARTIALLY_MEASURED"}
    for f in facts:
        c.add(f"platform fact '{(f.get('fact') or '')[:40].strip()}...': "
              f"provenance is explicit",
              f.get("status") in allowed_status,
              f"status={f.get('status')}; must be one of "
              f"{sorted(allowed_status)} -- 'the docs say' and 'we watched "
              f"it' are different strengths of claim and the §13.2 ask must "
              f"not blur them")
        if f.get("status") == "PARTIALLY_MEASURED":
            c.add("partially-measured fact names both halves",
                  bool(f.get("measured_part")) and bool(f.get("unmeasured_part")),
                  "a half-measured fact that does not say which half is "
                  "which gets quoted as a whole one")

    # Per-recipient checks.
    ent_shares = set()
    if ENTITLEMENTS.exists():
        ent_shares = {s.get("name") for s in
                      (yaml.safe_load(ENTITLEMENTS.read_text())
                       .get("shares") or [])}
    seen = set()
    for r in recips:
        n = r.get("name")
        c.add(f"recipient {n}: name is unique in this file", n not in seen)
        seen.add(n)
        c.add(f"recipient {n}: authentication_type is declared",
              r.get("authentication_type") in ("TOKEN", "DATABRICKS"),
              "the authentication type IS the OD-5 branch")
        c.add(f"recipient {n}: carries a DSA reference",
              bool(r.get("dsa_ref")), "§3.3 purpose limitation")
        c.add(f"recipient {n}: the DSA reference's status is declared",
              r.get("dsa_ref_status") in ("PLACEHOLDER", "EXECUTED"),
              "a placeholder that does not say so gets quoted as an "
              "executed agreement reference")
        c.add(f"recipient {n}: declares its purpose", bool(r.get("purpose")))
        c.add(f"recipient {n}: declares its channel",
              r.get("channel") in ("D2O", "D2D"),
              "§3.1's isolation rule has a different answer per channel, so "
              "a recipient with no channel cannot be checked against it")

        grants = r.get("grants") or []
        c.add(f"recipient {n}: has at least one grant", bool(grants),
              "a recipient with no grant can prove nothing -- a denial "
              "against it would be a denial either way")
        for g in grants:
            c.add(f"recipient {n}: grant target {g.get('share')} is defined "
                  f"in entitlements.yaml",
                  (g.get("share") in ent_shares) if ent_shares else True,
                  "a grant to a share the entitlement model does not define "
                  "is a hole with no column list behind it")
            c.add(f"recipient {n}: grant on {g.get('share')} names its "
                  f"privileges", bool(g.get("privileges")))

        ipl = r.get("ip_access_list") or {}
        mode = ipl.get("mode")
        c.add(f"recipient {n}: ip_access_list mode is declared",
              mode in ("APPLIED", "NOT_APPLIED_BY_DESIGN"),
              "an absent list and a deliberately-absent list are different "
              "configurations and only one of them is a finding")
        if mode == "NOT_APPLIED_BY_DESIGN":
            c.add(f"recipient {n}: records why no list is applied",
                  bool(ipl.get("not_applied_because")),
                  "without the reason, the next reader 'fixes' it and turns "
                  "an entitlement test into a network test that passes for "
                  "the wrong reason")
        if mode == "APPLIED":
            addrs = ipl.get("allowed_ip_addresses") or []
            c.add(f"recipient {n}: applied list is non-empty", bool(addrs),
                  "an APPLIED list with no addresses denies everything and "
                  "is indistinguishable from a misconfiguration")
            c.add(f"recipient {n}: applied list records why these addresses",
                  bool(ipl.get("allowed_because")))
            # The one that matters: a routable address here could be the
            # operator's own, which silently converts a deny test into an
            # allow test that still reports a pass.
            c.add(f"recipient {n}: applied list uses documentation-range "
                  f"addresses only",
                  all(str(a).startswith(("203.0.113.", "198.51.100.",
                                         "192.0.2.")) for a in addrs),
                  "RFC 5737 ranges are chosen so the list can never "
                  "accidentally contain the operator's own egress address, "
                  "which would turn T-02's deny test into an allow test "
                  "while still reporting a pass")
            proc = r.get("t02_procedure") or {}
            c.add(f"recipient {n}: the deny test is specified in two phases",
                  bool(proc.get("phase_1")) and bool(proc.get("phase_2")),
                  "one observation cannot attribute a denial: 'denied while "
                  "the list excludes me' is also what a broken credential, "
                  "an unactivated token and a typo'd share name look like")
            c.add(f"recipient {n}: the deny test records its status honestly",
                  proc.get("status") in ("SPECIFIED_NOT_RUN", "RUN"),
                  "a specified procedure is not a run one")

    # Unmanaged objects: inventory, never delete.
    um = doc.get("unmanaged_recipients") or {}
    c.add("unmanaged recipients: a policy is declared",
          um.get("policy") == "INVENTORY_AND_REPORT_NEVER_DELETE",
          "B-19: a leftover is labelled, not erased -- and a probe object "
          "still needed by a probe must not be removed by an applier that "
          "does not know what needs it")
    c.add("unmanaged recipients: the policy carries its reason",
          bool(um.get("policy_because")))
    for lo in (um.get("known_leftovers") or []):
        c.add(f"leftover {lo.get('name')}: origin is named",
              bool(lo.get("origin")))
        c.add(f"leftover {lo.get('name')}: last measured reachability is "
              f"recorded with its evidence",
              bool(lo.get("last_measured_reachability"))
              and bool(lo.get("evidence")),
              "membership is not reachability (B-31); a leftover recorded "
              "without one of them is a claim with no measurement")

    # §3.1's two answers.
    sh = doc.get("share_isolation") or {}
    c.add("share_isolation: the CONOPS text is quoted",
          bool(sh.get("conops_text")))
    c.add("share_isolation: the finding is stated", bool(sh.get("finding")))
    c.add("share_isolation: measured and unmeasured halves are separated",
          sh.get("status") == "HALF_MEASURED"
          and bool(sh.get("measured_half")) and bool(sh.get("unmeasured_half")),
          "the D2D refusal is measured (B-29) and the D2O permission is not; "
          "a single verdict over both would be a guess wearing evidence")
    c.add("share_isolation: names what v1.6 must change",
          bool(sh.get("consequence_for_v1_6")))

    inv = doc.get("invariants") or []
    c.add("recipients.yaml declares its invariants", len(inv) >= 7,
          f"{len(inv)} declared")
    for i in inv:
        c.add(f"invariant {i.get('id')}: names what checks it",
              bool(i.get("checked_by")),
              "an invariant with no checker is a wish")
        c.add(f"invariant {i.get('id')}: carries a reason",
              bool(i.get("because")))
    ids = {i.get("id") for i in inv}
    c.add("invariant RI-7 exists: the activation link never reaches stdout "
          "or the evidence file", "RI-7" in ids,
          "whoever holds the one-time link holds the credential, and stdout "
          "reaches scrollback, screen shares, CI logs and chat transcripts")

    ki = doc.get("known_incomplete") or []
    c.add("recipients.yaml records what it does not establish", len(ki) >= 4,
          f"{len(ki)} recorded")
    for k in ki:
        c.add(f"{k.get('id')}: names an owner", bool(k.get("owner")))
        c.add(f"{k.get('id')}: names what closes it",
              bool(k.get("closes_when")))
    c.add("known_incomplete: the consumer-side gap is recorded",
          any("consumer" in str(k.get("scope", "")).lower() for k in ki),
          "everything scripts/27 checks is provider-side, exactly as Task "
          "1.4's checks were; RKI-1 is what stops that being read as a "
          "consumer-side pass")

    return doc


def check_entitlements(c):
    """E1 Task 1.4's static half.

    The live half -- what the metastore actually holds -- belongs to
    scripts/24, which reads the same file and applies it. These checks
    exist so a bad edit fails AT THE EDIT: by the time the model has
    been applied, a withheld column in a select list has already been
    published to a recipient, and §11.5 is the record of how long that
    can go unnoticed.

    Returns the parsed document, or None if the file is absent. Absence
    is reported as a check, not as a crash, so this script still runs
    for Task 1.3 alone.
    """
    if not ENTITLEMENTS.exists():
        c.add("entitlements.yaml exists (Task 1.4)", False,
              "iac/config/entitlements.yaml is missing; Task 1.4's static "
              "checks did not run. This is NOT a pass for them.")
        return None
    doc = yaml.safe_load(ENTITLEMENTS.read_text())
    c.add("entitlements.yaml exists (Task 1.4)", True)

    base_tables = doc.get("base_tables") or []
    views = doc.get("views") or []
    shares = doc.get("shares") or []

    withheld, declared_cols = set(), {}
    for t in base_tables:
        cols = t.get("columns") or []
        declared_cols[t.get("name")] = [x.get("name") for x in cols]
        c.add(f"base table {t.get('name')}: never_shared is set",
              t.get("never_shared") is True,
              "a base table in this file that is not marked never_shared "
              "has had the §11.5 decision silently reversed")
        for col in cols:
            if not col.get("entitled"):
                withheld.add(col.get("name"))
                c.add(f"column {t.get('name')}.{col.get('name')}: "
                      f"withheld with a reason",
                      bool(col.get("withheld_because")),
                      "a column excluded without a recorded reason cannot "
                      "be defended in the ARB package or reinstated safely")

    c.add("at least one column is withheld", bool(withheld),
          "with nothing withheld, T-04 has nothing to request and the "
          "model proves nothing -- which is exactly §11.5's defect")

    # EI-2 and EI-5, the two that fail open.
    for v in views:
        vid = v.get("id")
        sel = v.get("select") or []
        c.add(f"view {vid}: select list is non-empty", bool(sel))
        c.add(f"view {vid}: no '*' in the select list",
              all("*" not in str(x) for x in sel),
              "EI-2: a view defined by subtraction picks up any column "
              "the base table gains, silently and share-wide")
        leaked = sorted(set(sel) & withheld)
        c.add(f"view {vid}: no withheld column in the select list",
              not leaked, f"withheld columns present: {leaked}")
        known = declared_cols.get(v.get("base_table"))
        c.add(f"view {vid}: base_table is declared in base_tables",
              known is not None, f"base_table={v.get('base_table')!r}")
        if known is not None:
            unknown = [x for x in sel if x not in known]
            c.add(f"view {vid}: every selected column exists on the base "
                  f"table", not unknown, f"not declared: {unknown}")
        for field in ("tier", "dsa_ref", "purpose", "base_table",
                      "row_scope"):
            c.add(f"view {vid}: has {field}", bool(v.get(field)),
                  "EI-4 / §3.3: the COMMENT built from these fields is the "
                  "only thing that travels with the shared object")
        if v.get("dsa_ref_status") == "PLACEHOLDER":
            c.add(f"view {vid}: placeholder DSA ref says why it is one",
                  bool(v.get("dsa_ref_status_because")),
                  "an unlabelled placeholder reference is indistinguishable "
                  "from an executed one downstream")
        # A WHERE clause with no row_scope label, or a row_scope label
        # with no WHERE, means the two fields disagree about what the
        # view does.
        has_where = bool(v.get("where"))
        scoped = v.get("row_scope") not in (None, "ALL_ROWS")
        c.add(f"view {vid}: where clause and row_scope agree",
              has_where == scoped,
              f"where={v.get('where')!r} row_scope={v.get('row_scope')!r}; "
              f"a predicate with no label is invisible to review, and a "
              f"label with no predicate filters nothing")

    view_ids = {v.get("id") for v in views}
    c.add("views: no duplicate ids", len(view_ids) == len(views))

    shared_ids = set()
    for sh in shares:
        name = sh.get("name")
        objs = sh.get("objects") or []
        c.add(f"share {name}: carries at least one object", bool(objs),
              "an empty share grants nothing and reads to the consumer as "
              "a provisioning failure")
        bad = [o for o in objs if o not in view_ids]
        c.add(f"share {name}: every object is a view defined here",
              not bad, f"not views in this file: {bad}")
        shared_ids |= set(objs)
        base_names = {t.get("name") for t in base_tables}
        c.add(f"share {name}: carries no base table",
              not (set(objs) & base_names),
              "§11.5: this is the defect, as config")
        c.add(f"share {name}: has a purpose", bool(sh.get("purpose")),
              "§3.1 share isolation is per purpose, so a share without one "
              "cannot be shown to be isolated from anything")
        if sh.get("remediation_required"):
            c.add(f"share {name}: remediation is explained",
                  bool(sh.get("remediation")),
                  "a share flagged for remediation with no statement of "
                  "what is wrong cannot be verified as fixed")

    # A view marked shared that no share carries is a view that looks
    # entitled and reaches nobody; the reverse is a share object with no
    # definition. Both are silent.
    for v in views:
        if v.get("shared"):
            c.add(f"view {v.get('id')}: some share carries it",
                  v.get("id") in shared_ids,
                  "marked shared: true but named by no share, so the "
                  "entitlement it describes reaches no recipient")

    c.add("masks and row filters are recorded as forbidden",
          any(f.get("mechanism") in ("column_mask", "row_filter")
              and f.get("status") == "REFUSED_BY_PLATFORM"
              for f in (doc.get("forbidden_mechanisms") or [])),
          "§11.4's measurement is what licences the view-only model; "
          "without it in this file, somebody reading §3.1 reintroduces "
          "masks")
    c.add("select-star subtraction is recorded as forbidden",
          any(f.get("mechanism") == "select_star_except"
              for f in (doc.get("forbidden_mechanisms") or [])),
          "this one is forbidden by THIS PROJECT, not by the platform, so "
          "it has to be written down or it comes back as a convenience")

    for inv in (doc.get("invariants") or []):
        c.add(f"invariant {inv.get('id')}: names what checks it",
              bool(inv.get("checked_by")),
              "an invariant with no checker is decorative, and reads as "
              "enforced")
    c.add("entitlements.yaml declares its invariants",
          len(doc.get("invariants") or []) >= 6,
          f"{len(doc.get('invariants') or [])} declared")

    for ki in (doc.get("known_incomplete") or []):
        missing = [k for k in ("statement", "closes_when", "owner")
                   if not ki.get(k)]
        c.add(f"known_incomplete {ki.get('id')}: statement, closes_when, "
              f"owner", not missing, f"missing {missing}")
    c.add("entitlements.yaml records what it does not establish",
          bool(doc.get("known_incomplete")),
          "the provider-side/recipient-side split is the whole of EKI-1; "
          "without it, a provider-side pass reads as Task 1.4's full "
          "verify clause")
    return doc


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, detail=""):
        self.rows.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    @property
    def failed(self):
        return [r for r in self.rows if not r["ok"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    c = Checks()

    for path in (CHANNELS, ROUTES):
        if not path.exists():
            c.add(f"{path.name} exists", False, "file missing")
            print(json.dumps(c.rows, indent=2))
            return 1

    ch_doc = yaml.safe_load(CHANNELS.read_text())
    rt_doc = yaml.safe_load(ROUTES.read_text())

    channels = ch_doc.get("channels") or []
    routes = rt_doc.get("routes") or []
    targets = rt_doc.get("targets") or {}
    enums = ch_doc.get("enums") or {}

    # ---- channels ----------------------------------------------------
    ch_ids = [x.get("id") for x in channels]
    c.add("channels: all five §2.1 ids present",
          sorted(ch_ids) == sorted(CONOPS_CHANNELS),
          f"found {ch_ids}")
    c.add("channels: no duplicate ids",
          len(ch_ids) == len(set(ch_ids)),
          f"{len(ch_ids)} rows, {len(set(ch_ids))} distinct")

    for ch in channels:
        cid = ch.get("id")
        for field in ("direction", "mechanism", "gravitee_fronts",
                      "databricks_control", "conops_status",
                      "prototype_status", "tests"):
            c.add(f"channel {cid}: has {field}", field in ch,
                  "Task 1.3 deliverable names this field")
        if ch.get("direction") not in (enums.get("direction") or []):
            c.add(f"channel {cid}: direction in enum", False,
                  f"{ch.get('direction')!r} not in enums.direction")
        if ch.get("conops_status") not in (enums.get("conops_status") or []):
            c.add(f"channel {cid}: conops_status in enum", False,
                  f"{ch.get('conops_status')!r} not in enums.conops_status")
        if ch.get("prototype_status") not in (enums.get("prototype_status") or []):
            c.add(f"channel {cid}: prototype_status in enum", False,
                  f"{ch.get('prototype_status')!r} not in enums.prototype_status")
        # A channel with no tests must say why. An empty list with no
        # explanation is the silent negative: it reads as "no tests
        # needed" and as "nobody wrote them down" identically.
        if not ch.get("tests") and not (ch.get("tests_gap") or ch.get("tests_note")):
            c.add(f"channel {cid}: empty tests is explained", False,
                  "tests is empty and neither tests_gap nor tests_note is set")
        # Likewise a channel with no routes.
        if not ch.get("routes") and not (ch.get("routes_note") or ch.get("routes_gap")):
            c.add(f"channel {cid}: empty routes is explained", False,
                  "routes is empty and neither routes_note nor routes_gap is set")
        # A correction must carry all three parts or it is an assertion.
        corr = ch.get("conops_correction")
        if corr:
            missing = [k for k in ("finding", "what_was_measured", "consequence")
                       if not corr.get(k)]
            c.add(f"channel {cid}: conops_correction is complete", not missing,
                  f"missing {missing}" if missing else "")

    # ---- routes ------------------------------------------------------
    rt_ids = [r.get("id") for r in routes]
    c.add("routes: all sixteen §2.3.2 ids present",
          sorted(rt_ids) == sorted(CONOPS_ROUTES),
          f"missing {sorted(set(CONOPS_ROUTES) - set(rt_ids))}, "
          f"extra {sorted(set(rt_ids) - set(CONOPS_ROUTES))}")
    c.add("routes: each id appears exactly once",
          len(rt_ids) == len(set(rt_ids)),
          f"{len(rt_ids)} rows, {len(set(rt_ids))} distinct")

    by_id = {r.get("id"): r for r in routes}

    for rid, r in by_id.items():
        for field in ("methods", "protocol_path", "target", "policy_class",
                      "exposed"):
            c.add(f"route {rid}: has {field}", field in r,
                  "Task 1.3 deliverable names this field")
        tgt = r.get("target")
        c.add(f"route {rid}: target resolves", tgt in targets,
              f"{tgt!r} not a key in targets")
        # No hostnames in rows -- hosts resolve through targets only.
        #
        # default=str is load-bearing, not tidiness. An unquoted YAML date
        # (methods_confirmed_on: 2026-10-22) parses to datetime.date, which
        # json.dumps refuses, and the refusal is a TypeError that kills the
        # whole gate: zero checks, no verdict, a non-zero exit for a reason
        # that has nothing to do with configuration. That is the silent
        # negative in its most literal form -- a gate that CRASHES is worse
        # than one that FAILS, because a failure names a cause and a crash
        # names only itself. It happened here on 2026-10-22. The scan wants
        # every scalar flattened to text so it can look for a host in it, so
        # stringifying whatever it does not recognise is also the correct
        # behaviour for the check: a date rendered "2026-10-22" contains no
        # hostname and is scanned rather than skipped.
        blob = json.dumps({k: v for k, v in r.items()
                           if k not in ("prototype_observed", "note",
                                        "prototype_status")},
                          default=str)
        leak = [tok for tok in (".cloud.databricks.com", "http://", "https://")
                if tok in blob]
        c.add(f"route {rid}: no hostname or URL in the row", not leak,
              f"found {leak}")

    for rid in NOT_EXPOSED:
        r = by_id.get(rid, {})
        c.add(f"route {rid}: exposed is false", r.get("exposed") is False,
              f"exposed={r.get('exposed')!r}")
        c.add(f"route {rid}: has enforcement", bool(r.get("enforcement")),
              "a not-exposed row without enforcement is an omission, "
              "and an omission emits Gravitee's 404 instead of the "
              "protocol error format")
        c.add(f"route {rid}: has not_exposed_because",
              bool(r.get("not_exposed_because")), "")

    for rid, r in by_id.items():
        if r.get("exposed") is True:
            c.add(f"route {rid}: exposed row has a policy class",
                  r.get("policy_class") in CONOPS_CLASSES,
                  f"policy_class={r.get('policy_class')!r}")
        elif r.get("exposed") is False:
            c.add(f"route {rid}: not-exposed row has a null policy class",
                  r.get("policy_class") is None,
                  f"policy_class={r.get('policy_class')!r}")
        else:
            c.add(f"route {rid}: exposed is a boolean", False,
                  f"exposed={r.get('exposed')!r}")

    # §2.3.3 class membership must agree with the route rows.
    for cls, ids in CONOPS_CLASSES.items():
        actual = sorted([rid for rid, r in by_id.items()
                         if r.get("policy_class") == cls])
        c.add(f"class {cls}: membership matches §2.3.3",
              actual == sorted(ids), f"expected {sorted(ids)}, got {actual}")

    # The selector trap, asserted directly rather than trusted.
    c.add("S7 and S8 are in different classes",
          by_id.get("S7", {}).get("policy_class")
          != by_id.get("S8", {}).get("policy_class"),
          "if these collapse, the selector is path-only and T-05 "
          "measures the wrong class")

    # Unconfirmed fields must name what settles them, or they are guesses
    # wearing a flag.
    for rid, r in by_id.items():
        for key in list(r):
            if key.endswith("_unconfirmed") and r.get(key) is True:
                base = key[: -len("_unconfirmed")]
                has_reason = bool(r.get(f"{key}_because"))
                has_owner = bool(r.get("settled_by") or r.get("tests"))
                c.add(f"route {rid}: {base} unconfirmed flag is accountable",
                      has_reason and has_owner,
                      f"needs {key}_because and a settled_by or tests")

    # ---- cross-file --------------------------------------------------
    route_channels = {r.get("channel") for r in routes} - {None}
    c.add("routes: every channel reference exists in channels.yaml",
          route_channels.issubset(set(ch_ids)),
          f"unknown {sorted(route_channels - set(ch_ids))}")

    for ch in channels:
        cid = ch.get("id")
        declared = set(ch.get("routes") or [])
        unknown = declared - set(rt_ids)
        c.add(f"channel {cid}: declared routes all exist", not unknown,
              f"unknown {sorted(unknown)}")
        if ch.get("gravitee_fronts") and not declared:
            gap_ids = {g.get("channel") for g in (rt_doc.get("gaps") or [])}
            c.add(f"channel {cid}: fronted channel has routes or a gap",
                  cid in gap_ids,
                  "a Gravitee-fronted channel with no routes and no "
                  "recorded gap is a hole in the perimeter description")
        # A route row's channel and the channel's route list must agree
        # in both directions.
        back = {rid for rid, r in by_id.items() if r.get("channel") == cid}
        c.add(f"channel {cid}: route membership agrees both ways",
              back == declared,
              f"channels.yaml says {sorted(declared)}, route rows say "
              f"{sorted(back)}")

    # ---- gaps --------------------------------------------------------
    for g in (rt_doc.get("gaps") or []):
        gid = g.get("id")
        missing = [k for k in ("decision_owner", "decision_status")
                   if not g.get(k)]
        c.add(f"gap {gid}: has an owner and a status", not missing,
              f"missing {missing}" if missing else "")

    # ---- the invariants block is not stale ---------------------------
    inv = rt_doc.get("invariants") or []
    c.add("route-table.yaml declares its invariants", len(inv) >= 8,
          f"{len(inv)} declared; this script asserts them")

    # ---- entitlements.yaml (Task 1.4) --------------------------------
    ent_doc = check_entitlements(c)

    # ---- recipients.yaml (Task 1.5) ----------------------------------
    rec_doc = check_recipients(c)

    # ---- report ------------------------------------------------------
    failed = c.failed
    results = {
        "task": "E1 Tasks 1.3, 1.4 and 1.5 -- channel model, route table, "
                "entitlement model and recipient model as configuration",
        "date": now(),
        "files": [str(CHANNELS.relative_to(REPO)), str(ROUTES.relative_to(REPO))]
                 + ([str(ENTITLEMENTS.relative_to(REPO))] if ent_doc else [])
                 + ([str(RECIPIENTS.relative_to(REPO))] if rec_doc else []),
        "conops_reference": {"channels": "§2.1", "routes": "§2.3.2",
                             "classes": "§2.3.3",
                             "entitlements": "§3.1, §2.3.1, §3.4, §3.3",
                             "recipients": "§3.1, §3.1.1, §3.2, §3.3, §3.4.1"},
        "open_decisions_touched": {
            "OD-5": "OPEN. recipients.yaml builds the bearer-token branch "
                    "and labels every policy number "
                    "PROTOTYPE_DEFAULT_NOT_POLICY. Nothing here decides it.",
        },
        "counts": {"channels": len(channels), "routes": len(routes),
                   "gaps": len(rt_doc.get("gaps") or []),
                   "views": len((ent_doc or {}).get("views") or []),
                   "entitlement_shares": len((ent_doc or {}).get("shares") or []),
                   "recipients": len((rec_doc or {}).get("recipients") or []),
                   "checks": len(c.rows), "failed": len(failed)},
        "scope": "STATIC ONLY. This script compares the config files against "
                 "the CONOPS lists and against each other. It does not "
                 "contact the platform, so it cannot say what the metastore "
                 "holds -- scripts/24 does that for the entitlement model, "
                 "and a clean result here is not evidence of a correct live "
                 "state.",
        "checks": c.rows,
        "verdict": "CAC_CONFIG_CONSISTENT" if not failed
                   else "CAC_CONFIG_INCONSISTENT",
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(results, indent=2) + "\n")

    if not args.quiet:
        print("=" * 68)
        print("E1 Tasks 1.3 + 1.4 + 1.5 -- CaC config check (static)")
        print("=" * 68)
        for r in c.rows:
            if not r["ok"]:
                print(f"[FAIL] {r['check']}")
                if r["detail"]:
                    print(f"       {r['detail']}")
        print(f"\nchannels: {len(channels)}   routes: {len(routes)}   "
              f"gaps: {len(rt_doc.get('gaps') or [])}   "
              f"views: {len((ent_doc or {}).get('views') or [])}   "
              f"recipients: {len((rec_doc or {}).get('recipients') or [])}")
        print(f"checks:   {len(c.rows)}   failed: {len(failed)}")
        print(f"VERDICT:  {results['verdict']}")
        print(f"\nWrote {EVIDENCE.relative_to(REPO)}")

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
