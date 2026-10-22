#!/usr/bin/env python3
"""
B-32c: does a CHANGED view definition reach a live consumer?

E1 Task 1.4's remaining gap. `scripts/24` proved it can `ALTER VIEW ...
AS` a view that is already inside a share -- but `iac/config/
entitlements.yaml` was unchanged between the two runs that proved it, so
the definition `ALTER` wrote was identical to the definition already
stored. The run proved the STATEMENT is accepted. It did not prove a
CHANGE propagates, and a change is the only case AC6 / T-12 cares about:
nobody redeploys configuration in order to keep a view the same.

WHY THE PLAUSIBLE FAILURE IS SILENT
-----------------------------------
`scripts/24`'s rule 2b reads the PROVIDER's catalog. So an `ALTER` that
returned 200 while consumers continued to resolve the previous
definition would be reported `APPLIED` / `EXACT` by the applier and
`ROW_SCOPE_MEASURED` by its row rule, because every one of those checks
is looking at the side that definitely changed. §12.9's silent negative,
in the one place where the thing that cannot see is the thing doing the
reporting.

So this test reads from the CONSUMER side, as the recipient, through the
share -- and it reads the same number three times:

  phase 0   BEFORE   the predicate as shipped            expect 16
  phase 1   CHANGED  predicate widened, applied          expect MORE
  phase 2   RESTORED predicate put back, applied         expect 16 again

WHAT MAKES EACH PHASE NECESSARY, AND WHY TWO IS NOT ENOUGH
----------------------------------------------------------
Phase 0 and phase 1 alone would show the number moved. They would NOT
show the number moved BECAUSE of the change: a count read twice against
a live platform can differ for reasons that have nothing to do with the
definition, and "16 then 33" is equally consistent with a propagation
that works and with a count that is not stable. Phase 2 is what closes
that -- a number that goes 16 -> 33 -> 16 while the config goes
narrow -> wide -> narrow is tracking the config. B-40: a control that
does not move when the variable moves is not a control, and its mirror,
a reading that moves when nothing moved is not a measurement.

Phase 2 is also the restore. It runs in a `finally`, and the restore is
VERIFIED by re-reading, not assumed from an exit code (B-23). A test
that widens a live entitlement and exits on an exception has widened a
live entitlement.

WHAT THIS TEST DOES NOT DO
--------------------------
It does not re-implement the applier. `scripts/24_build_entitlement_
model.py` is invoked as a subprocess, because an `ALTER VIEW` written
here would be a second definition of how this repository changes a view,
and the two would diverge the first time one was fixed. B-39, which has
cost six defects in this repository. The consumer-side row counter is
imported from `tests/t04_column_denied.py` for the same reason -- it is
the function that already knows not to substitute a file count for a row
count, and not to write a pre-signed URL into an evidence file (B-15).

It also does not touch the column list. The widening is confined to the
row predicate because `select` is what T-04 measures, and a test that
moved both would not be able to say which one propagated.

Usage:
    python3 tests/b32c_change_propagation.py
    python3 tests/b32c_change_propagation.py --dry-run
"""

import argparse
import copy
import datetime
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from common import Report, load_env  # noqa: E402

CONFIG = ROOT / "iac" / "config" / "entitlements.yaml"
BACKUP = ROOT / "_secrets" / "entitlements.yaml.b32c-backup"
SECRETS = ROOT / "_secrets"
EVIDENCE = ROOT / "evidence" / "b32c-change-propagation.json"
APPLIER = ROOT / "scripts" / "24_build_entitlement_model.py"

RECIPIENT = "awoz1227-psp7-t2-us-recipient"
SHARE = "awoz1227-psp7-t2-us-share"
SCHEMA = "opensharing_test"
VIEW = "v_entitled_t2_us"

# The widening. Chosen from the data generator rather than invented:
# scripts/01_create_test_dataset.py assigns region by
# `element_at(array('us-east','us-west','us-central'), (id % 3) + 1)`
# over 50 rows, so the three regions are ~17/17/16 and admitting a
# second one must move the count by roughly a third of the table.
#
# NOT chosen: `region LIKE 'us-%'`, which selects every row. That is the
# trap the config's own `row_scope_note` already warns about -- a
# predicate that matches everything is indistinguishable from no
# predicate, so widening TO it would prove propagation while destroying
# the row scope this view exists to demonstrate. The widening has to be
# visible and still be a restriction.
NARROW_PREDICATE = "region = 'us-east'"
WIDE_PREDICATE = "region IN ('us-east', 'us-west')"

# The NARROWING direction, and the reason this test grew a --narrow mode.
#
# Widening and narrowing are not the same experiment with the sign
# flipped. The first run of this test WIDENED the predicate and found
# the consumer stale at 16 while the provider had moved to 33, for the
# full 600s budget. In that direction staleness is merely wrong: the
# consumer sees LESS than it is entitled to, which is an operational
# complaint.
#
# Narrowing is the direction the CONOPS depends on for security. §3.1's
# row scope is how an entitlement is REDUCED, and reducing an
# entitlement is what an operator does in response to a DSA change, a
# revocation, or an incident. If a narrowed predicate does not reach the
# consumer, the consumer keeps reading rows that have just been taken
# out of scope -- and the provider's own catalog reports the narrow
# definition, so every provider-side check says the change is in force.
#
# That is the same inversion this repository keeps finding, in the one
# place where it is a disclosure rather than a reporting error: the
# control reports applied, and the data is still going out.
#
# So the narrowing direction gets its own run and its own evidence.
# 8 rows from 16 -- a clean halving the synthetic data can discriminate
# (counted, not assumed: scripts/01 assigns region by id % 3, and
# record_id is bigint).
NARROWED_PREDICATE = "region = 'us-east' AND record_id % 2 = 0"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def load_t04():
    """Import T-04's consumer-side reader rather than copying it."""
    spec = importlib.util.spec_from_file_location(
        "t04_for_b32c", ROOT / "tests" / "t04_column_denied.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["t04_for_b32c"] = mod
    spec.loader.exec_module(mod)
    for fn in ("count_rows_from_query", "sharing_get"):
        if not hasattr(mod, fn):
            sys.exit(
                f"tests/t04_column_denied.py no longer exports `{fn}`. "
                "This test reads the consumer side through T-04's reader "
                "deliberately -- that function already knows not to "
                "substitute a file-action count for a row count and not "
                "to write a pre-signed URL into evidence (B-15). "
                "Re-pointing it at a local copy would be B-39 a seventh "
                "time. Fix the import, do not reimplement the reader.")
    return mod


def read_predicate(cfg):
    for v in cfg.get("views", []):
        if v.get("id") == VIEW:
            return v.get("where")
    sys.exit(f"No view with id {VIEW} in {CONFIG.relative_to(ROOT)}.")


def set_predicate(cfg, predicate):
    out = copy.deepcopy(cfg)
    for v in out.get("views", []):
        if v.get("id") == VIEW:
            v["where"] = predicate
            return out
    sys.exit("unreachable: view vanished between read and write")


def write_config(cfg):
    CONFIG.write_text(yaml.safe_dump(cfg, sort_keys=False, width=100,
                                     default_flow_style=False))


def apply_model(label):
    """Run the applier. Returns (returncode, tail-of-output)."""
    proc = subprocess.run(
        [sys.executable, str(APPLIER)], cwd=str(ROOT),
        capture_output=True, text=True, timeout=900)
    tail = "\n".join((proc.stdout or "").strip().splitlines()[-6:])
    return proc.returncode, tail, (proc.stderr or "")[-600:]


def provider_count():
    """Read the row count the applier just measured, provider-side.

    Recorded alongside the consumer count in every phase, because the
    whole point of B-32c is that these two can disagree. A test that
    recorded only the consumer number could not show the disagreement it
    exists to rule out.
    """
    model = ROOT / "evidence" / "entitlement-model.json"
    if not model.exists():
        return None
    # Walk for the view's own row_count rather than pattern-matching a
    # number out of the file text: two views are measured and both counts
    # appear, so a regex would be a coin toss.
    data = json.loads(model.read_text())

    def walk(node):
        if isinstance(node, dict):
            if node.get("view") == VIEW and isinstance(
                    node.get("row_count"), int):
                return node["row_count"]
            for key, val in node.items():
                if key == VIEW and isinstance(val, dict) and isinstance(
                        val.get("row_count"), int):
                    return val["row_count"]
                got = walk(val)
                if got is not None:
                    return got
        elif isinstance(node, list):
            for item in node:
                got = walk(item)
                if got is not None:
                    return got
        return None

    return walk(data)


def consumer_count(t04, endpoint, bearer, label):
    res = t04.count_rows_from_query(endpoint, bearer, SHARE, SCHEMA, VIEW)
    return {
        "label": label,
        "verdict": res.get("verdict"),
        "rows_counted": res.get("rows_counted"),
        "file_actions": res.get("file_actions"),
        "file_actions_without_numrecords": res.get(
            "file_actions_without_numrecords"),
        "cannot_see_because": res.get("cannot_see_because"),
        "read_by": "tests/t04_column_denied.py::count_rows_from_query",
    }


def poll_consumer(t04, endpoint, bearer, name, differ_from, budget, interval):
    """Read the consumer side repeatedly until the count leaves `differ_from`.

    The first version of this test read the consumer side ONCE, straight
    after the applier returned, and recorded 16 against a provider-side 33.
    Read that way the result is unreadable: "the change never reaches the
    consumer" and "the change reaches the consumer in four minutes" produce
    the identical single sample, and T-19 has already measured a
    newly-shared object taking more than 170.8s to become visible. So a
    single immediate read cannot tell a defect from a latency, which is this
    repository's recurring defect shape applied to its own test.

    So: poll. `differ_from` is the count this phase must move AWAY from --
    phase 0's baseline for the widening, and the widened count for the
    restore. Returning the elapsed time matters as much as the count: a
    change that arrives is an operational latency figure the CONOPS needs,
    and one that never arrives within the budget is a floor, stated as a
    floor, not as "never".
    """
    started = time.monotonic()
    samples = []
    while True:
        elapsed = round(time.monotonic() - started, 1)
        got = consumer_count(t04, endpoint, bearer, f"{name}@{elapsed}s")
        got["elapsed_s"] = elapsed
        samples.append(got)
        count = got.get("rows_counted")
        moved = (differ_from is None
                 or (isinstance(count, int) and count != differ_from))
        print(f"    t+{elapsed:>6.1f}s  consumer={count}  "
              f"({got.get('verdict')})"
              + ("  <- moved" if moved and differ_from is not None else ""))
        if moved:
            return samples, True, elapsed
        if time.monotonic() - started + interval > budget:
            return samples, False, round(time.monotonic() - started, 1)
        time.sleep(interval)


def phase(t04, endpoint, bearer, name, predicate, cfg_base, expect,
          differ_from=None, budget=0.0, interval=30.0, direction=None):
    """Set the predicate, apply, then read both sides.

    There is deliberately no dry-run path through this function. --dry-run
    returns in main() before the backup is even taken, so a phase that
    could be entered and skipped would be a branch that writes nothing
    while reporting a phase ran -- the shape of the silent negative this
    whole test exists to close.

    `name` is the evidence KEY and `direction` is what actually happened to
    the predicate. They are separate arguments because the key "1_widened"
    is now a legacy name: it was minted when this test only widened, and the
    verdict ladder reads phases by that key. Renaming it would have been a
    cosmetic change that silently broke the ladder, so the key stays and the
    truth is carried in `direction` -- which is also why the printed banner
    reads from `direction` and not from the key. A label that disagrees with
    the measurement under it is this repository's seventh inversion, and for
    one run of this test the banner really did print WIDENED over a
    narrowing measurement.
    """
    out = {"phase": name, "predicate": predicate, "expectation": expect}
    if direction:
        out["direction"] = direction
        out["evidence_key_is_legacy"] = (
            f"key {name!r} predates --narrow; the direction actually "
            f"applied in this run was {direction!r}")
    write_config(set_predicate(cfg_base, predicate))
    rc, tail, err = apply_model(name)
    out["applier_returncode"] = rc
    out["applier_tail"] = tail
    if err.strip():
        out["applier_stderr_tail"] = err
    out["provider_side_row_count"] = provider_count()
    samples, moved, elapsed = poll_consumer(
        t04, endpoint, bearer, name, differ_from, budget, interval)
    out["consumer_samples"] = samples
    out["consumer_side"] = samples[-1]
    out["consumer_row_count"] = samples[-1].get("rows_counted")
    out["consumer_polled_for_s"] = elapsed
    out["consumer_poll_budget_s"] = budget
    if differ_from is not None:
        out["expected_to_differ_from"] = differ_from
        out["consumer_moved"] = moved
        out["consumer_moved_after_s"] = elapsed if moved else None
        out["consumer_did_not_move_within_s"] = None if moved else elapsed
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poll-budget", type=float, default=600.0,
                    help="seconds to wait for a consumer-side count to "
                         "move before calling it a floor (default 600)")
    ap.add_argument("--poll-interval", type=float, default=30.0,
                    help="seconds between consumer reads (default 30)")
    ap.add_argument("--narrow", action="store_true",
                    help="change the predicate in the NARROWING "
                         "direction (the security-relevant one) instead "
                         "of widening it")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and touch nothing")
    args = ap.parse_args()

    load_env()
    t04 = load_t04()

    cred_path = SECRETS / f"credential-{RECIPIENT}.json"
    if not cred_path.exists():
        sys.exit(
            f"Missing {cred_path.relative_to(ROOT)}.\n"
            "This test reads AS THE RECIPIENT -- that is the entire "
            "point, since the provider side is what already reports "
            "success. Run:\n"
            f"  python3 scripts/28_activate_credential.py --recipient "
            f"{RECIPIENT} --activate --also-rewrite")
    cred = json.loads(cred_path.read_text())
    endpoint, bearer = cred.get("endpoint"), cred.get("bearerToken")
    if not endpoint or not bearer:
        sys.exit(f"{cred_path.relative_to(ROOT)} is not a usable profile.")

    cfg = yaml.safe_load(CONFIG.read_text())
    shipped = read_predicate(cfg)

    # Direction decides the predicate AND how the result is read. A
    # single "the count moved" ladder cannot serve both: a drop is the
    # expected outcome when narrowing and a defect when widening, so a
    # direction-blind verdict would call one of the two runs a failure
    # whichever way the platform behaved.
    direction = "narrowing" if args.narrow else "widening"
    changed_predicate = NARROWED_PREDICATE if args.narrow \
        else WIDE_PREDICATE
    evidence_path = (EVIDENCE.with_name("b32c-change-propagation-narrow.json")
                     if args.narrow else EVIDENCE)
    report_path = (ROOT / "evidence" / "b32c-narrow-report.json"
                   if args.narrow else ROOT / "evidence" / "b32c-report.json")

    print("=" * 70)
    print("B-32c: does a CHANGED view definition reach a live consumer?")
    print("=" * 70)
    print(f"view        : {SCHEMA}.{VIEW}")
    print(f"share       : {SHARE}")
    print(f"recipient   : {RECIPIENT}  (expires {cred.get('expirationTime')})")
    print(f"as shipped  : {shipped!r}")
    print(f"direction   : {direction.upper()}"
          + ("   <- the security-relevant direction" if args.narrow else ""))
    print(f"changed to  : {changed_predicate!r}")
    print(f"applier     : {APPLIER.relative_to(ROOT)}  (subprocess, not "
          f"reimplemented)")
    print()

    if shipped != NARROW_PREDICATE:
        print(f"NOTE: the shipped predicate is {shipped!r}, not the "
              f"{NARROW_PREDICATE!r} this test was written against. "
              f"Restoring to the SHIPPED value, not to the constant -- a "
              f"test that restored to its own idea of the right value "
              f"would silently revert somebody's deliberate change "
              f"(B-19).")
        print()

    if args.dry_run:
        print("--dry-run: three phases planned, nothing written.")
        print(f"  phase 0  narrow  {shipped!r}")
        print(f"  phase 1  {direction[:6]:6s}  {changed_predicate!r}")
        print(f"  phase 2  restore {shipped!r}")
        return 0

    # The config is backed up to _secrets/ (gitignored) before the first
    # write. The finally block restores from the FILE, not from the
    # in-memory object, so a crash between the write and the restore
    # still has a source of truth on disk.
    SECRETS.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CONFIG, BACKUP)
    # copy2 preserves the SOURCE's mode, and the source is a tracked
    # config file at 0664. Anything landing in _secrets/ must be 0600, so
    # without this chmod the backup inherits a world-readable mode and
    # running this test leaves the repository FAILING its own secret
    # hygiene gate -- which is exactly what happened, and the gate is the
    # only reason anybody found out. Note which way that cuts: the gate
    # was right, the test was wrong, and the fix belongs here rather than
    # in a gate exemption. An exemption added so a local run would pass
    # is a candidate for having disabled the thing it was meant to
    # observe (B-47).
    BACKUP.chmod(0o600)
    print(f"config backed up -> {BACKUP.relative_to(ROOT)}  [gitignored, 0600]")

    phases = {}
    restored = False
    try:
        print("\n--- phase 0: the predicate as shipped")
        p0 = phase(t04, endpoint, bearer, "0_as_shipped", shipped, cfg,
                   "the baseline count; whatever it is, phase 2 must "
                   "return to it")
        phases["0_as_shipped"] = p0
        print(f"  provider {p0['provider_side_row_count']}  consumer "
              f"{p0['consumer_row_count']}  "
              f"({p0['consumer_side']['verdict']})")

        print(f"\n--- phase 1: the predicate {direction.upper()}")
        p1 = phase(t04, endpoint, bearer, "1_widened", changed_predicate,
                   cfg,
                   ("the consumer count must DROP. A provider count that "
                    "drops while the consumer count does not means rows "
                    "removed from entitlement are STILL READABLE by the "
                    "recipient -- a disclosure, not a staleness bug."
                    if args.narrow else
                    "the consumer count must INCREASE. A provider count "
                    "that moves while the consumer count does not is "
                    "B-32c confirmed as a real defect."),
                   differ_from=p0["consumer_row_count"],
                   budget=args.poll_budget, interval=args.poll_interval,
                   direction=direction)
        phases["1_widened"] = p1
        print(f"  provider {p1['provider_side_row_count']}  consumer "
              f"{p1['consumer_row_count']}  "
              f"({p1['consumer_side']['verdict']})")

        print("\n--- phase 2: RESTORED (also the restore)")
        p2 = phase(t04, endpoint, bearer, "2_restored", shipped, cfg,
                   "the consumer count must return to phase 0's. This is "
                   "what shows the count tracks the config rather than "
                   "drifting.",
                   # Only poll if phase 1 actually moved. If it did not,
                   # there is nothing for phase 2 to move BACK from, and a
                   # poll would spend the whole budget waiting for a change
                   # that must not happen -- then report "did not move" as
                   # though that were the failure, when it is the correct
                   # outcome. The guard is the difference between a restore
                   # check and a second copy of phase 1's question.
                   differ_from=(p1["consumer_row_count"]
                                if p1.get("consumer_moved") else None),
                   budget=args.poll_budget, interval=args.poll_interval)
        phases["2_restored"] = p2
        restored = (p2.get("applier_returncode") == 0)
        print(f"  provider {p2['provider_side_row_count']}  consumer "
              f"{p2['consumer_row_count']}  "
              f"({p2['consumer_side']['verdict']})")
    finally:
        # Restore the FILE unconditionally. Phase 2 restored the
        # PLATFORM; this restores the config text, including any comments
        # yaml.safe_dump would have dropped -- which is most of this
        # repository's reasoning.
        if BACKUP.exists():
            shutil.copy2(BACKUP, CONFIG)
            print(f"\n[restore] {CONFIG.relative_to(ROOT)} restored from "
                  f"backup (comments intact)")
            if not restored:
                print("[restore] phase 2 did not complete, so the LIVE "
                      "view may still be widened. Re-running the applier "
                      "now, from the restored config.")
                rc, tail, _ = apply_model("emergency_restore")
                phases["emergency_restore"] = {
                    "applier_returncode": rc, "applier_tail": tail}
                print(f"[restore] applier rc={rc}")

    # --- the verdict ---------------------------------------------------
    c0 = phases.get("0_as_shipped", {}).get("consumer_row_count")
    c1 = phases.get("1_widened", {}).get("consumer_row_count")
    c2 = phases.get("2_restored", {}).get("consumer_row_count")
    p0v = phases.get("0_as_shipped", {}).get("provider_side_row_count")
    p1v = phases.get("1_widened", {}).get("provider_side_row_count")

    unreadable = [n for n, v in (("0", c0), ("1", c1), ("2", c2))
                  if not isinstance(v, int)]

    # How long each phase waited, and whether the move arrived. These are
    # what separate "does not propagate" from "propagates in N seconds" --
    # the distinction the first run of this test could not make, because it
    # read once and recorded 16 against a provider-side 33.
    waited_1 = phases.get("1_widened", {}).get("consumer_polled_for_s")
    moved_1 = phases.get("1_widened", {}).get("consumer_moved")
    budget_1 = phases.get("1_widened", {}).get("consumer_poll_budget_s")
    provider_moved = (isinstance(p1v, int) and isinstance(p0v, int)
                      and p1v != p0v)

    # Which way the count was SUPPOSED to go, checked against the
    # provider's own two counts rather than against the direction flag
    # alone. If the applier did not actually change the stored
    # definition, the flag would still say "narrowing" and the ladder
    # would be grading a no-op against an expectation nothing attempted.
    provider_went_down = (isinstance(p0v, int) and isinstance(p1v, int)
                          and p1v < p0v)
    wrong_way = ((args.narrow and not provider_went_down)
                 or (not args.narrow and provider_went_down))

    if unreadable:
        verdict = "CANNOT_SEE_CONSUMER_COUNT_UNREADABLE_IN_SOME_PHASE"
    elif provider_moved and wrong_way:
        verdict = "CANNOT_SEE_PROVIDER_MOVED_THE_WRONG_WAY_FOR_THIS_MODE"
    elif c1 == c0:
        if provider_moved:
            # The defect B-32c predicted. Stated as a FLOOR, with the wait
            # in the label: this run did not see it propagate within the
            # budget, which is not the same sentence as "it never does".
            # B-46 -- a verdict must not claim more than it measured.
            #
            # The NARROWING label names the CONSEQUENCE ("revoked rows
            # still readable") rather than the mechanism ("did not
            # propagate"), because the consequence is the finding. A
            # verdict a reader has to translate into a disclosure before
            # they can act on it is a verdict that gets filed as a
            # latency note.
            verdict = (
                ("B32C_NARROWING_DID_NOT_REACH_THE_CONSUMER_"
                 f"REVOKED_ROWS_STILL_READABLE_AFTER_{int(budget_1 or 0)}S")
                if args.narrow else
                ("B32C_CONFIRMED_PROVIDER_MOVED_CONSUMER_DID_NOT_"
                 f"WITHIN_{int(budget_1 or 0)}S"))
        else:
            verdict = "CANNOT_SEE_NEITHER_SIDE_MOVED_CHANGE_NOT_APPLIED"
    elif (c1 < c0) != bool(args.narrow):
        verdict = ("UNEXPECTED_CONSUMER_COUNT_MOVED_AGAINST_THE_CHANGE_"
                   + direction.upper())
    elif c2 != c0:
        verdict = "PROPAGATION_SHOWN_BUT_RESTORE_DID_NOT_RETURN_THE_COUNT"
    elif moved_1 and isinstance(waited_1, (int, float)) and waited_1 > 0:
        # It propagated, but not immediately. That is a pass AND an
        # operational number the CONOPS needs, so the number goes in the
        # verdict rather than into prose underneath it, where it would be
        # read as a caveat on a clean pass instead of as the finding.
        verdict = ("CHANGED_DEFINITION_PROPAGATES_TO_THE_LIVE_CONSUMER_"
                   f"AFTER_{int(waited_1)}S")
    else:
        verdict = "CHANGED_DEFINITION_PROPAGATES_TO_THE_LIVE_CONSUMER"

    passed = verdict.startswith(
        "CHANGED_DEFINITION_PROPAGATES_TO_THE_LIVE_CONSUMER")

    ev = {
        "finding": "B-32c",
        "test": "B-32c change propagation",
        "epic_task": "E1 Task 1.4 (remaining gap)",
        "ac": "AC6 / T-12 -- redeploy the configuration from code",
        "at": now(),
        "subject": {"view": f"{SCHEMA}.{VIEW}", "share": SHARE,
                    "recipient": RECIPIENT,
                    "credential_expires": cred.get("expirationTime"),
                    "shipped_predicate": shipped,
                    "direction": direction,
                    "changed_predicate": changed_predicate},
        "counts": {"phase_0_consumer": c0, "phase_1_consumer": c1,
                   "phase_2_consumer": c2,
                   "phase_0_provider": p0v, "phase_1_provider": p1v},
        "phases": phases,
        "verdict": verdict,
        "what_this_closes": (
            "B-32c as stated in docs/11 §11.7: 'the run proves the "
            "STATEMENT is accepted on a shared view; it does not prove "
            "that a CHANGED definition propagates to a live share.' It "
            "now does, read from the consumer side, with the count "
            "returning to its starting value when the config does."
            if passed else
            "Nothing. B-32c stays open with this verdict attached."),
        "why_three_phases": (
            "Two phases would show the number moved, not that it moved "
            "BECAUSE of the change. A count read twice against a live "
            "platform can differ for uninteresting reasons. 16 -> 33 -> "
            "16 against narrow -> wide -> narrow is tracking the config; "
            "16 -> 33 alone is not."),
        "what_this_does_not_prove": {
            "propagation_latency": (
                "RETRACTED AND REPLACED (B-19, in place). The first "
                "version of this entry said the consumer read happens "
                "immediately after the applier returns, and treated that "
                "as showing propagation was 'fast enough to be invisible'. "
                "That was written before the first run, and the first run "
                "contradicted it: the consumer count did NOT move "
                "immediately. A single immediate read cannot tell a "
                "propagation delay from a propagation failure -- it "
                "returns the same number for both -- so the test now "
                "polls and reports the wait. What is still NOT bounded "
                "above is the general case: this measures ONE view on ONE "
                "free-tier metastore. T-19's >170.8s was a newly SHARED "
                "OBJECT, a different operation from a changed DEFINITION "
                "on an already-shared one, and v1.6 should not generalise "
                "either number to the other."),
            "the_mechanism_of_the_delay": (
                "Not identified. A wait that ends is consistent with "
                "several causes -- a cached share manifest, the "
                "provider-side view not being re-resolved until the next "
                "query plan, a CDN or metadata TTL in front of the "
                "sharing endpoint -- and this test distinguishes none of "
                "them. It measures that the change arrives and roughly "
                "when, which is what the access matrix needs; naming the "
                "cause would need provider-side instrumentation the free "
                "tier does not expose."),
            "column_changes": (
                "Only the row predicate moved. A changed `select` list is "
                "the other half of the model and is untested for "
                "propagation -- deliberately, because moving both at "
                "once would leave the test unable to say which one "
                "propagated."),
            "scale": (
                "One view, 50 rows, one parquet file. The counts come "
                "from file statistics, so a view large enough to span "
                "many files exercises a code path this run does not."),
            "t12": (
                "Still NOT_RUN. This shows a CHANGE reaching a consumer "
                "on a live metastore; it says nothing about building the "
                "model on a CLEAN target, which is what AC6 asks and "
                "what this topology has no way to provide."),
        },
    }
    evidence_path.write_text(json.dumps(ev, indent=2))

    rep = Report()
    rep.record(
        "B-32c" + ("-narrow" if args.narrow else ""),
        ("A NARROWED view definition reaches the live consumer "
         "(the security-relevant direction)" if args.narrow else
         "A changed view definition reaches the live consumer"),
        ("the consumer-side row count DROPPING when the row predicate is "
         "narrowed, which is what makes a reduced entitlement effective, "
         "and returning when the predicate is put back"
         if args.narrow else
         "the consumer-side row count moving when the row predicate is "
         "widened, and returning to its original value when the predicate "
         "is put back -- three reads through the share, one variable"),
        verdict, passed, str(evidence_path.relative_to(ROOT)))
    rep.write(report_path)

    print()
    print(f"counts (consumer): {c0} -> {c1} -> {c2}")
    print(f"counts (provider): {p0v} -> {p1v}")
    print(f"VERDICT: {verdict}")
    print(rep.summary())
    print(f"Wrote {evidence_path.relative_to(ROOT)}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
