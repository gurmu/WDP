#!/usr/bin/env python3
"""What makes a newly shared object appear in the consumer's catalog:
TIME, or a consumer-side PROVIDER UPDATE?

WHY THIS EXISTS
---------------
T-19's Part 4 produced two readings in one run that look like a single
finding and are not:

  carry_forward_prior_probe  STANDING_OBJECT_NOW_READABLE_CATALOG_DOES_REFRESH
                             age=7.7h, OBJECT_ADDED_AFTER_CATALOG_CREATED
  object_visibility          NOT_VISIBLE_WITHIN_BOUND after 170.8s / 12 polls
  object_metadata_check      ABSENT_FROM_CONSUMER_METADATA
                             tables=['t19_refresh_probe', 'test_dataset']

Read together they exclude the snapshot-at-create hypothesis outright.
The standing object was added to the share AFTER this catalog was
created -- that ordering is measured from the share's added_at against
the catalog's created_at, not assumed -- and it is readable now, through
a catalog that has never been dropped. So the consumer's object list is
not frozen at CREATE CATALOG time, and §2.4.1 does NOT need a
re-import step on that account.

They also exclude warehouse-side caching, which is the explanation a
reviewer reaches for first. The tables API is a control-plane read with
no warehouse in the path, and it reported the new object ABSENT while
listing the old one. The object genuinely is not in the consumer's
metadata yet. Nothing a consumer does to its SQL warehouse will change
that.

What they do NOT distinguish is the thing a runbook has to say:

  (a) TIME. Propagation is slower than ~171s and faster than ~7.7h.
      The consumer waits, and §2.4.1 carries a timing expectation.
  (b) A CONSUMER-SIDE TRIGGER. The object list refreshes when the
      consumer updates the provider, and otherwise does not. §2.4.1
      step 5 then needs an explicit action after the provider adds an
      object, and a consumer who waits instead waits forever.

The run cannot tell them apart, and the reason is a confound in our own
test rather than anything about the platform. T-19's Part 2 PATCHes the
provider with the current credential on EVERY run. In the run above
that PATCH happened before Part 4, the standing object had been in the
share since the previous run -- so it was present at the moment of the
update -- and the new probe was added after it. Both hypotheses predict
exactly what was observed. A refresh figure quoted from that run would
be a guess with a decimal point on it.

HOW THIS SETTLES IT
-------------------
The probe object T-19 deliberately left in the share is the instrument,
and it is used in the only order that works, because the destructive
step destroys the observation:

  Phase 1  Read it now, no mutation at all. If it is already visible,
           time alone did it -- there has been no consumer-side action
           since it was added -- and the answer is (a) with a bound.
  Phase 2  Keep reading, still touching nothing, for the watch window.
           Appearance here is again (a), with a tighter bound.
  Phase 3  Only if it is still absent: ONE mutation, the provider
           update, then read again. Appearance within seconds of an
           update that nothing else accompanied is (b).

Phase 3 is an asymmetry argument, not a proof, and the write-up says so.
A timer that fires during the post-update read would be indistinguish-
able from a trigger. What makes the inference worth recording is the
ratio: absent across the whole watch window, present seconds after the
one action taken. The watch window is reported with the verdict so a
reader can judge the ratio instead of taking the label on trust.

The subject is READ from evidence/t19-ingress-d2d.json, never named
here. If this file retyped the probe table name, it would measure a
table T-19 did not leave behind the first time the two disagreed.
"""

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
T19 = REPO / "evidence" / "t19-ingress-d2d.json"
EVIDENCE = REPO / "evidence" / "t19-refresh-trigger.json"
CREDENTIAL = REPO / "_secrets" / "glovashu-d2o-credential.json"

UC = "/api/2.1/unity-catalog"
TAG = "awoz1227_t19"
SUB_SHARE = f"{TAG}_sub_share"
PROVIDER_NAME = f"{TAG}_glovashu_provider"
CATALOG_NAME = f"{TAG}_glovashu_catalog"


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this probe reuses its helpers rather "
                 f"than restating them.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "p21_probe14")
P19 = load_probe("19_probe_token_path_same_pair.py", "p21_probe19")
call = P14.call
run_sql = P19.run_sql
find_warehouse = P19.find_warehouse


def now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


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


def subject():
    """Read the instrument out of T-19's record.

    Every exit here names what is missing and what to run, because
    "no probe object" and "the probe object is not visible" are
    opposite findings and a bare failure would read as the second.
    """
    if not T19.exists():
        sys.exit(f"Missing {T19.relative_to(REPO)}. Run "
                 f"tests/t19_ingress_d2d.py first; this probe measures "
                 f"the object that test leaves behind.")
    doc = json.loads(T19.read_text())
    p4 = doc.get("part4_refresh") or {}
    steps = p4.get("steps") or {}
    add = steps.get("add_to_share") or {}
    obj = add.get("object")
    if not obj:
        sys.exit("T-19's part4_refresh has no add_to_share.object. That "
                 "field is written by the current version of the test; "
                 "an older evidence file means the run you are pointing "
                 "at did not verify share membership at all, so its "
                 "probe object is unknown. Re-run T-19.")
    if not add.get("membership_new"):
        sys.exit(f"T-19 recorded membership_new=False for {obj}: it was "
                 f"already in the share before that run's ADD. There is "
                 f"no known moment of addition to measure from. Re-run "
                 f"T-19 to create a fresh probe.")
    vis = (steps.get("object_visibility") or {}).get("verdict")
    if vis != "NOT_VISIBLE_WITHIN_BOUND":
        sys.exit(f"T-19 recorded object_visibility={vis}. This probe "
                 f"only has a question to answer when the object did "
                 f"NOT appear within the test's bound -- if it appeared, "
                 f"the latency is already measured and there is nothing "
                 f"here to discriminate.")
    cleanup = (steps.get("probe_cleanup") or {}).get("verdict")
    if cleanup not in (None, "PROBE_LEFT_DELIBERATELY"):
        sys.exit(f"T-19 recorded probe_cleanup={cleanup}, so the probe "
                 f"object was removed from the share and cannot be "
                 f"re-read. Re-run T-19.")
    return {
        "object": obj,
        "shared_schema": (doc.get("part2_substitute_ingress") or {})
        .get("shared_schema"),
        "t19_date": doc.get("date"),
        # The OBSERVED absence, not the bound it was polled against.
        # 180s is what T-19 was willing to wait; 170.8s is what it
        # actually watched, and quoting the first as evidence would
        # claim 9 seconds nobody measured.
        "t19_absent_seconds": (steps.get("object_visibility") or {})
        .get("latency_seconds"),
        "t19_bound_seconds": (steps.get("object_visibility") or {})
        .get("bound_seconds"),
        "t19_polls": (steps.get("object_visibility") or {}).get("polls"),
        "t19_carry_forward": (steps.get("carry_forward_prior_probe") or {})
        .get("verdict"),
    }


def in_metadata(s, schema, leaf):
    """Control-plane view: is the object in the consumer's catalog?

    Used for the polling loop in preference to a SELECT because it has
    no warehouse in the path. A warehouse that is asleep adds a minute
    of start-up to a latency figure that is supposed to be about
    sharing, and that minute would be indistinguishable from
    propagation.
    """
    status, payload = call(
        s["p_host"], s["p_token"],
        f"{UC}/tables?catalog_name={CATALOG_NAME}&schema_name={schema}")
    listed = [t.get("name") for t in ((payload or {}).get("tables") or [])]
    return status, listed, leaf in listed


def added_at(s, leaf):
    status, payload = call(
        s["g_host"], s["g_token"],
        f"{UC}/shares/{SUB_SHARE}?include_shared_data=true")
    for obj in ((payload or {}).get("objects") or []):
        if str(obj.get("name", "")).split(".")[-1] == leaf:
            return status, obj.get("added_at")
    return status, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch-seconds", type=int, default=900,
                    help="no-touch observation window (default 900)")
    ap.add_argument("--poll-interval", type=int, default=30)
    ap.add_argument("--skip-watch", action="store_true",
                    help="go straight to the provider update; only "
                         "honest if a real wait already happened and is "
                         "recorded elsewhere")
    args = ap.parse_args()

    print("Probe 21 -- what triggers consumer-side object refresh")
    print("=" * 68)
    s = sides()
    subj = subject()
    leaf, schema = subj["object"], subj["shared_schema"]
    print(f"Subject (read from T-19): {leaf}")
    print(f"T-19 saw it absent after {subj['t19_absent_seconds']}s / "
          f"{subj['t19_polls']} poll(s) "
          f"(bound was {subj['t19_bound_seconds']}s)")
    print(f"T-19 carry-forward:       {subj['t19_carry_forward']}")

    res = {
        "probe": "21",
        "question": ("Does a newly shared object appear in the "
                     "consumer's catalog through the passage of TIME, "
                     "or through a consumer-side PROVIDER UPDATE?"),
        "date": now(),
        "subject": subj,
        "watch_seconds": args.watch_seconds,
        "poll_interval_seconds": args.poll_interval,
        "excluded_before_this_probe": {
            "snapshot_at_catalog_create": (
                "Excluded by T-19's carry_forward_prior_probe: an object "
                "added AFTER this catalog was created is readable "
                "through it, with the ordering measured from "
                "share.added_at against catalog.created_at."),
            "warehouse_side_caching": (
                "Excluded by T-19's object_metadata_check: the tables "
                "API, which has no warehouse in the path, reported the "
                "object absent from the consumer's metadata while "
                "listing an older one."),
        },
        "steps": {},
    }

    # B-19, and it bites harder here than in T-19. This file is
    # overwritten every run, and a RE-RUN IS STRICTLY WORSE than the
    # first one: the object keeps ageing, so the second run's upper
    # bound is looser than the first's, and the first was the tight
    # one. Without carry-forward, fixing a defect in this probe and
    # re-running it would destroy the best measurement in the repo and
    # replace it with a weaker number bearing the same name.
    prior = []
    if EVIDENCE.exists():
        try:
            old = json.loads(EVIDENCE.read_text())
            prior = (old.get("prior_runs") or [])[-5:]
            ob = (old.get("steps", {}).get("bounds") or {})
            prior.append({
                "date": old.get("date"),
                "object": (old.get("subject") or {}).get("object"),
                "verdict": old.get("verdict"),
                "lower_bound_seconds": ob.get("lower_bound_seconds"),
                "upper_bound_seconds": ob.get("upper_bound_seconds"),
                "unmeasured_gap_seconds": ob.get("unmeasured_gap_seconds"),
                "age_minutes_at_read": (old.get("steps", {})
                                        .get("share_membership", {})
                                        .get("age_minutes")),
            })
        except (ValueError, OSError) as exc:
            prior = [{"carry_forward_error": str(exc),
                      "means": ("Previous probe evidence unreadable, so "
                                "earlier bounds are NOT carried "
                                "forward. An error, not an empty "
                                "history.")}]
    res["prior_runs"] = prior
    if prior:
        print(f"Prior runs carried forward: {len(prior)}")

    astatus, added = added_at(s, leaf)
    age = (round((time.time() * 1000 - int(added)) / 60000, 1)
           if added else None)
    res["steps"]["share_membership"] = {
        "status": astatus,
        "added_at": added,
        "age_minutes": age,
        "verdict": "IN_SHARE" if added else "NOT_IN_SHARE_OR_NO_TIMESTAMP",
        "means": ("The object must still be in the share for any read "
                  "below to mean anything. No timestamp means the age "
                  "figures are unavailable, not zero."),
    }
    print(f"    [{'ok ' if added else 'REF'}] share_membership: "
          f"{res['steps']['share_membership']['verdict']} "
          f"(age={age} min)")
    if not added:
        res["verdict"] = "NOT_RUN_SUBJECT_NOT_IN_SHARE"
        res["means"] = ("The probe object is no longer in the share, so "
                        "its absence from the consumer says nothing "
                        "about refresh. NOT_RUN, not a negative.")
        EVIDENCE.write_text(json.dumps(res, indent=2, default=str))
        print(f"\nVERDICT: {res['verdict']}")
        return

    # --- phase 1: read it now, touch nothing --------------------------
    mstatus, listed, present = in_metadata(s, schema, leaf)
    res["steps"]["phase1_control_read"] = {
        "status": mstatus,
        "tables_listed": listed,
        "present": present,
        "verdict": "PRESENT" if present else "ABSENT",
        "means": ("No mutation has been performed by this probe and, "
                  "per T-19's record, none has been performed by "
                  "anything else since the object was added. PRESENT "
                  "here means time alone did it."),
    }
    print(f"    [{'ok ' if present else '---'}] phase1_control_read: "
          f"{'PRESENT' if present else 'ABSENT'} (tables={listed})")

    appeared_at = None
    polls = 0
    found_wall = time.time() if present else None
    if present:
        appeared_at = 0.0
        res["steps"]["phase2_watch"] = {
            "verdict": "NOT_RUN_ALREADY_PRESENT",
            "means": "Nothing to wait for."}
    elif args.skip_watch:
        res["steps"]["phase2_watch"] = {
            "verdict": "SKIPPED_BY_FLAG",
            "means": ("--skip-watch was passed, so this run did NOT "
                      "observe a no-touch window. Phase 3's asymmetry "
                      "argument depends on that window; without it, an "
                      "appearance after the update is NOT attributable "
                      "to the update. Any conclusion below is weaker "
                      "than the label suggests and says so."),
        }
        print("    [---] phase2_watch: SKIPPED_BY_FLAG "
              "(weakens phase 3 -- see evidence)")
    else:
        # --- phase 2: keep watching, still touching nothing -----------
        t0 = time.time()
        deadline = t0 + args.watch_seconds
        trail = []
        while True:
            polls += 1
            mstatus, listed, present = in_metadata(s, schema, leaf)
            trail.append({"t": round(time.time() - t0, 1),
                          "present": present, "status": mstatus})
            if present:
                appeared_at = round(time.time() - t0, 1)
                found_wall = time.time()
                break
            if time.time() + args.poll_interval > deadline:
                break
            time.sleep(args.poll_interval)
            print(f"          watching... {round(time.time() - t0)}s / "
                  f"{args.watch_seconds}s", end="\r", flush=True)
        elapsed = round(time.time() - t0, 1)
        res["steps"]["phase2_watch"] = {
            "polls": polls,
            "elapsed_seconds": elapsed,
            "window_seconds": args.watch_seconds,
            "appeared_after_seconds": appeared_at,
            "trail": trail,
            "verdict": ("APPEARED_WITHOUT_CONSUMER_ACTION" if present
                        else "ABSENT_THROUGHOUT_WINDOW"),
            "means": ("A bounded observation with ZERO mutations. "
                      "ABSENT_THROUGHOUT_WINDOW is a bounded negative "
                      f"({elapsed}s on top of T-19's "
                      f"{subj['t19_absent_seconds']}s), not a claim "
                      "that it never appears."),
        }
        print(f"    [{'ok ' if present else '---'}] phase2_watch: "
              f"{res['steps']['phase2_watch']['verdict']} "
              f"after {elapsed}s / {polls} poll(s)")

    if present:
        # The upper bound is the AGE OF THE SHARE MEMBERSHIP at the read
        # that found the object -- time since added_at -- and nothing
        # else.
        #
        # The first version of this computed t19_absent_seconds plus the
        # watch window, which is only the same number when phase 2 is
        # what found it. Phase 1 found it, the window was zero, and the
        # file therefore said "absent for at least 170.8s and present by
        # 171s" about an object whose membership was 17.4 minutes old.
        # Not merely imprecise: it asserted appearance inside 0.2s of
        # T-19's last poll, understated the bound by a factor of six,
        # and did it in the one field §2.4.1 would quote. A sentence
        # that is only correct on one branch is a wrong sentence (B-23b)
        # -- and the fields it was derived from were sitting in the same
        # record, disagreeing with it.
        upper = (round((found_wall * 1000 - int(added)) / 1000, 1)
                 if found_wall and added else None)
        lower = subj["t19_absent_seconds"]
        gap = (round(upper - lower, 1)
               if upper is not None and lower is not None else None)
        # The tightest upper bound ever observed wins, whichever run
        # produced it, because each run's reading is an independent
        # observation of the same mechanism on its own object.
        candidates = [p.get("upper_bound_seconds") for p in prior
                      if p.get("upper_bound_seconds")]
        if upper:
            candidates.append(upper)
        tightest = min(candidates) if candidates else None
        floors = [p.get("lower_bound_seconds") for p in prior
                  if p.get("lower_bound_seconds")]
        if lower:
            floors.append(lower)
        strongest_floor = max(floors) if floors else None
        res["steps"]["bounds"] = {
            "lower_bound_seconds": lower,
            "lower_bound_source": ("T-19's object_visibility: observed "
                                   "ABSENT this long after the ADD"),
            "upper_bound_seconds": upper,
            "upper_bound_source": ("age of the share membership at this "
                                   "probe's first PRESENT read"),
            "unmeasured_gap_seconds": gap,
            "tightest_upper_bound_across_runs": tightest,
            "strongest_lower_bound_across_runs": strongest_floor,
            "aggregation_means": (
                "Each run observes the same mechanism on its own "
                "object, so the smallest PRESENT age and the largest "
                "ABSENT age are the best bounds the repo holds. They "
                "may come from different runs, which is why both are "
                "carried rather than overwritten -- a re-run of this "
                "probe has a LOOSER upper bound than its first run by "
                "construction, since the object keeps ageing."),
            "verdict": ("BRACKETED" if gap else "BOUNDS_INCOMPLETE"),
            "means": (f"The object appeared somewhere in a {gap}s window "
                      f"that nobody watched: absent at {lower}s, present "
                      f"at {upper}s, and no observation in between. The "
                      f"resolution of this figure is that gap -- NOT the "
                      f"{args.poll_interval}s poll interval, which only "
                      f"describes how often this probe asked once it "
                      f"started asking. Quoting {upper}s as a latency "
                      f"would claim precision the run does not have."),
        }
        res["steps"]["phase3_provider_update"] = {
            "verdict": "NOT_RUN_ANSWER_ALREADY_IN_HAND",
            "means": ("The object appeared with no consumer-side action, "
                      "so the provider update is not required to "
                      "explain it and running one would only muddy the "
                      "record."),
        }
        res["verdict"] = "REFRESH_IS_TIME_BASED"
        res["conops_implication"] = (
            f"A newly shared object appears in the consumer's existing "
            f"catalog WITHOUT any consumer-side action: no re-import, no "
            f"provider update, no catalog recreate. It was observed "
            f"ABSENT {lower}s after the share membership was created and "
            f"PRESENT at {upper}s, with a {gap}s window in between that "
            f"was not observed. So §2.4.1 needs a TIMING expectation on "
            f"the consumer side rather than a re-provision step: the "
            f"consumer waits. Both ends are real observations and the "
            f"middle is not -- the honest statement is 'later than "
            f"{lower}s and no later than {upper}s', and a runbook that "
            f"prints {upper}s as the refresh latency is quoting a "
            f"number this run cannot support. What IS safe to put in "
            f"the runbook is the floor: a consumer who polls for three "
            f"minutes and raises a defect is raising a false one. "
            f"Tightening the upper end means re-running this probe "
            f"against a fresh object with a watch window that covers "
            f"the gap.")
    else:
        # --- phase 3: one mutation, then read -------------------------
        if not CREDENTIAL.exists():
            res["steps"]["phase3_provider_update"] = {
                "verdict": "NOT_RUN_NO_CREDENTIAL",
                "means": (f"{CREDENTIAL.name} absent, so the provider "
                          f"cannot be updated with the credential this "
                          f"path uses.")}
            res["verdict"] = "INCONCLUSIVE_TRIGGER_UNTESTED"
            res["means"] = ("The time hypothesis has a longer bounded "
                            "negative and the trigger hypothesis was "
                            "never exercised. Neither is excluded.")
        else:
            profile = json.loads(CREDENTIAL.read_text())
            ustatus, upayload = call(
                s["p_host"], s["p_token"],
                f"{UC}/providers/{PROVIDER_NAME}", "PATCH",
                {"recipient_profile_str": json.dumps(profile)})
            print(f"    [{'ok ' if ustatus in (200, 201) else 'REF'}] "
                  f"provider_update: {ustatus}")
            t0 = time.time()
            ppolls, ppresent, ptrail = 0, False, []
            # Short window on purpose. The claim being tested is "the
            # update triggers it", and a trigger that takes longer than
            # the watch window above is not distinguishable from the
            # timer this phase exists to rule out.
            pdeadline = t0 + min(180, args.watch_seconds)
            while True:
                ppolls += 1
                pstatus, plisted, ppresent = in_metadata(s, schema, leaf)
                ptrail.append({"t": round(time.time() - t0, 1),
                               "present": ppresent, "status": pstatus})
                if ppresent:
                    break
                if time.time() + args.poll_interval > pdeadline:
                    break
                time.sleep(args.poll_interval)
            pelapsed = round(time.time() - t0, 1)
            res["steps"]["phase3_provider_update"] = {
                "update_status": ustatus,
                "updated": ustatus in (200, 201),
                "polls": ppolls,
                "elapsed_seconds": pelapsed,
                "window_seconds": round(pdeadline - t0, 1),
                "present_after_update": ppresent,
                "trail": ptrail,
                "verdict": ("APPEARED_AFTER_PROVIDER_UPDATE" if ppresent
                            else "STILL_ABSENT_AFTER_PROVIDER_UPDATE"),
                "means": ("One mutation, nothing else. The PATCH pushes "
                          "the same credential the consumer already "
                          "held, so the variable is the update itself "
                          "and not a new credential."),
            }
            print(f"    [{'ok ' if ppresent else '---'}] "
                  f"phase3_provider_update: "
                  f"{res['steps']['phase3_provider_update']['verdict']} "
                  f"after {pelapsed}s / {ppolls} poll(s)")

            watched = (res["steps"].get("phase2_watch", {})
                       .get("elapsed_seconds") or 0)
            if ppresent and ustatus in (200, 201):
                # Corroborate on the data plane before concluding: the
                # tables API and a SELECT disagreeing would mean the
                # object is listed but not servable, which is a third
                # state and not the one being claimed.
                wh = find_warehouse(s["p_host"], s["p_token"])
                rows, raw = (None, None)
                if wh:
                    rows, raw = run_sql(
                        s["p_host"], s["p_token"], wh,
                        f"SELECT count(*) FROM {CATALOG_NAME}.{schema}."
                        f"{leaf}")
                readable = bool(rows and rows[0] and rows[0][0] is not None)
                res["steps"]["phase3_data_plane_confirm"] = {
                    "warehouse": bool(wh),
                    "rows": (int(rows[0][0]) if readable else None),
                    "raw": None if readable else raw,
                    "verdict": ("READABLE" if readable else
                                "LISTED_BUT_NOT_READABLE" if wh else
                                "NOT_RUN_NO_WAREHOUSE"),
                    "means": ("Metadata presence and servability are "
                              "different states. LISTED_BUT_NOT_"
                              "READABLE would mean the update refreshed "
                              "the object list without making the data "
                              "available, which is a separate finding "
                              "and must not be reported as a working "
                              "refresh."),
                }
                print(f"    [{'ok ' if readable else '---'}] "
                      f"data_plane_confirm: "
                      f"{res['steps']['phase3_data_plane_confirm']['verdict']}")
                res["verdict"] = (
                    "REFRESH_REQUIRES_CONSUMER_PROVIDER_UPDATE"
                    if readable else
                    "PROVIDER_UPDATE_REFRESHES_METADATA_ONLY")
                res["conops_implication"] = (
                    f"The object was absent from the consumer's metadata "
                    f"for {subj['t19_absent_seconds']}s during T-19 and a "
                    f"further {watched}s here with NO consumer-side "
                    f"action, then appeared {pelapsed}s after a single "
                    f"provider update. On this path the consumer's "
                    f"object list refreshes when the consumer updates "
                    f"the provider. §2.4.1 therefore needs an explicit "
                    f"consumer step after the provider adds an object -- "
                    f"and a consumer who only waits sits in front of a "
                    f"catalog that is silently short of what the share "
                    f"contains, with nothing in the UI to say so. This "
                    f"is an asymmetry argument, not a proof: a timer "
                    f"firing during the post-update window would look "
                    f"identical. The ratio is the evidence -- "
                    f"{round((subj['t19_absent_seconds'] or 0) + watched)}s "
                    f"absent with no action against {pelapsed}s after "
                    f"one action. Re-running this probe on a later "
                    f"object with a longer watch window is how the "
                    f"argument is strengthened if the CONOPS needs it.")
                if not readable:
                    res["means"] = (
                        "The update put the object in the consumer's "
                        "metadata but the read did not return rows. "
                        "Reported as metadata-only rather than as a "
                        "working refresh, because a runbook step that "
                        "produces a listable unreadable table is not a "
                        "step that works.")
            else:
                res["verdict"] = "NEITHER_TIME_NOR_PROVIDER_UPDATE"
                res["means"] = (
                    f"Absent for {subj['t19_absent_seconds']}s in T-19, a "
                    f"further {watched}s here with no action, and still "
                    f"absent {pelapsed}s after a provider update "
                    f"(status {ustatus}). Both candidate mechanisms now "
                    f"have bounded negatives. The remaining untested "
                    f"candidate is the catalog recreate, which "
                    f"tests/t19_ingress_d2d.py runs when object "
                    f"visibility fails and the carry-forward has not "
                    f"already answered -- and that is a destructive "
                    f"step, so it goes last. Do NOT write 'objects do "
                    f"not propagate' into the CONOPS off this: two "
                    f"bounded negatives and an untested third mechanism "
                    f"is not a platform limit.")

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(res, indent=2, default=str))
    print("\n" + "=" * 68)
    print(f"VERDICT: {res['verdict']}")
    if res.get("conops_implication"):
        print(f"\n{res['conops_implication']}")
    print(f"\nWrote {EVIDENCE.relative_to(REPO)}")


if __name__ == "__main__":
    main()
