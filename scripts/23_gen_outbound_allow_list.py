#!/usr/bin/env python3
"""
Generate iac/config/outbound-allow-list.yaml -- the SINGLE writer.

Two tests contribute outbound hosts for channel I-1, and until now only
one of them wrote the file. T-20 generated it from a socket capture;
T-19 found the Databricks open-sharing endpoint host and recorded an
`allow_list_implication` that never reached any configuration. Two
writers, or one writer and one orphaned finding, both end the same way:
the next T-20 run silently drops the other test's host.

So this script is the only writer. `tests/t20_ingress_d2o.py` calls it
after writing its evidence file, and it can also be run by hand.

PROVENANCE IS A FIELD, NOT A FOOTNOTE. The two contributions are not the
same kind of fact:

  SOCKET_CAPTURE                 the host was observed being contacted,
                                 under a filter that showed the set to
                                 be necessary and sufficient
  DECLARED_NOT_CAPTURED          the host is named in the credential
                                 the platform was issued, and the read
                                 through it succeeded -- but no socket
                                 capture was taken on that path, so the
                                 hosts it ALSO contacts are unknown

Flattening those into one list would be the silent negative §2.4.3 is
written to avoid: an entry nobody watched being used looks exactly like
an entry proven necessary. A firewall built from the first kind is
derived from evidence; one built from the second is derived from a
document, and the difference matters when the data plane fails.

Usage:
    python3 scripts/23_gen_outbound_allow_list.py
    python3 scripts/23_gen_outbound_allow_list.py --dry-run
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
T20 = REPO / "evidence" / "t20-ingress-d2o.json"
T19 = REPO / "evidence" / "t19-ingress-d2d.json"
OUT = REPO / "iac" / "config" / "outbound-allow-list.yaml"

# T-20's own guard, preserved: an allow-list generated from a capture
# that was not shown to be sufficient would be worse than none, because
# it would look derived from evidence while being wrong.
WRITEABLE = ("NECESSARY_AND_SUFFICIENT",
             "NECESSARY_AND_SUFFICIENT_REVIEW_REQUIRED",
             "SUFFICIENT_ONLY")


def now():
    return datetime.now(timezone.utc).isoformat()


def load(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        print(f"  WARNING: {path.name} unreadable ({exc}); its hosts are "
              f"omitted and the file records the omission.")
        return {"__unreadable__": str(exc)}


def captured_from_t20(doc):
    """Socket-captured hosts, with the sufficiency verdict that licences
    them."""
    if not doc or "__unreadable__" in doc:
        return [], None, (doc or {}).get("__unreadable__")
    pb = doc.get("path_b_client") or {}
    verdict = pb.get("allowlist_verdict")
    hosts = ((pb.get("capture") or {}).get("hosts") or [])
    out = []
    for h in hosts:
        out.append({
            "host": h.get("host"),
            "port": h.get("port"),
            "role": h.get("role"),
            "conops_ref": h.get("conops_ref"),
            "provenance": "SOCKET_CAPTURE",
            "observed_resolutions": h.get("resolved"),
            "stages": h.get("stages") or [],
            "source_test": "T-20",
            "source_evidence": str(T20.relative_to(REPO)),
        })
    return out, verdict, None


def declared_from_t19(doc):
    """The Databricks open-sharing endpoint host. Named in the issued
    credential and read through successfully -- not socket-captured."""
    if not doc or "__unreadable__" in doc:
        return [], (doc or {}).get("__unreadable__")
    part2 = doc.get("part2_substitute_ingress") or {}
    cred = part2.get("credential") or {}
    host = cred.get("endpoint_host")
    endpoint = cred.get("endpoint") or ""
    if not host:
        return [], "no endpoint_host in part2_substitute_ingress.credential"

    scheme = urlparse(endpoint).scheme if endpoint else ""
    port = {"https": 443, "http": 80}.get(scheme)

    # Only claim the read worked if the evidence says so, in the field
    # that says it. A host whose read was never demonstrated has no
    # business in an allow-list at all.
    read = ((part2.get("steps") or {}).get("entitled_read") or {})
    read_verdict = read.get("verdict")

    return [{
        "host": host,
        "port": port,
        "port_derivation": (f"from the credential endpoint scheme "
                            f"({scheme!r})" if port else "UNKNOWN"),
        "role": "databricks_open_sharing_endpoint",
        "conops_ref": "CONOPS 2.4.3 approved provider endpoint",
        "provenance": "DECLARED_NOT_CAPTURED",
        "source_test": "T-19",
        "source_evidence": str(T19.relative_to(REPO)),
        "read_demonstrated": read_verdict,
        "caveat": (
            "Named in the credential the platform was issued and read "
            "through successfully, but NO socket capture was taken on "
            "this path. This entry says the host is required; it does "
            "NOT say the set is sufficient. See known_incomplete."),
    }], None


def render(captured, declared, t20_verdict, notes):
    L = [
        "# GENERATED FILE -- DO NOT HAND-EDIT.",
        "#",
        "# Produced by scripts/23_gen_outbound_allow_list.py, which is the",
        "# SINGLE writer of this file. It merges the contributions of two",
        "# tests and labels each entry with how it was obtained.",
        "#",
        "# CONOPS 2.4.3 is the reason the provenance field exists:",
        "# \"Databricks documentation does not publish the firewall",
        "# requirements for the recipient side, so test T-20 records the",
        "# hosts actually contacted and the allow-list is built from that",
        "# capture, not from assumption.\" An entry that was never watched",
        "# being used is therefore a weaker fact than one that was, and the",
        "# file has to be able to say which is which.",
        "#",
        "# NOT TRANSFERABLE AS WRITTEN. These hostnames and ports belong to",
        "# the local prototype. What transfers to a client environment is",
        "# the PROCEDURE that produced them -- run the recipient read with a",
        "# socket capture in place and generate this file from the result.",
        "# Copying these entries would permit hosts that do not exist there",
        "# and omit the ones that do.",
        "#",
        f"# Generated: {now()}",
        "",
        "channel: I-1",
        "direction: outbound",
        "rule: pull only -- the platform opens every connection (CONOPS 2.4.3)",
        "default: deny",
        "non_transferable: true",
        "",
        "provenance_classes:",
        "  SOCKET_CAPTURE: >-",
        "    Observed being contacted during the read, under a filter that",
        "    showed this set to be both necessary and sufficient: the read",
        "    succeeds with exactly this set permitted, and removing the",
        "    storage host breaks the data read while leaving discovery",
        "    intact. Both halves matter -- discovery surviving is what",
        "    attributes the data failure to the storage host rather than to",
        "    a broken read.",
        "  DECLARED_NOT_CAPTURED: >-",
        "    Named in an issued credential and read through successfully, but",
        "    not socket-captured. Required, not proven sufficient.",
        "",
        "sufficiency:",
        f"  socket_captured_set: {t20_verdict or 'NOT_ESTABLISHED'}",
        "  declared_set: NOT_ESTABLISHED",
        "  enforcement_caveat: >-",
        "    T-20's filter is in-process. It proves the read DEPENDS on the",
        "    captured hosts; it does not prove a firewall would enforce the",
        "    list.",
        "",
        "hosts:",
    ]

    def emit(h):
        L.append(f"  - host: {h['host']}")
        L.append(f"    port: {h['port']}")
        if h.get("port_derivation"):
            L.append(f"    port_derivation: \"{h['port_derivation']}\"")
        L.append(f"    role: {h['role']}")
        L.append(f"    provenance: {h['provenance']}")
        L.append(f"    conops_ref: \"{h['conops_ref']}\"")
        L.append(f"    source_test: {h['source_test']}")
        L.append(f"    source_evidence: {h['source_evidence']}")
        if h.get("observed_resolutions") is not None:
            L.append(f"    observed_resolutions: {h['observed_resolutions']}")
        if h.get("stages"):
            L.append(f"    stages: [{', '.join(h['stages'])}]")
        if h.get("read_demonstrated"):
            L.append(f"    read_demonstrated: {h['read_demonstrated']}")
        if h.get("caveat"):
            L.append("    caveat: >-")
            for line in wrap(h["caveat"], 64):
                L.append(f"      {line}")

    for h in captured + declared:
        emit(h)
    if not (captured or declared):
        L.append("  []  # nothing to emit -- see the evidence files before "
                 "using this")

    L += [
        "",
        "# What this file does NOT cover, stated so the gap is not mistaken",
        "# for a complete list. A missing entry and a host that is genuinely",
        "# not contacted produce the same empty line here.",
        "known_incomplete:",
        "  - id: KI-1",
        "    scope: Databricks-hosted provider data plane",
        "    statement: >-",
        "      The DECLARED_NOT_CAPTURED entry is the sharing CONTROL plane",
        "      only. A Databricks provider vends pre-signed URLs for the",
        "      data plane, so that path also contacts storage hosts which",
        "      are NOT in this file because no capture was taken on it.",
        "    consequence: >-",
        "      A firewall built from this file alone would permit discovery",
        "      against the Databricks provider and break the read. The",
        "      failure would look like a permissions problem.",
        "    closes_when: >-",
        "      The same socket-capture procedure T-20 used is run against",
        "      the Databricks-hosted provider path.",
    ]
    for i, n in enumerate(notes, start=2):
        L.append(f"  - id: KI-{i}")
        L.append(f"    statement: \"{n}\"")
    return "\n".join(L) + "\n"


def wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    notes = []
    d20, d19 = load(T20), load(T19)
    captured, t20_verdict, err20 = captured_from_t20(d20)
    declared, err19 = declared_from_t19(d19)
    if err20:
        notes.append(f"T-20 contribution omitted: {err20}")
    if err19:
        notes.append(f"T-19 contribution omitted: {err19}")

    if captured and t20_verdict not in WRITEABLE:
        print(f"REFUSING to write: T-20 verdict {t20_verdict!r} is not in "
              f"{WRITEABLE}.")
        print("An allow-list generated from a capture that was not shown to "
              "be sufficient\nwould be worse than none: it would look "
              "derived from evidence while being wrong.")
        return 1

    if not captured and not declared:
        print("REFUSING to write: neither evidence file contributed a host.")
        return 1

    text = render(captured, declared, t20_verdict, notes)

    print("=" * 68)
    print("Outbound allow-list generation (channel I-1)")
    print("=" * 68)
    for h in captured:
        print(f"  [capture ] {h['host']}:{h['port']}  {h['role']}")
    for h in declared:
        print(f"  [declared] {h['host']}:{h['port']}  {h['role']}")
    for n in notes:
        print(f"  NOTE: {n}")
    print(f"\n  socket-captured sufficiency: {t20_verdict or 'NOT_ESTABLISHED'}")
    print("  declared sufficiency:        NOT_ESTABLISHED (KI-1)")

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"\nWrote {OUT.relative_to(REPO)} "
          f"({len(captured)} captured, {len(declared)} declared).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
