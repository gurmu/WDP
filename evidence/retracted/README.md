# Retracted evidence

Files here were produced by a probe that ran, returned a verdict, and
was later found to have measured the wrong thing. They are kept, not
deleted: a CONOPS evidence pack is more credible if it shows which
readings were withdrawn and why.

## capability-baseline-d2d.2026-10-18.INVALID.json

Reported `SAME_METASTORE` for the second account's workspace.

Withdrawn the same day. Two independent faults, either of which alone
would have invalidated it:

1. The second workspace's host and token were written into
   `.env.example` instead of `.env`. `load_env()` reads only `.env`, so
   the probe found no second credential and silently fell back to its
   single-workspace mode instead of doing the real comparison.

2. In that fallback mode it looked for a catalog named `workspace`.
   Every Databricks workspace has a catalog by that name, so it matched
   the PRIMARY workspace's own catalog and reported it as the far side.
   The verdict was an artefact of the catalog name, not a measurement of
   metastore identity.

The two accounts are registered to different emails and show different
workspace IDs (`dbc-0c6ebc56-563d` vs `dbc-519df5ad-574f`), which is
positive reason to expect DISTINCT metastores -- the opposite of what
was recorded.

Guards added so neither fault can recur silently: the probe now refuses
to conclude from an ambiguous catalog name (`INVALID_PROBE`), and
`scripts/check_secret_hygiene.py` now scans dotenv-style filenames,
which is how the credential in `.env.example` was found at all.
