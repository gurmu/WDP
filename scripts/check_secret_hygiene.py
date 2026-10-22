#!/usr/bin/env python3
"""
E1 Task 1.1 -- the reusable secret-hygiene check.

CONOPS Sections 1.4 and 3.6 make credential custody a hard rule, and
T-21's second half is a secret scan that must pass. The task deliverable
is explicitly "a reusable hygiene check that asserts it" -- asserted by a
check, not by inspection, because inspection does not survive a umask.

Root cause worth remembering: this repo runs under `umask 0002`, so every
newly created file under _secrets/ lands as mode 664 no matter how many
times you chmod the existing ones. A one-off `chmod 0600 _secrets/*` is
therefore necessary but never sufficient. This script is what catches the
next one.

Run it before every commit and as the first step of any evidence run:

    python3 scripts/check_secret_hygiene.py

Exit code 0 = clean, 1 = violations found.
"""
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SECRETS = REPO / "_secrets"

# Things that look like live credentials. Kept deliberately broad.
TOKEN_PATTERNS = [
    (re.compile(r"\bdapi[0-9a-f]{32}\b"), "Databricks personal access token"),
    (re.compile(r"\bdkea[0-9a-f]{32}\b"), "Databricks OAuth token"),
    # The value is CAPTURED so it can be tested against
    # DECLARED_PLACEHOLDER below. Without that, this pattern flagged
    # `"bearerToken": "dummy-not-a-real-token"` in
    # scripts/14_probe_d2o_provider_import.py -- a string whose whole
    # purpose is to be sent in the one request that must not carry a live
    # credential. See docs/11 B-13.
    (re.compile(r'"bearerToken"\s*:\s*"([^"]{20,})"'), "Delta Sharing bearer token"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token (classic)"),
    # Fine-grained PATs are a different shape and the classic pattern
    # above does not match them: the prefix is `github_pat_`, the body is
    # much longer, and it CONTAINS UNDERSCORES, so [A-Za-z0-9] stops at
    # the first one. A live fine-grained PAT passed this check unflagged
    # on 2026-10-18.
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "GitHub token (fine-grained)"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    # A PRE-SIGNED URL IS A CREDENTIAL, and this repository now generates
    # them. It carries an access key id and a signature in its query
    # string, and anyone holding it can fetch the object with no other
    # authentication -- that is the whole premise of check 6 in
    # scripts/11_probe_oss_provider.py, which fetches one with no
    # Authorization header at all. It expires, but a one-hour window
    # (preSignedUrlTimeoutSeconds) committed to a repository is still a
    # window, and the access key id and bucket name inside it do not
    # expire. The D2O evidence file deliberately records outbound HOSTS
    # and byte counts rather than URLs; these patterns are what would
    # catch that guarantee being dropped by a later edit to the probe.
    (re.compile(r"X-Amz-Signature=[0-9a-f]{16,}"), "pre-signed URL (SigV4 signature)"),
    # Matches the credential SCOPE shape -- key/YYYYMMDD/region/... -- not
    # the bare parameter name. Two reasons. The scope is what makes it a
    # real signed URL rather than a mention of one, and a pattern of the
    # bare name MATCHED THIS FILE: the scanner flagged its own source and
    # the gate failed on first run. Skipping this file would have fixed
    # that by making the scanner the one place it cannot see, which is
    # the wrong trade; requiring the scope means the regex source cannot
    # satisfy its own pattern.
    (re.compile(r"X-Amz-Credential=[^&\s]*(%2F|/)\d{8}(%2F|/)"),
     "pre-signed URL (SigV4 credential scope)"),
    (re.compile(r"[?&]Signature=[A-Za-z0-9%+/=]{20,}"), "pre-signed URL (SigV2 signature)"),
    # Catch-all for the shape of this repo's own config: a *_TOKEN or
    # *_SECRET or *_PASSWORD key assigned something long that is not a
    # <placeholder>. This is the backstop for credential formats nobody
    # anticipated, which is how all three misses above happened.
    (
        re.compile(r"^[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|APIKEY|API_KEY)=(?!<)(?!$)\S{20,}", re.MULTILINE),
        "long value assigned to a *_TOKEN/_SECRET/_PASSWORD key",
    ),
]

# A value is exempt only if it ASSERTS IN ITS OWN TEXT that it is not
# real. That rule is what keeps this from becoming a hole.
#
# The alternative fixes were both worse. Shortening the probe's dummy
# token below the 20-character floor games the scanner and leaves the
# same trap for the next person who writes a probe. Excluding the probe
# file repeats the mistake rejected for X-Amz-Credential above: it makes
# a file the one place the scanner cannot see.
#
# Note this is not a new concession -- the catch-all pattern already
# exempts `<placeholder>` via `(?!<)`. What is new is that the exemption
# is now explicit, anchored at BOTH ENDS, and logged.
#
# Anchoring is the whole defence. `dummy-<a real token>` does not match,
# because the real part is extra characters outside the placeholder
# vocabulary. To slip a live token past this, someone would have to write
# `not-a-real-token` into a value that is one -- a deliberate lie, not
# the accident this gate exists to catch.
DECLARED_PLACEHOLDER = re.compile(
    r"^(?:"
    r"<redacted[^<>]*>"                 # <redacted>, <redacted-by-script-14>
    r"|__[A-Z0-9_]+__"                  # __BEARER_TOKEN__ template slots
    r"|[a-z0-9-]*not-a-real-(?:token|secret|credential|password)[a-z0-9-]*"
    r")$"
)

SCAN_EXCLUDE_DIRS = {".git", "_secrets", "node_modules", "__pycache__", ".terraform"}
SCAN_EXTENSIONS = {".py", ".json", ".yaml", ".yml", ".md", ".sh", ".tf", ".txt", ".env"}

# Suffix matching alone has a blind spot that bites exactly where it
# hurts most. Path(".env").suffix is '' and Path(".env.example").suffix
# is '.example', so a suffix-only filter silently skips both dotenv
# files -- the two files in this repo most likely to hold a live
# credential. Found 2026-10-18 after a real token sat unflagged in
# .env.example while this check reported "clean".
#
# Any file whose name begins with one of these is scanned regardless of
# what the suffix machinery thinks of it.
SCAN_NAME_PREFIXES = (".env", "env.", "credential", "secret", ".npmrc", ".netrc")

# Sanctioned secret stores, by path relative to the repo root. These are
# SUPPOSED to contain live credentials and are gitignored, so finding a
# token in them is correct behaviour, not a violation. They are excluded
# from the token scan but still mode-checked and git-checked below.
# Everything else named like a dotenv -- .env.example above all -- is
# fair game, because a template with a real token in it is the exact
# failure this check exists to catch.
SANCTIONED_SECRET_FILES = {".env"}


def should_scan(path, repo):
    """Scan if the extension is interesting OR the name looks credential-bearing."""
    rel = str(path.relative_to(repo))
    if rel in SANCTIONED_SECRET_FILES:
        return False
    name = path.name.lower()
    if any(name.startswith(p) for p in SCAN_NAME_PREFIXES):
        return True
    return path.suffix in SCAN_EXTENSIONS


def fail(violations, msg):
    violations.append(msg)
    print(f"  FAIL  {msg}")


def main():
    violations = []
    print("Secret hygiene check\n" + "=" * 60)

    # --- 1. Sanctioned secret stores must be 0600 ------------------------
    # _secrets/* plus .env itself. .env was omitted from the first version
    # of this check, which was an oversight of the same family as the
    # suffix blind spot above: the file holding DATABRICKS_TOKEN was the
    # one file whose permissions nobody asserted.
    print("\n[1] File modes on secret stores")
    mode_targets = []
    if SECRETS.exists():
        mode_targets += [f for f in sorted(SECRETS.rglob("*")) if f.is_file()]
    else:
        print("  skip  no _secrets/ directory")
    for rel in sorted(SANCTIONED_SECRET_FILES):
        p = REPO / rel
        if p.is_file():
            mode_targets.append(p)
    for f in mode_targets:
        mode = f.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            fail(violations, f"{f.relative_to(REPO)} is {oct(mode & 0o777)}, expected 0600")
        else:
            print(f"  ok    {f.relative_to(REPO)} {oct(mode & 0o777)}")

    # --- 2. No executable code may live in _secrets/ ---------------------
    # A secrets directory is for secrets. Code there drifts from the
    # tracked copy and is silently excluded from review (this repo had
    # exactly that: a rewrite script that was MORE correct than the
    # tracked one, invisible to everyone).
    print("\n[2] No code in _secrets/")
    if SECRETS.exists():
        code = [f for f in SECRETS.rglob("*") if f.is_file() and f.suffix in {".py", ".sh", ".tf"}]
        if code:
            for f in code:
                fail(violations, f"code file in secrets dir: {f.relative_to(REPO)} -- reconcile into scripts/")
        else:
            print("  ok    no .py/.sh/.tf files present")

    # --- 3. No live-looking tokens anywhere outside _secrets/ ------------
    print("\n[3] Token scan outside _secrets/")
    hits = 0
    scanned = 0
    exempted = []
    for f in REPO.rglob("*"):
        if not f.is_file():
            continue
        if any(part in SCAN_EXCLUDE_DIRS for part in f.relative_to(REPO).parts):
            continue
        if not should_scan(f, REPO):
            continue
        scanned += 1
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for pattern, label in TOKEN_PATTERNS:
            for m in pattern.finditer(text):
                # A pattern with a capturing group offers its VALUE for
                # inspection; one without does not, and is reported as-is.
                value = m.group(1) if m.re.groups else None
                if value is not None and DECLARED_PLACEHOLDER.match(value):
                    exempted.append(f"{label} in {f.relative_to(REPO)}: {value}")
                    continue
                fail(violations, f"{label} found in {f.relative_to(REPO)}")
                hits += 1
                break  # one report per pattern per file; the file is already failing
    # Exemptions are PRINTED, not silent. An exemption that leaves no
    # trace is the same defect shape this project keeps meeting
    # (docs/12 §12.9): the run output would be identical whether the
    # scanner found nothing or found something and waved it through.
    for note in exempted:
        print(f"  note  declared placeholder exempted -- {note}")
    if hits == 0:
        print(f"  ok    no token-shaped strings found ({scanned} files scanned, "
              f"{len(exempted)} declared placeholder(s) exempted)")

    # --- 4. Git must not be tracking anything from _secrets/ -------------
    print("\n[4] Git tracking")
    try:
        inside = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=REPO, capture_output=True, text=True,
        )
        if inside.returncode != 0:
            fail(violations, "no git repository -- .gitignore is inert and T-12 has no substrate")
        else:
            tracked = subprocess.run(
                ["git", "ls-files", "_secrets/", ".env"],
                cwd=REPO, capture_output=True, text=True,
            ).stdout.strip()
            if tracked:
                for line in tracked.splitlines():
                    fail(violations, f"tracked by git but must not be: {line}")
            else:
                print("  ok    nothing from _secrets/ or .env is tracked")
    except FileNotFoundError:
        fail(violations, "git not installed")

    # --- 5. The OD-4 bypass check ----------------------------------------
    # Specific to this project: a rewritten credential must not retain any
    # reference to a databricks host in ANY field.
    print("\n[5] OD-4: rewritten credentials must not reference Databricks")
    rewritten = SECRETS / "rewritten-credential.json" if SECRETS.exists() else None
    if rewritten and rewritten.exists():
        text = rewritten.read_text()
        bad = re.findall(r'"([^"]*databricks[^"]*)"', text, re.IGNORECASE)
        if bad:
            for b in bad:
                fail(violations, f"rewritten-credential.json still points at Databricks: {b}")
            print("        ^ this is a live perimeter bypass, not a cosmetic issue")
        else:
            print("  ok    no Databricks host survives in the rewritten credential")
    else:
        print("  skip  no rewritten-credential.json yet")

    # --- 6. Duplicate keys in .env ---------------------------------------
    # B-22. .env held its opening block twice. Both copies defined
    # DATABRICKS_TOKEN, with DIFFERENT values, and every loader in this
    # repo uses os.environ.setdefault(), so the first copy silently won.
    # Two consequences, both hygiene problems rather than style ones:
    # a second live credential existed that nothing could reach, so it
    # could never be rotated through configuration; and anyone editing
    # the visible later copy -- the obvious thing to do after rotating a
    # token -- would change nothing and get no warning. The failure
    # surfaces later as an auth error that looks like a permissions
    # problem. A duplicated key is therefore reported here, with any
    # value divergence named but never printed.
    print("\n[6] No duplicate keys in .env")
    env_file = REPO / ".env"
    if env_file.exists():
        order, values = [], {}
        for num, line in enumerate(env_file.read_text().splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            key, val = s.split("=", 1)
            key = key.strip()
            if key not in values:
                order.append(key)
                values[key] = []
            values[key].append((num, val.strip()))
        dupes = [k for k in order if len(values[k]) > 1]
        if dupes:
            for key in dupes:
                occ = values[key]
                lines_at = ", ".join(f"L{n}" for n, _ in occ)
                diverge = len({v for _, v in occ}) > 1
                fail(violations,
                     f".env defines {key} {len(occ)} times ({lines_at}); "
                     f"the copies "
                     f"{'DIVERGE' if diverge else 'agree'} and only the "
                     f"first takes effect under setdefault()")
            print("        ^ a later copy of a key is dead config: editing "
                  "it changes nothing")
        else:
            print(f"  ok    {len(order)} keys, no duplicates")
    else:
        print("  skip  no .env present")

    # --- Result ----------------------------------------------------------
    print("\n" + "=" * 60)
    if violations:
        print(f"{len(violations)} violation(s). Blocker B-4 is not cleared.")
        out = REPO / "evidence" / "secret-hygiene.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"clean": False, "violations": violations}, indent=2))
        return 1
    print("Clean. T-21's secret-scan half can pass.")
    out = REPO / "evidence" / "secret-hygiene.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"clean": True, "violations": []}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
