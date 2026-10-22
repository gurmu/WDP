#!/usr/bin/env bash
# Resolve the object-store image to a VERIFIED digest and pin it in
# docker-compose.yml.
#
# WHY THIS IS A SCRIPT AND NOT A COMMAND IN THE RUNBOOK. The first
# attempt was three shell lines, and it failed in the worst available
# way: `docker pull` errored, the digest came back empty, and `sed`
# cheerfully wrote `image: minio/minio@` into the compose file. Nothing
# checked that the thing being pinned existed before it was pinned.
#
# That is the same defect shape as docs/12 Sec 12.9 and docs/11 B-6: a
# step that could not do its job produced output indistinguishable from
# a step that did. So this script asserts, in order:
#
#   1. the reference RESOLVES in a registry           (else: next candidate)
#   2. it PULLS                                        (else: next candidate)
#   3. its architecture is amd64                       (else: abort, B-6)
#   4. the digest matches ^sha256:[0-9a-f]{64}$        (else: abort)
#   5. only then is docker-compose.yml rewritten
#
# and it never writes a partial result. Re-runnable: pinning an
# already-pinned file is a no-op unless the digest changed.
#
# Usage:
#   scripts/12_pin_object_store.sh                 # try known candidates
#   scripts/12_pin_object_store.sh quay.io/minio/minio:RELEASE.2025-xx
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="${REPO}/docker-compose.yml"
WANT_ARCH="amd64"

# Candidates in preference order.
#
# quay.io first because that is MinIO's own registry and the one their
# documentation uses. docker.io/minio/minio is listed only so that its
# failure is recorded rather than assumed: Docker Hub returns the SAME
# message -- "pull access denied ... repository does not exist or may
# require 'docker login'" -- for a deleted repository, a private one, a
# rate-limited anonymous client and a tag that never existed. That one
# message covering four causes is why this is worth probing instead of
# concluding from.
if [[ $# -gt 0 ]]; then
  CANDIDATES=("$@")
else
  # Scality CloudServer, then Garage as fallback. MinIO is deliberately
  # absent: its community image is gone from both registries and
  # dl.min.io answers 410 Gone (docs/11 B-10). Re-add it only if that
  # changes, and only with evidence from
  # scripts/13_probe_object_stores.sh.
  CANDIDATES=(
    "docker.io/zenko/cloudserver:latest"
    "docker.io/dxflrs/garage:v1.0.1"
  )
fi

echo "Pinning the object-store image for the D2O provider"
echo "============================================================"

# `docker pull` is the AUTHORITATIVE test and is therefore the only
# gate. An earlier version of this script put `docker manifest inspect`
# in front of it and discarded that command's stderr -- so when
# `docker manifest` was itself unavailable, every candidate reported
# "does not resolve" and the actual cause never appeared. That is the
# B-10 defect committed inside the script written to prevent it, which
# is a useful reminder that the rule is not "assert more" but "never
# discard the error text of the thing you are asserting on".
CHOSEN=""
declare -a FAILURES=()
for ref in "${CANDIDATES[@]}"; do
  printf '  %-48s ' "$ref"
  if out="$(docker pull "$ref" 2>&1)"; then
    echo "PULLED"
    CHOSEN="$ref"
    break
  fi
  reason="$(printf '%s' "$out" | grep -v '^$' | tail -1)"
  echo "failed"
  FAILURES+=("$ref :: $reason")
done

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo
  echo "  Failure text, verbatim -- read these rather than inferring:"
  for f in "${FAILURES[@]}"; do
    echo "    $f"
  done
fi

if [[ -z "$CHOSEN" ]]; then
  cat <<'EOF'

ABORTED -- no candidate resolved, and nothing was written.

This is setup-incomplete, NOT a finding about the D2O channel. Do not
record it in the test matrix as a capability result.

Read the verbatim failure text above before acting. TWO registries
failing identically is evidence about THIS HOST, not about MinIO:
quay.io and Docker Hub do not go down together. Likely causes, in the
order they are worth testing:

  1. No egress to registries at all. Test with something known-good:
         docker pull hello-world
     If that also fails, the problem is DNS, a proxy, or the daemon's
     network -- not this image.
  2. Anonymous Docker Hub rate limit (HTTP 429). Docker reports it as
     "repository does not exist or may require 'docker login'".
         docker login
  3. A daemon-level registry mirror or allow-list. Check:
         docker info | grep -iA3 'registry\|mirror\|proxy'
  4. The tag genuinely does not exist. List what does:
     curl -s 'https://quay.io/api/v1/repository/minio/minio/tag/?limit=10&onlyActiveTags=true' \
       | python3 -c 'import json,sys; [print(t["name"]) for t in json.load(sys.stdin)["tags"]]'
     then:  scripts/12_pin_object_store.sh quay.io/minio/minio:<tag>

If MinIO stays unavailable, say so and we will swap the service. The
rest of the design is store-agnostic: core-site.xml, the s3a:// table
location and scripts 10 and 11 need only path-style addressing, SigV4
and GET pre-signing, which several S3-compatible servers provide.
EOF
  exit 1
fi

ARCH="$(docker image inspect "$CHOSEN" --format '{{.Architecture}}')"
DIGEST_FULL="$(docker image inspect "$CHOSEN" --format '{{index .RepoDigests 0}}')"
DIGEST="${DIGEST_FULL##*@}"
REPO_PART="${DIGEST_FULL%@*}"

echo
echo "  reference : $CHOSEN"
echo "  arch      : $ARCH"
echo "  digest    : $DIGEST"

# Assertion 3. B-6 was exactly this: a reference that resolved, pulled
# and validated, for the wrong architecture, and then exited silently at
# runtime looking like a software limitation.
if [[ "$ARCH" != "$WANT_ARCH" ]]; then
  echo
  echo "ABORTED -- image is $ARCH, host needs $WANT_ARCH. Nothing written."
  echo "See docs/11 B-6: an arm64 image on this host pulls fine and then"
  echo "exits on start, which reads as 'the software does not work here'."
  exit 1
fi

# Assertion 4. The failure that produced `image: minio/minio@`.
if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo
  echo "ABORTED -- digest is not a well-formed sha256. Nothing written."
  exit 1
fi

# Assertion 5. Rewrite only the image line of the minio service, and
# verify the file afterwards rather than trusting the edit.
python3 - "$COMPOSE" "$REPO_PART" "$DIGEST" <<'PY'
import re, sys
path, repo, digest = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
# Anchored on the `# PIN-TARGET` sentinel comment, NOT on the product
# name. Matching the vendor's name was the obvious approach and it is
# wrong: the store was swapped once already (docs/11 B-10), and a
# rewrite rule keyed on the old vendor silently matches nothing after a
# swap -- which, combined with `n != 1`, at least fails loudly, but only
# because that assertion exists. The sentinel survives vendor changes.
pat = re.compile(
    r'(#\s*PIN-TARGET\b[^\n]*\n(?:[^\n]*\n)*?\s*image:\s*)\S+',
    re.MULTILINE,
)
new, n = pat.subn(lambda m: f"{m.group(1)}{repo}@{digest}", src)
if n != 1:
    sys.exit(
        f"Refusing to write: matched {n} PIN-TARGET image lines, expected 1.\n"
        "Check that docker-compose.yml still carries the `# PIN-TARGET` "
        "comment directly above the object store's image line."
    )
open(path, "w").write(new)
print(f"  rewrote 1 image line in {path}")
PY

echo
echo "Verifying the file parses and the pin is what we chose:"
docker compose config 2>/dev/null | grep -E "^\s+image:.*${DIGEST}" || {
  echo "  WARNING: compose config did not echo the pinned digest."
  echo "  If it failed outright, OBJECTSTORE_ACCESS_KEY /"
  echo "  OBJECTSTORE_SECRET_KEY are probably still missing from .env --"
  echo "  the service declares them with :? so compose refuses to render"
  echo "  without them. That is intentional: a store with default or"
  echo "  absent credentials would let scripts/11 check 7 pass for the"
  echo "  wrong reason."
}

echo
echo "Done. Next:"
echo "  docker compose up -d objectstore"
echo "  python3 scripts/10_setup_oss_provider.py --force"
