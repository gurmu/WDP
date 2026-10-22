#!/usr/bin/env bash
# Which S3-compatible object store can this host actually obtain?
#
# WHY. The D2O provider cannot serve a file:// table (docs/11 B-8), so an
# object store is mandatory. MinIO was the obvious choice and turned out
# to be unobtainable anonymously from both quay.io (401) and Docker Hub
# (access denied) -- see B-10. Rather than guess a replacement by
# reputation, this probes the candidates and reports what is true here.
#
# READ-ONLY. Pulls images and prints a table. Writes nothing, changes no
# configuration, and does not touch docker-compose.yml.
#
# WHAT THE PROVIDER ACTUALLY NEEDS, which is the whole selection
# criterion -- everything else is incidental:
#   * S3 API with PATH-STYLE addressing (bucket in the path, not the host)
#   * SigV4
#   * GET pre-signing, and REFUSAL of a write with a GET-signed URL
#   * amd64
#
# That last point is not a nice-to-have. scripts/11 check 7 is T-21's
# read-only evidence, and a store that ignores signatures would PASS
# checks 1-6 and then accept the tampering PUT, producing a false
# ACCEPTS_WRITE. A permissive store is worse than no store, because it
# manufactures a negative finding about the protocol. Stores known to
# relax auth by default are marked below and ranked last.
#
# Usage:  scripts/13_probe_object_stores.sh
set -uo pipefail

echo "Probing obtainable S3-compatible object stores"
echo "======================================================================"
printf '%-46s %-9s %s\n' "REFERENCE" "RESULT" "ARCH / NOTE"
echo "----------------------------------------------------------------------"

# Ranked by fit, best first. The notes are the reason for the order.
CANDIDATES=(
  # Scality's S3 server. Enforces SigV4, path-style by default, one
  # command, two env vars. Closest drop-in for MinIO's role here.
  "docker.io/zenko/cloudserver:latest"

  # Garage: small, strict about signatures, actively maintained.
  # Needs a TOML config plus a key-creation step, so second on effort.
  "docker.io/dxflrs/garage:v1.0.1"

  # SeaweedFS has an S3 gateway. Capable, but its S3 API permits
  # ANONYMOUS access until identities are configured, so it needs an
  # explicit s3.json before it can be trusted for check 7.
  "docker.io/chrislusf/seaweedfs:3.69"

  # LocalStack. Reliable to obtain, but historically lenient about
  # signature verification -- exactly the failure mode described above.
  # Usable only if check 7 is verified to refuse.
  "docker.io/localstack/localstack:3"

  # Older MinIO tags, in case only recent ones were moved behind auth.
  "docker.io/minio/minio:RELEASE.2023-09-04T19-57-37Z"
  "quay.io/minio/minio:RELEASE.2024-01-16T16-07-38Z"
)

AVAILABLE=()
for ref in "${CANDIDATES[@]}"; do
  if out="$(docker pull "$ref" 2>&1)"; then
    arch="$(docker image inspect "$ref" --format '{{.Architecture}}' 2>/dev/null || echo '?')"
    printf '%-46s %-9s %s\n' "$ref" "PULLED" "$arch"
    AVAILABLE+=("$ref")
  else
    reason="$(printf '%s' "$out" | grep -v '^$' | tail -1 | cut -c1-70)"
    printf '%-46s %-9s %s\n' "$ref" "failed" "$reason"
  fi
done

echo
echo "MinIO without a registry: is the official binary still served?"
echo "----------------------------------------------------------------------"
# If this answers 200, MinIO remains usable: a three-line Dockerfile can
# fetch the binary and pin it BY SHA256 CHECKSUM, which is as strong as a
# digest for reproducibility. B-6 rejected build-time downloads for the
# sharing server because a registry digest was available and better; here
# there may be no digest to prefer, which changes the trade.
for url in \
  "https://dl.min.io/server/minio/release/linux-amd64/minio" \
  "https://dl.min.io/server/minio/release/linux-amd64/minio.sha256sum"
do
  code="$(curl -s -o /dev/null -w '%{http_code}' -I --max-time 20 "$url" 2>/dev/null || echo 'curl-failed')"
  printf '  %-72s %s\n' "$url" "$code"
done

echo
echo "What quay.io actually says about minio/minio (B-10 evidence):"
echo "----------------------------------------------------------------------"
curl -s --max-time 20 \
  'https://quay.io/api/v1/repository/minio/minio/tag/?limit=5&onlyActiveTags=true' \
  | cut -c1-400
echo

echo
echo "======================================================================"
if [[ ${#AVAILABLE[@]} -eq 0 ]]; then
  echo "Nothing pulled. Report this output -- the next move depends on"
  echo "whether the dl.min.io checks above returned 200."
else
  echo "Obtainable (${#AVAILABLE[@]}):"
  for a in "${AVAILABLE[@]}"; do echo "  $a"; done
  echo
  echo "Report this table. The service definition, core-site.xml endpoint"
  echo "and scripts 10/11 then get written for the winner -- and note that"
  echo "whichever it is, it is a LOCAL STAND-IN for the client's S3/ADLS."
  echo "The s3a:// table location and the pre-signed URL mechanics do not"
  echo "change with the store, which is why this choice does not reopen"
  echo "any test verdict."
fi
