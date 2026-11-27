#!/usr/bin/env bash
# Verify a published JEV Reflex release the way an operator would.
#
#   scripts/verify-release.sh v0.3.0
#
# Requires: gh (authenticated), cosign 2.6+ or 3.x, docker, python3.11+, helm, yq.
# Checks, in order, and stops at the first failure:
#   1. the broker image signature, bound to the tag-triggered release workflow;
#   2. the SPDX SBOM attestation on that image, bound to the same identity;
#   3. that the same signature does not verify for a branch identity (the pin matters);
#   4. the release wheel installs into a clean virtualenv and its CLI enforces;
#   5. the image starts healthy with the release's Helm configuration, read-only,
#      without network access and with every capability dropped.
# The wheel and sdist are not signed or attested; step 4 checks behaviour, and the
# script prints their SHA-256 so they can be compared with any other copy (PyPI).
set -euo pipefail

tag=${1:?usage: verify-release.sh vX.Y.Z}
version=${tag#v}
repo=${JRX_REPOSITORY:-Madhumasa84/jrx}
image=${JRX_IMAGE:-ghcr.io/madhumasa84/jrx-broker}
python=${PYTHON:-python3.11}
identity="https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}"
issuer="https://token.actions.githubusercontent.com"
work=$(mktemp -d)
trap 'docker stop "${container:-none}" >/dev/null 2>&1 || true' EXIT

digest=$(docker buildx imagetools inspect "${image}:${version}" --format '{{json .Manifest}}' |
  "$python" -c 'import json, sys; print(json.load(sys.stdin)["digest"])')
pinned="${image}@${digest}"
echo "image: ${pinned}"

echo "1. image signature"
cosign verify "$pinned" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" >/dev/null
echo "2. SBOM attestation (spdxjson)"
cosign verify-attestation "$pinned" --type spdxjson \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" >/dev/null
echo "3. a branch identity is rejected"
if cosign verify "$pinned" --certificate-identity "https://github.com/${repo}/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "$issuer" >/dev/null 2>&1; then
  echo "signature verified for a branch identity; the identity pin is not effective" >&2
  exit 1
fi

echo "4. release wheel in a clean virtualenv"
gh release download "$tag" -R "$repo" --dir "$work/dist" \
  --pattern "jev_reflex-${version}-py3-none-any.whl" --pattern "jev_reflex-${version}.tar.gz"
(cd "$work/dist" && sha256sum ./*)
"$python" -m venv "$work/venv"
"$work/venv/bin/pip" install --quiet "$work/dist/jev_reflex-${version}-py3-none-any.whl"
"$work/venv/bin/pip" check
cp "$work/venv/share/jev-reflex/reflex.example.yaml" "$work/reflex.yaml"
decision=$(cd "$work" && "$work/venv/bin/jrx" check --config reflex.yaml --demo \
  --command 'rm -rf ./cache' --json | "$python" -c 'import json, sys; print(json.load(sys.stdin)["decision"])')
test "$decision" = HOLD

echo "5. image startup with the release Helm configuration"
mkdir -p "$work/chart"
gh api "repos/${repo}/tarball/${tag}" > "$work/source.tar.gz"
tar -xzf "$work/source.tar.gz" -C "$work/chart" --strip-components=1
helm template release "$work/chart/helm/jrx-broker" --show-only templates/configmap.yaml |
  yq -r '.data."reflex.yaml"' > "$work/broker-reflex.yaml"
uid=$(helm show values "$work/chart/helm/jrx-broker" | yq '.podSecurityContext.runAsUser')
container=$(docker run --rm --detach --network none --user "$uid" --read-only --cap-drop ALL \
  --tmpfs /tmp:mode=1777 --health-interval=2s \
  --mount "type=bind,src=$work/broker-reflex.yaml,dst=/home/jrx/reflex.yaml,readonly" "$pinned")
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ] && break
  sleep 2
done
test "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy
docker exec "$container" python -m pip check >/dev/null
echo "release ${tag} verified"
