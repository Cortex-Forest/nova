#!/usr/bin/env bash
set -euo pipefail

image="${1:-nova-testnet-seed:local}"
state="$(mktemp -d /tmp/nova-seed-state.XXXXXX)"
chmod 0777 "${state}"

first="$(docker run --rm --network none \
  --mount "type=bind,src=${state},dst=/storage" \
  "${image}" \
  --seed-file /storage/network-seed.hex \
  -- /usr/local/bin/yazimao-node --help 2>&1 |
  sed -n 's/^NOVA_SEED_INIT state=\([^ ]*\).*/\1/p')"

second="$(docker run --rm --network none \
  --mount "type=bind,src=${state},dst=/storage" \
  "${image}" \
  --seed-file /storage/network-seed.hex \
  -- /usr/local/bin/yazimao-node --help 2>&1 |
  sed -n 's/^NOVA_SEED_INIT state=\([^ ]*\).*/\1/p')"

seed_bytes="$(wc -c < "${state}/network-seed.hex")"
carrier="nova-seed-inspect-$(date +%s)"
docker create --name "${carrier}" "${image}" >/dev/null
trap 'docker rm "${carrier}" >/dev/null 2>&1 || true' EXIT
docker cp "${carrier}:/read-only/genesis/genesis.bin" "${state}/genesis.bin"
genesis="$(sha256sum "${state}/genesis.bin" | awk '{print $1}')"

test "${first}" = "created"
test "${second}" = "reused"
test "${seed_bytes}" = "65"
test "${genesis}" = "7d1ec6b9fccceb042e5948a9ca90d984836d57189ffdfd3c00850a82bca54e3d"

printf 'first=%s\nsecond=%s\nseed_bytes=%s\ngenesis=%s\nstate=%s\n' \
  "${first}" "${second}" "${seed_bytes}" "${genesis}" "${state}"
