#!/usr/bin/env bash
set -euo pipefail

state="$(mktemp -d /tmp/nova-seed-node.XXXXXX)"
chmod 0777 "${state}"
log="${state}/node.log"

docker run --rm --network none \
  --mount "type=bind,src=${state},dst=/storage" \
  nova-testnet-seed:local \
  --seed-file /storage/network-seed.hex \
  -- /usr/local/bin/yazimao-node \
  --genesis /read-only/genesis/genesis.bin \
  --genesis-hash 7d1ec6b9fccceb042e5948a9ca90d984836d57189ffdfd3c00850a82bca54e3d \
  --chain-id 2002 \
  --network-id testnet \
  --storage-dir /storage \
  --network-seed-file /storage/network-seed.hex \
  --listen 0.0.0.0:17770 \
  --run-steps 1 >"${log}" 2>&1

grep -q 'NOVA_SEED_INIT state=created' "${log}"
grep -q 'node_id=' "${log}"
grep -q 'head_height=0' "${log}"
grep -q 'validator_enabled=false' "${log}"
grep -q 'runtime shut down' "${log}"
printf 'PASS node_one_step\nstate=%s\n' "${state}"
