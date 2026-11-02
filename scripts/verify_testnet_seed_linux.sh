#!/usr/bin/env bash
set -euo pipefail

repo="${1:-/mnt/c/Users/Administrator/nova}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
context="${TMPDIR:-/tmp}/nova-seed-verify-${stamp}"

mkdir -p "${context}/tests"
cp "${repo}/Cargo.toml" "${repo}/Cargo.lock" "${repo}/rust-toolchain.toml" "${context}/"
cp -a "${repo}/crates" "${context}/"
cp -a "${repo}/tests/vectors" "${context}/tests/"
cp "${repo}/Containerfile.testnet-seed" "${context}/Containerfile"
cp "${repo}/genesis-image/genesis.bin" "${context}/genesis.bin"
cp "${repo}/genesis-image/genesis_hash.txt" "${context}/genesis_hash.txt"

docker buildx build \
  --platform linux/amd64 \
  --file "${context}/Containerfile" \
  --target builder \
  --tag nova-testnet-seed-builder:local \
  --load \
  "${context}"

docker run --rm --network none nova-testnet-seed-builder:local \
  sh -lc '
    set -eu
    /usr/local/cargo/bin/cargo test -p nova-node --bin nova-seed-init --locked
    /usr/local/cargo/bin/cargo test -p nova-node --bin nova-validator-init --locked
  '
