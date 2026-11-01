#!/usr/bin/env bash
set -euo pipefail

repo="${1:-/mnt/c/Users/Administrator/nova}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
context="${TMPDIR:-/tmp}/nova-seed-context-${stamp}"

mkdir -p "${context}/tests"
cp "${repo}/Cargo.toml" "${repo}/Cargo.lock" "${repo}/rust-toolchain.toml" "${context}/"
cp -a "${repo}/crates" "${context}/"
cp -a "${repo}/tests/vectors" "${context}/tests/"
cp "${repo}/Containerfile.testnet-seed" "${context}/Containerfile"
cp "${repo}/genesis-image/genesis.bin" "${context}/genesis.bin"
cp "${repo}/genesis-image/genesis_hash.txt" "${context}/genesis_hash.txt"

expected=7d1ec6b9fccceb042e5948a9ca90d984836d57189ffdfd3c00850a82bca54e3d
actual="$(sha256sum "${context}/genesis.bin" | awk '{print $1}')"
test "${actual}" = "${expected}"
find "${context}" -type f -print0 | sort -z | xargs -0 sha256sum \
  > "${context}/BUILD_CONTEXT.sha256"

docker buildx build \
  --platform linux/amd64 \
  --file "${context}/Containerfile" \
  --tag nova-testnet-seed:local \
  --load \
  "${context}"

docker image inspect nova-testnet-seed:local \
  --format '{{.Id}} {{.Os}}/{{.Architecture}} user={{json .Config.User}} entrypoint={{json .Config.Entrypoint}}'
printf 'CONTEXT=%s\n' "${context}"
