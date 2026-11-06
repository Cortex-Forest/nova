#!/usr/bin/env python3
"""Render a TESTNET_ONLY, provider-visible five-validator peer mesh."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


HEX64 = set("0123456789abcdef")
GENESIS_HASH = "7d1ec6b9fccceb042e5948a9ca90d984836d57189ffdfd3c00850a82bca54e3d"
DEFAULT_IMAGE = (
    "sha256:cae82775c5566977b3d80b5e52c317d020576ea2f392aaf7203a3506e27fbb6d"
)


def is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in HEX64 for char in value)
    )


def check_seed(keygen: Path, seed_file: Path, expected_pubkey: str) -> None:
    result = subprocess.run(
        [
            str(keygen),
            "check-seed",
            "--seed-file",
            str(seed_file),
            "--expect-pubkey",
            expected_pubkey,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"seed check failed for {seed_file.name}")


def read_seed(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not is_hex64(value):
        raise RuntimeError(f"invalid seed file format: {path.name}")
    return value


def restrict_acl(path: Path) -> None:
    account = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"
    result = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:(F)"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        path.unlink(missing_ok=True)
        raise RuntimeError("could not restrict rendered SDL ACL")


def build_document(args: argparse.Namespace) -> tuple[dict, list[dict]]:
    genesis = json.loads(args.genesis_input.read_text(encoding="utf-8"))
    genesis_validators = genesis["validators"]
    validators: list[dict] = []

    for index in range(1, args.validator_count + 1):
        network_seed = args.secrets_root / f"validator-{index}-network.seed"
        consensus_seed = args.secrets_root / f"validator-{index}-consensus.seed"
        network_public_path = args.public_root / "network" / f"validator-{index}.pub.json"
        consensus_public_path = (
            args.public_root / "consensus" / f"validator-{index}.pub.json"
        )
        for required in (
            network_seed,
            consensus_seed,
            network_public_path,
            consensus_public_path,
        ):
            if not required.is_file():
                raise RuntimeError(f"missing Validator-{index} input: {required}")

        network_public = json.loads(network_public_path.read_text(encoding="utf-8"))
        consensus_public = json.loads(
            consensus_public_path.read_text(encoding="utf-8")
        )
        node_id = network_public.get("node_id_hex")
        consensus_pubkey = consensus_public.get("pubkey_hex")
        if not is_hex64(node_id) or not is_hex64(consensus_pubkey):
            raise RuntimeError(f"Validator-{index} public identity is malformed")
        if sum(
            value.get("consensus_public_key") == consensus_pubkey
            for value in genesis_validators
        ) != 1:
            raise RuntimeError(
                f"Validator-{index} consensus public key is not in the frozen Genesis"
            )

        check_seed(args.keygen, network_seed, node_id)
        check_seed(args.keygen, consensus_seed, consensus_pubkey)
        validators.append(
            {
                "index": index,
                "name": f"validator-{index}",
                "port": 17770 + index,
                "node_id": node_id,
                "consensus_pubkey": consensus_pubkey,
                "network_seed": read_seed(network_seed),
                "consensus_seed": read_seed(consensus_seed),
            }
        )

    services: dict[str, object] = {}
    for validator in validators:
        peer_entries = [f"{args.seed_node_id}@{args.seed_host_port}"]
        peer_entries.extend(
            f"{peer['node_id']}@{peer['name']}:{peer['port']}"
            for peer in validators
            if peer["index"] != validator["index"]
        )
        command = [
            "/usr/local/bin/nova-validator-init",
            "--",
            "/usr/local/bin/nova-validator-start",
            "--genesis",
            "/read-only/genesis/genesis.bin",
            "--genesis-hash",
            GENESIS_HASH,
            "--chain-id",
            "2002",
            "--network-id",
            "testnet",
            "--storage-dir",
            "/storage",
            "--safety-dir",
            "/safety",
            "--network-seed-file",
            "/storage/network-seed.hex",
            "--validator-seed-file",
            "/storage/validator-seed.hex",
            "--validator",
            "--listen",
            f"0.0.0.0:{validator['port']}",
        ]
        for peer in peer_entries:
            command.extend(["--peer", peer])
        command.extend(["--idle-ms", "1", "--run-steps", "0"])
        services[validator["name"]] = {
            "image": f"ghcr.io/cortex-forest/nova@{args.image_digest}",
            "command": command,
            "env": [
                f"NOVA_NETWORK_SEED_HEX={validator['network_seed']}",
                f"NOVA_VALIDATOR_SEED_HEX={validator['consensus_seed']}",
                f"NOVA_EXPECTED_NETWORK_NODE_ID={validator['node_id']}",
                f"NOVA_EXPECTED_CONSENSUS_PUBKEY={validator['consensus_pubkey']}",
            ],
            "params": {
                "storage": {
                    "data": {"mount": "/storage"},
                    "safety": {"mount": "/safety"},
                    "anchor": {"mount": "/anchor"},
                }
            },
            "expose": [
                {
                    "port": validator["port"],
                    "as": validator["port"],
                    "proto": "tcp",
                    "to": [{"global": True}],
                }
            ],
        }

    compute = {}
    pricing = {}
    deployment = {}
    for validator in validators:
        compute[validator["name"]] = {
            "resources": {
                "cpu": {"units": 0.5},
                "memory": {"size": "512Mi"},
                "storage": [
                    {"size": "512Mi"},
                    {
                        "name": "data",
                        "size": "4Gi",
                        "attributes": {"persistent": True, "class": "beta1"},
                    },
                    {
                        "name": "safety",
                        "size": "1Gi",
                        "attributes": {"persistent": True, "class": "beta1"},
                    },
                    {
                        "name": "anchor",
                        "size": "1Gi",
                        "attributes": {"persistent": True, "class": "beta1"},
                    },
                ],
            }
        }
        pricing[validator["name"]] = {"denom": "uact", "amount": 10000}
        deployment[validator["name"]] = {
            "akash": {"profile": validator["name"], "count": 1}
        }

    document = {
        "version": "2.0",
        "services": services,
        "profiles": {
            "compute": compute,
            "placement": {"akash": {"pricing": pricing}},
        },
        "deployment": deployment,
    }
    return document, validators


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-root", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--genesis-input", type=Path, required=True)
    parser.add_argument("--seed-node-id", required=True)
    parser.add_argument("--seed-host-port", required=True)
    parser.add_argument("--image-digest", default=DEFAULT_IMAGE)
    parser.add_argument("--validator-count", type=int, choices=range(2, 6), default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if not is_hex64(args.seed_node_id):
        raise RuntimeError("seed node id must be 64 lowercase hex")
    if not args.image_digest.startswith("sha256:") or not is_hex64(
        args.image_digest.removeprefix("sha256:")
    ):
        raise RuntimeError("image digest must be immutable sha256")
    host, port = args.seed_host_port.rsplit(":", 1)
    octets = host.split(".")
    if len(octets) != 4 or not all(
        0 <= int(value) <= 255 for value in octets
    ) or not port.isdigit():
        raise RuntimeError("seed peer must be IPv4:port")

    repo = Path(__file__).resolve().parent.parent
    args.keygen = repo / "target" / "debug" / "yazimao-keygen.exe"
    if not args.keygen.is_file():
        subprocess.run(
            [
                "cargo",
                "build",
                "-p",
                "nova-keygen",
                "--bin",
                "yazimao-keygen",
                "--locked",
            ],
            cwd=repo,
            check=True,
        )

    document, validators = build_document(args)
    if args.output is None:
        root = Path(tempfile.mkdtemp(prefix="nova-validator-group-secret-"))
        args.output = root / f"UPLOAD_VALIDATORS_1_TO_{args.validator_count}.yaml"
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite rendered SDL: {args.output}")
    args.output.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    restrict_acl(args.output)
    print(
        json.dumps(
            {
                "status": "RENDERED",
                "output_path": str(args.output.resolve()),
                "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                "validator_count": len(validators),
                "validator_names": [value["name"] for value in validators],
                "validator_node_ids": [value["node_id"] for value in validators],
                "seed_peer": f"{args.seed_node_id}@{args.seed_host_port}",
                "contains_provider_visible_secrets": True,
                "processing_mode": "SINGLE_DEPLOYMENT_PEER_MESH",
                "handling": "LOCAL_TEMP_ONLY_DO_NOT_COMMIT_OR_SHARE",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
