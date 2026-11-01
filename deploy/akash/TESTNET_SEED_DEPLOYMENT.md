# Minimal Testnet Seed Deployment

This deployment is deliberately limited to one Seed service.

- image:
  `ghcr.io/cortex-forest/nova@sha256:f440b26b59eeb4bf59b6eea1909d8df8a91c7614fd73e6cc0fd6d43ebf610709`
- Genesis:
  `7d1ec6b9fccceb042e5948a9ca90d984836d57189ffdfd3c00850a82bca54e3d`
- service count: 1
- resources: 0.5 CPU / 512 MiB RAM / 5 GiB persistent `beta1`
- exposed TCP port: `17770`
- network identity: generated on first boot inside the persistent volume
- Validator mode: disabled

The image is public. The first boot creates `/storage/network-seed.hex`
with mode `0600`, validates it on every restart, and never prints its value.

This `LOW_BUDGET_STAGING` profile is constrained by the Owner's USD 10-20/year
budget. It is not the approved full-Testnet capacity profile and must not be
used to claim full workload sizing.

## Boundaries

This is a staging foothold, not a live L1:

- one node has no seven-validator consensus;
- head height and finality must remain `0`/`none`;
- it does not prove Bridge, Explorer, RPC, fault recovery or full Testnet
  acceptance;
- closing the lease destroys provider-local persistent state unless it has
  been separately exported.

## Static Validation

```bash
akt sdl validate deploy/akash/testnet-seed-sdl-v1.yaml
```

Expected result:

```text
valid: 1 service(s), 1 group(s), 0 warning(s)
```
