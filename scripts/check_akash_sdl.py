#!/usr/bin/env python3
"""YAZIMAO L1 -- custom Akash SDL structural checker (NOT official Akash validation).

SCOPE / HONEST LABELLING
------------------------
This script is a **local structural check**. It is NOT Akash's official SDL
validation. Akash does not publish (per the official CLI documentation) a
non-interactive `validate` subcommand, and no official `akash` /
`provider-services` binary is available in this environment, so
`deploy/akash/testnet-sdl-v1.yaml` has never been validated by the official
toolchain. Any report that says "SDL valid" on the strength of this script must
be read as "CUSTOM_STATIC_PASS".

What it checks:
  1. schema shape (version, services, profiles.compute, placement pricing, deployment)
  2. duplicate YAML keys (PyYAML silently keeps the last one -- we scan raw text)
  3. the approved fixed topology: 1 bootstrap-only Seed + 7 independent Validators
  4. per-Validator independence: each Validator is its OWN service with count: 1,
     its own listen port, its own identity seed file, and its own persistent
     storage mounts. `count > 1` for a single service is rejected.
  5. persistent-volume declarations: first storage entry is the ephemeral root,
     every additional entry is named + persistent: true, sizes within 5Mi..32Ti
  6. mount wiring: CLI `--storage-dir` / `--safety-dir` must equal the
     `params.storage.<name>.mount` values, because the node's mount guard refuses
     to start unless those exact paths are mount points
  7. storage accounting is reported explicitly (never silently re-interpreted)
  8. the file must cite the official volume-isolation evidence (docs URL), so the
     isolation conclusion cannot silently disappear from the SDL header

Exit code 0 = all checks passed. Exit code 1 = at least one check failed.
Usage: python check_akash_sdl.py [path/to/sdl.yaml]
       python check_akash_sdl.py --selftest   (verify the checker's own detectors)
"""

from __future__ import annotations

import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not an SDL problem
    print("SDL_STRUCT_FAIL (PyYAML missing; install pyyaml to run this checker)")
    sys.exit(2)

DEFAULT_SDL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "akash", "testnet-sdl-v1.yaml"
)

# Official evidence for per-service persistent volume isolation (see report).
ISOLATION_EVIDENCE_URL = "https://akash.network/docs/learn/core-concepts/persistent-storage"

VALIDATOR_SERVICES = ["validator-%d" % i for i in range(1, 8)]
SEED_SERVICE = "seed"
EXPECTED_PORTS = [17770 + i for i in range(8)]


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.errors: list[str] = []

    def chk(self, cond: bool, msg: str) -> None:
        if cond:
            self.passed += 1
        else:
            self.errors.append(msg)

    def note(self, msg: str) -> None:
        print("NOTE: %s" % msg)


def duplicate_keys(raw: str) -> list[str]:
    """Report keys repeated inside the same YAML mapping (indentation frame).

    PyYAML (and most parsers) silently keep the LAST duplicate, which can hide a
    hand-edit mistake. This is a deliberately simple indentation-frame scan:
    a fresh frame is opened for every sequence item, so keys that merely repeat
    across separate list items (e.g. `size:` in two different volumes) are NOT
    reported as duplicates.
    """
    dupes: list[str] = []
    stack: list[tuple[int, set[str]]] = []  # (indent, keys seen at that indent)
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m_seq = re.match(r"^(\s*)-(\s|$)", line)
        if m_seq:
            indent = len(m_seq.group(1).expandtabs(1))
            while stack and stack[-1][0] > indent:
                stack.pop()
            if stack and stack[-1][0] == indent:
                stack[-1] = (indent, set())  # next item of the same sequence
            else:
                stack.append((indent, set()))
            continue
        m = re.match(r"^(\s*)([^:#\s][^:]*):(\s|$)", line)
        if not m:
            continue
        indent = len(m.group(1).expandtabs(1))
        key = m.group(2).strip()
        while stack and stack[-1][0] > indent:
            stack.pop()
        if stack and stack[-1][0] < indent:
            stack.append((indent, set()))
        elif not stack:
            stack.append((indent, set()))
        keys = stack[-1][1]
        if key in keys:
            dupes.append("line %d: duplicate key %r at indent %d" % (lineno, key, indent))
        keys.add(key)
    return dupes


def size_to_gib(value: object) -> int:
    s = str(value)
    if s.endswith("Gi"):
        return int(s[:-2])
    if s.endswith("Mi"):
        return int(s[:-2]) / 1024  # type: ignore[return-value]
    raise ValueError("unsupported size unit: %r" % s)


def argv_value(cmd: list[str], flag: str) -> str | None:
    """Return the token following `flag` in a command argv list (None if absent)."""
    try:
        return cmd[cmd.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def selftest() -> int:
    """Verify the checker's own detectors -- a check that cannot fail proves nothing."""
    failures = 0

    def expect(cond: bool, label: str) -> None:
        nonlocal failures
        if cond:
            print("SELFTEST ok   %s" % label)
        else:
            failures += 1
            print("SELFTEST FAIL %s" % label)

    # a real duplicate inside one mapping must be detected
    expect(bool(duplicate_keys("a: 1\na: 2\n")), "real duplicate at top level is detected")
    expect(bool(duplicate_keys("svc:\n  image: x\n  image: y\n")), "real duplicate nested is detected")
    # repeats across separate sequence items must NOT be reported
    seq = "storage:\n  - name: a\n    size: 1Gi\n  - name: b\n    size: 2Gi\n"
    expect(duplicate_keys(seq) == [], "per-item repeats are not false positives")
    # the real SDL must be duplicate-free
    raw = open(DEFAULT_SDL, encoding="utf-8").read()
    expect(duplicate_keys(raw) == [], "the shipped SDL has no duplicate keys")
    # argv helper
    expect(argv_value(["--listen", "0.0.0.0:17771"], "--listen") == "0.0.0.0:17771", "argv_value finds a flag")
    expect(argv_value(["--listen"], "--listen") is None, "argv_value tolerates a trailing flag")
    # size parser
    expect(size_to_gib("1Gi") == 1 and size_to_gib("59Gi") == 59, "size_to_gib parses Gi")
    print("SELFTEST_%s" % ("OK" if not failures else "FAIL"))
    return 1 if failures else 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return selftest()
    path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SDL)
    raw = open(path, encoding="utf-8").read()
    doc = yaml.safe_load(raw)
    c = Checker()

    print("CUSTOM_STATIC_CHECK (NOT official Akash validation)")
    print("sdl=%s" % path)
    print("bytes=%d" % len(raw.encode("utf-8")))

    # ---- 1. duplicate keys (before schema checks) --------------------------
    dupes = duplicate_keys(raw)
    for d in dupes:
        c.errors.append("duplicate YAML key: %s" % d)
    c.chk(not dupes, "no duplicate YAML keys")

    # ---- 2. schema shape ---------------------------------------------------
    services = doc.get("services") or {}
    profiles = (doc.get("profiles") or {}).get("compute") or {}
    placement = ((doc.get("profiles") or {}).get("placement") or {}).get("akash") or {}
    pricing = placement.get("pricing") or {}
    deployment = doc.get("deployment") or {}

    c.chk(doc.get("version") == "2.0", "version must be 2.0")
    c.chk(set(services) == {SEED_SERVICE, *VALIDATOR_SERVICES}, "services set: %s" % sorted(services))
    c.chk(len(services) == 8, "services == 8 (1 seed + 7 validators), got %d" % len(services))
    c.chk(set(deployment) == set(services), "deployment covers exactly the services")
    c.chk("replicas" not in raw, "SDL must not use 'replicas' (use count)")

    # ---- 3. topology: seed is bootstrap-only -------------------------------
    seed_cmd = list(services[SEED_SERVICE].get("command") or [])
    seed_text = " ".join(seed_cmd)
    c.chk(bool(services[SEED_SERVICE].get("image")), "seed image present")
    c.chk("--validator" not in seed_text, "seed must not run in validator mode")
    c.chk("--safety-dir" not in seed_text, "seed must not declare a safety dir")
    c.chk("--validator-seed-file" not in seed_text, "seed must not carry a validator identity")
    c.chk(seed_text.count("--peer") == 7, "seed must peer with all 7 validators (got %d)" % seed_text.count("--peer"))
    c.chk("0.0.0.0:17770" in seed_text, "seed listen address")
    seed_profile = ((deployment.get(SEED_SERVICE) or {}).get("akash") or {}).get("profile")
    c.chk(seed_profile in profiles, "seed profile resolves: %r" % seed_profile)
    seed_declared = list((profiles.get(seed_profile) or {}).get("resources", {}).get("storage") or [])
    seed_persistent = [e for e in seed_declared if "name" in e]
    c.chk([e["name"] for e in seed_persistent] == ["data"], "seed persistent volumes == ['data']")
    c.chk(len(seed_persistent) == 1, "seed has exactly one persistent volume (no safety volume)")

    # ---- 4. per-validator independence ------------------------------------
    ports_seen: list[int] = []
    for name in VALIDATOR_SERVICES:
        svc = services[name]
        cmd = list(svc.get("command") or [])
        text = " ".join(cmd)
        c.chk(bool(svc.get("image")), "%s image present" % name)
        c.chk("--validator" in cmd, "%s must run in validator mode" % name)
        c.chk("--validator-seed-file" in cmd, "%s must carry its own identity seed file" % name)
        c.chk(argv_value(cmd, "--validator-seed-file") == "/read-only/secrets/validator-seed.hex",
              "%s identity seed path" % name)
        listen = argv_value(cmd, "--listen")
        c.chk(listen == "0.0.0.0:%d" % (17771 + VALIDATOR_SERVICES.index(name)),
              "%s listen must be 0.0.0.0:%d (got %r)" % (name, 17771 + VALIDATOR_SERVICES.index(name), listen))
        if listen and ":" in listen:
            ports_seen.append(int(listen.rsplit(":", 1)[1]))

        # storage dirs must be the mount points themselves (mount guard requirement)
        c.chk(argv_value(cmd, "--storage-dir") == "/storage", "%s --storage-dir must be /storage" % name)
        c.chk(argv_value(cmd, "--safety-dir") == "/safety", "%s --safety-dir must be /safety" % name)

        params = (svc.get("params") or {}).get("storage") or {}
        c.chk(set(params) == {"data", "safety"}, "%s params.storage keys == data,safety (got %s)" % (name, sorted(params)))
        c.chk((params.get("data") or {}).get("mount") == "/storage", "%s data -> /storage" % name)
        c.chk((params.get("safety") or {}).get("mount") == "/safety", "%s safety -> /safety" % name)

        prof_name = ((deployment.get(name) or {}).get("akash") or {}).get("profile")
        c.chk(prof_name in profiles, "%s profile resolves: %r" % (name, prof_name))
        c.chk(((deployment.get(name) or {}).get("akash") or {}).get("count") == 1,
              "%s count must be 1 (7 services, never one service x7)" % name)
        declared = list((profiles.get(prof_name) or {}).get("resources", {}).get("storage") or [])
        names = sorted(e["name"] for e in declared if "name" in e)
        c.chk(names == ["data", "safety"], "%s profile declares data+safety (got %s)" % (name, names))
        c.chk(sorted(params) == names, "%s params.storage must match its profile volumes" % name)

        peers = [cmd[i + 1] for i, tok in enumerate(cmd) if tok == "--peer"]
        c.chk(len(peers) == 7, "%s peer count == 7 (got %d)" % (name, len(peers)))
        c.chk(not any(":%d" % (17771 + VALIDATOR_SERVICES.index(name)) in p for p in peers),
              "%s must not list itself as a peer" % name)
        c.chk(any(p.endswith(":17770") for p in peers), "%s must peer with the seed" % name)

    c.chk(sorted(ports_seen) == EXPECTED_PORTS[1:], "validator listen ports are distinct: %s" % sorted(ports_seen))
    c.chk(len(set(ports_seen)) == 7, "no two validators share a listen port")

    # ---- 5. storage declarations ------------------------------------------
    for prof_name, prof in profiles.items():
        res = prof.get("resources") or {}
        c.chk((res.get("cpu") or {}).get("units") == 2, "%s cpu == 2" % prof_name)
        c.chk((res.get("memory") or {}).get("size") == "4Gi", "%s memory == 4Gi" % prof_name)
        c.chk("gpu" not in res, "%s must not request GPU" % prof_name)
        storage = list(res.get("storage") or [])
        c.chk(len(storage) >= 2, "%s has an ephemeral root plus persistent volumes" % prof_name)
        c.chk(storage and "name" not in storage[0], "%s first storage entry is the ephemeral root (no name)" % prof_name)
        for entry in storage:
            c.chk("size" in entry, "%s storage entry has size" % prof_name)
            gib = size_to_gib(entry.get("size"))
            c.chk(0.0048 <= float(gib) <= 32768, "%s volume size within 5Mi..32Ti (%s)" % (prof_name, entry.get("size")))
        named = [e for e in storage if "name" in e]
        c.chk(all((e.get("attributes") or {}).get("persistent") is True for e in named),
              "%s all named volumes carry attributes.persistent: true" % prof_name)
        for entry in named:
            attrs = entry.get("attributes") or {}
            # The official schema (@akashnetwork/chain-sdk validateSDL) requires an explicit
            # storage class on every named persistent volume; omitting it fails validation.
            if "class" not in attrs:
                c.errors.append("%s volume %r must declare attributes.class "
                                "(required by the official SDL schema)" % (prof_name, entry.get("name")))
            else:
                c.chk(str(attrs.get("class")) in {"default", "beta1", "beta2", "beta3", "ram"},
                      "%s volume %r class value %r" % (prof_name, entry.get("name"), attrs.get("class")))
                c.chk(not (str(attrs.get("class")) == "ram" and attrs.get("persistent") is True),
                      "%s volume %r: ram class must not be persistent" % (prof_name, entry.get("name")))
        total = sum(size_to_gib(e.get("size")) for e in storage)
        persistent = sum(size_to_gib(e.get("size")) for e in named)
        c.note("%s: total=%sGi persistent=%sGi" % (prof_name, total, persistent))

    # explicit accounting for the approved capacity policy (no silent reinterpretation)
    seed_total = sum(size_to_gib(e.get("size")) for e in seed_declared)
    seed_persistent_gib = sum(size_to_gib(e.get("size")) for e in seed_persistent)
    c.chk(seed_total == 60, "seed total storage == 60Gi (got %s)" % seed_total)
    c.chk(seed_persistent_gib == 59, "seed persistent storage == 59Gi (got %s)" % seed_persistent_gib)
    for name in VALIDATOR_SERVICES:
        prof_name = ((deployment.get(name) or {}).get("akash") or {}).get("profile")
        storage = (profiles.get(prof_name) or {}).get("resources", {}).get("storage") or []
        total = sum(size_to_gib(e.get("size")) for e in storage)
        persistent = sum(size_to_gib(e.get("size")) for e in storage if "name" in e)
        c.chk(total == 60, "%s total storage == 60Gi (got %s)" % (name, total))
        c.chk(persistent == 59, "%s persistent storage == 59Gi (got %s)" % (name, persistent))

    # ---- 6. pricing for every compute profile actually used ----------------
    for prof_name in profiles:
        c.chk(prof_name in pricing, "pricing entry for compute profile %r" % prof_name)
        c.chk((pricing.get(prof_name) or {}).get("denom") in {"uakt", "uact"},
              "pricing denom for %r" % prof_name)

    # ---- 7. expose / global reachability ----------------------------------
    for name, svc in services.items():
        expose = svc.get("expose") or []
        c.chk(len(expose) == 1, "%s has exactly one expose entry" % name)
        if expose:
            c.chk(expose[0].get("to") == [{"global": True}], "%s exposes globally" % name)
            port = expose[0].get("port")
            c.chk(port in EXPECTED_PORTS, "%s expose port in approved set (%r)" % (name, port))

    # ---- 8. evidence citation must stay in the file ------------------------
    c.chk(ISOLATION_EVIDENCE_URL in raw, "SDL header must cite the official volume-isolation evidence")
    c.chk("Not Shared Between Services" in raw, "SDL header must quote the official isolation statement")
    c.chk("CUSTOM_STATIC_CHECK" in raw or "custom" in raw.lower(),
          "SDL header must state that validation is custom, not official")

    validator_total = 0
    for name in VALIDATOR_SERVICES:
        prof_name = ((deployment.get(name) or {}).get("akash") or {}).get("profile")
        storage = (profiles.get(prof_name) or {}).get("resources", {}).get("storage") or []
        validator_total += sum(size_to_gib(e.get("size")) for e in storage)
    print("host_total_storage_gib=%d (seed %d + validators %d)"
          % (seed_total + validator_total, seed_total, validator_total))
    print("SDL_STRUCT_%s" % ("OK" if not c.errors else "FAIL"))
    print("checks_passed=%d checks_failed=%d" % (c.passed, len(c.errors)))
    for e in c.errors:
        print("FAIL: %s" % e)
    return 1 if c.errors else 0


if __name__ == "__main__":
    sys.exit(main())
