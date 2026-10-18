#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YAZIMAO Genesis Freeze Record — fail-closed 校验器（R11，新增，**附加式**）。

用途
----
`yazimao-genesis build/verify` 只校验 **Genesis 数据本身**（结构 / 语义 / hash），
它**无法**证明"Owner 已批准"、"复核人是第二人"、"hash 已经独立渠道分发"。
这些是**流程性**前置条件。本脚本把它们变成**可机器检查**的显式记录。

设计约束（重要）
----------------
1. **不修改** `yazimao-genesis` 的 CLI 契约（不新增必填 flag），避免破坏既有
   审计用例与向后兼容。
2. **fail-closed**：任何缺失 / 空值 / 占位值 / 格式不符 / 双人规则违反 ⇒ 退出码 1。
3. **不生成、不推断、不填补**任何值；本脚本只做**判定**。
4. 不接触私钥 / seed / mnemonic / keystore；记录中出现这些键名 ⇒ 直接失败。

用法
----
    python scripts/check_genesis_freeze.py --selftest
    python scripts/check_genesis_freeze.py --record freeze-record.json
    python scripts/check_genesis_freeze.py --template > freeze-record.json   # 空模板

冻结记录 schema（JSON，字段全部必填）
------------------------------------
{
  "profile": "testnet",
  "chain_id": 2002,
  "network_id": 2,
  "genesis_timestamp": <int > 0>,
  "validator_count": 7,
  "account_count": <int > 0>,
  "total_supply": "1000000000",
  "account_liquid_sum": "1000000000",
  "validator_bonded_sum": "<decimal string>",
  "validator_liquid_sum": "<decimal string>",
  "canonical_len": <int>,
  "genesis_hash": "<64 lowercase hex>",
  "generated_by": "<name>",
  "generated_at": "<YYYY-MM-DD>",
  "verify_command": "yazimao-genesis verify --genesis <path> --hash <path>",
  "verify_exit_code": 0,
  "reviewed_by": "<name>",
  "reviewed_at": "<YYYY-MM-DD>",
  "distributed_via": "<channel description>",
  "owner_approved_by": "<name>",
  "owner_approved_at": "<YYYY-MM-DD>"
}
"""

from __future__ import annotations

import io
import json
import re
import sys

# ---------------------------------------------------------------- 常量

TESTNET_PROFILE = "testnet"
TESTNET_CHAIN_ID = 2002
TESTNET_NETWORK_ID = 2
TESTNET_VALIDATORS = 7
ADR_0051_TOTAL_SUPPLY = 1000000000

FORBIDDEN_KEYS = ("private_key", "seed", "mnemonic", "secret", "keystore", "passphrase")
PLACEHOLDER_PATTERN = re.compile(
    r"(REPLACE|TBD|TODO|PENDING|PLACEHOLDER|FIXME|XXX|待定|待填|<.*?>)", re.IGNORECASE
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")

TEMPLATE = {
    "profile": TESTNET_PROFILE,
    "chain_id": TESTNET_CHAIN_ID,
    "network_id": TESTNET_NETWORK_ID,
    "genesis_timestamp": 0,
    "validator_count": TESTNET_VALIDATORS,
    "account_count": 0,
    "total_supply": str(ADR_0051_TOTAL_SUPPLY),
    "account_liquid_sum": str(ADR_0051_TOTAL_SUPPLY),
    "validator_bonded_sum": "",
    "validator_liquid_sum": "",
    "canonical_len": 0,
    "genesis_hash": "",
    "generated_by": "",
    "generated_at": "",
    "verify_command": "",
    "verify_exit_code": 0,
    "reviewed_by": "",
    "reviewed_at": "",
    "distributed_via": "",
    "owner_approved_by": "",
    "owner_approved_at": "",
}

REQUIRED_STRINGS = (
    "profile",
    "total_supply",
    "account_liquid_sum",
    "validator_bonded_sum",
    "validator_liquid_sum",
    "genesis_hash",
    "generated_by",
    "generated_at",
    "verify_command",
    "reviewed_by",
    "reviewed_at",
    "distributed_via",
    "owner_approved_by",
    "owner_approved_at",
)

# ---------------------------------------------------------------- 校验


def _is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _bad_text(value) -> bool:
    return isinstance(value, str) and PLACEHOLDER_PATTERN.search(value) is not None


def canonical_len_formula(validator_count: int, account_count: int) -> int:
    """docs/genesis/genesis-freeze-workflow-v1.md §3.5 的 canonical 长度公式。"""
    return 1 + 8 + 8 + 4 + 85 * validator_count + 4 + 51 * account_count + 40 + 42


def validate(record) -> list:
    """返回失败原因列表；空列表 = 通过。"""
    errors: list = []

    if not isinstance(record, dict):
        return ["record 必须是 JSON 对象"]

    # 0) 禁止键（递归）
    def scan_keys(node, path="$"):
        if isinstance(node, dict):
            for key, value in node.items():
                if any(bad in str(key).lower() for bad in FORBIDDEN_KEYS):
                    errors.append("禁止键: %s.%s" % (path, key))
                scan_keys(value, "%s.%s" % (path, key))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                scan_keys(item, "%s[%d]" % (path, i))

    scan_keys(record)

    # 1) 必填 + 非空 + 无占位
    for key in REQUIRED_STRINGS:
        if key not in record:
            errors.append("缺失字段: %s" % key)
        elif _is_blank(record[key]):
            errors.append("字段为空: %s" % key)
        elif _bad_text(record[key]):
            errors.append("字段含占位值: %s=%r" % (key, record[key]))

    # 2) profile / chain / network
    if record.get("profile") != TESTNET_PROFILE:
        errors.append("profile 必须为 %r" % TESTNET_PROFILE)
    if record.get("chain_id") != TESTNET_CHAIN_ID:
        errors.append("chain_id 必须为 %d" % TESTNET_CHAIN_ID)
    if record.get("network_id") != TESTNET_NETWORK_ID:
        errors.append("network_id 必须为 %d" % TESTNET_NETWORK_ID)

    # 3) timestamp
    ts = record.get("genesis_timestamp")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
        errors.append("genesis_timestamp 必须为正整数（> 0）")

    # 4) 计数
    vc = record.get("validator_count")
    ac = record.get("account_count")
    if vc != TESTNET_VALIDATORS:
        errors.append("validator_count 必须为 %d" % TESTNET_VALIDATORS)
    if not isinstance(ac, int) or isinstance(ac, bool) or ac <= 0:
        errors.append("account_count 必须为正整数")

    # 5) 供应不变量
    for key in ("total_supply", "account_liquid_sum", "validator_bonded_sum", "validator_liquid_sum"):
        value = record.get(key)
        if isinstance(value, str) and value and not DECIMAL.match(value):
            errors.append("%s 必须是十进制字符串（无前导零/符号/小数点）: %r" % (key, value))

    supply = record.get("total_supply")
    liquid = record.get("account_liquid_sum")
    if isinstance(supply, str) and DECIMAL.match(supply or ""):
        if int(supply) != ADR_0051_TOTAL_SUPPLY:
            errors.append("total_supply 必须为 ADR-0051 固定供应 %d" % ADR_0051_TOTAL_SUPPLY)
    if (
        isinstance(supply, str)
        and isinstance(liquid, str)
        and DECIMAL.match(supply or "")
        and DECIMAL.match(liquid or "")
        and int(supply) != int(liquid)
    ):
        errors.append("Σ account_liquid 必须等于 total_supply")

    bonded = record.get("validator_bonded_sum")
    vliquid = record.get("validator_liquid_sum")
    if isinstance(bonded, str) and isinstance(vliquid, str) and DECIMAL.match(bonded or "") and DECIMAL.match(vliquid or ""):
        if int(bonded) > int(vliquid):
            errors.append("validator_bonded_sum 必须 <= validator_liquid_sum")

    # 6) hash 格式
    digest = record.get("genesis_hash")
    if isinstance(digest, str) and digest and not HEX64.match(digest):
        errors.append("genesis_hash 必须是 64 位小写十六进制")

    # 7) verify 证据
    if record.get("verify_exit_code") != 0:
        errors.append("verify_exit_code 必须为 0")
    command = record.get("verify_command")
    if isinstance(command, str) and command.strip():
        if "--genesis" not in command or "--hash" not in command:
            errors.append("verify_command 必须同时包含 --genesis 与 --hash")

    # 8) canonical_len 公式
    clen = record.get("canonical_len")
    if isinstance(vc, int) and isinstance(ac, int) and vc > 0 and ac > 0:
        expected = canonical_len_formula(vc, ac)
        if clen != expected:
            errors.append("canonical_len 必须等于公式值 %d（实际 %r）" % (expected, clen))

    # 9) 日期格式
    for key in ("generated_at", "reviewed_at", "owner_approved_at"):
        value = record.get(key)
        if isinstance(value, str) and value.strip() and not DATE.match(value):
            errors.append("%s 必须是 YYYY-MM-DD: %r" % (key, value))

    # 10) 双人规则 / 分离职责
    if record.get("generated_by") == record.get("reviewed_by") and not _is_blank(record.get("generated_by")):
        errors.append("reviewed_by 必须是生成者以外的人（双人规则）")
    if record.get("owner_approved_by") == record.get("generated_by") and not _is_blank(record.get("generated_by")):
        errors.append("owner_approved_by 不能与 generated_by 相同")

    return errors


# ---------------------------------------------------------------- 自检


def _good_record() -> dict:
    rec = dict(TEMPLATE)
    rec.update(
        {
            "genesis_timestamp": 1750000000,
            "account_count": 5,
            "validator_bonded_sum": "70000000",
            "validator_liquid_sum": "100000000",
            "canonical_len": canonical_len_formula(7, 5),
            "genesis_hash": "0" * 64,
            "generated_by": "operator-a",
            "generated_at": "2026-10-18",
            "verify_command": "yazimao-genesis verify --genesis g.bin --hash g.txt",
            "verify_exit_code": 0,
            "reviewed_by": "reviewer-b",
            "reviewed_at": "2026-10-18",
            "distributed_via": "independent release channel #1",
            "owner_approved_by": "owner",
            "owner_approved_at": "2026-10-18",
        }
    )
    return rec


def selftest() -> int:
    failures = []
    total = 0

    def case(name, record, must_pass):
        nonlocal total
        total += 1
        errs = validate(record)
        passed = not errs
        ok = passed == must_pass
        print("%-58s %s (errors=%d)" % (name, "ok" if ok else "MISMATCH", len(errs)))
        if not ok:
            failures.append(name)
        elif not must_pass:
            print("    rejected because: %s" % errs[0])

    # 1) 空模板必须失败（fail-closed：缺 Owner 数据不可通过）
    case("empty template must FAIL", dict(TEMPLATE), False)
    # 2) 完整记录必须通过
    case("complete synthetic record must PASS", _good_record(), True)
    # 3) hash 大写必须失败
    rec = _good_record()
    rec["genesis_hash"] = "A" * 64
    case("uppercase hash must FAIL", rec, False)
    # 4) hash 长度错误必须失败
    rec = _good_record()
    rec["genesis_hash"] = "0" * 63
    case("short hash must FAIL", rec, False)
    # 5) 复核人 == 生成者必须失败
    rec = _good_record()
    rec["reviewed_by"] = rec["generated_by"]
    case("reviewer == generator must FAIL", rec, False)
    # 6) 占位值必须失败
    rec = _good_record()
    rec["distributed_via"] = "REPLACE_CHANNEL"
    case("placeholder text must FAIL", rec, False)
    # 7) timestamp = 0 必须失败
    rec = _good_record()
    rec["genesis_timestamp"] = 0
    case("zero timestamp must FAIL", rec, False)
    # 8) 供应不等于 ADR-0051 必须失败
    rec = _good_record()
    rec["total_supply"] = "980000000"
    rec["account_liquid_sum"] = "980000000"
    case("non-ADR0051 supply must FAIL", rec, False)
    # 9) 分配合计不等必须失败
    rec = _good_record()
    rec["account_liquid_sum"] = "999999999"
    case("liquid sum != supply must FAIL", rec, False)
    # 10) canonical_len 不符必须失败
    rec = _good_record()
    rec["canonical_len"] = 1
    case("wrong canonical_len must FAIL", rec, False)
    # 11) verify 未通过必须失败
    rec = _good_record()
    rec["verify_exit_code"] = 1
    case("verify_exit_code != 0 must FAIL", rec, False)
    # 12) 禁止键必须失败
    rec = _good_record()
    rec["seed"] = "x"
    case("forbidden key must FAIL", rec, False)
    # 13) 十进制字符串非法必须失败
    rec = _good_record()
    rec["validator_bonded_sum"] = "070000000"
    case("leading-zero decimal must FAIL", rec, False)
    # 14) bonded > liquid 必须失败
    rec = _good_record()
    rec["validator_bonded_sum"] = "200000000"
    case("bonded > liquid must FAIL", rec, False)
    # 15) 日期格式错误必须失败
    rec = _good_record()
    rec["reviewed_at"] = "2026/10/18"
    case("bad date format must FAIL", rec, False)
    # 16) 空字符串字段必须失败
    rec = _good_record()
    rec["owner_approved_by"] = ""
    case("empty owner approval must FAIL", rec, False)

    print("")
    print("selftest: %d cases, %d mismatches" % (total, len(failures)))
    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    print("SELFTEST_OK")
    return 0


# ---------------------------------------------------------------- main


def main(argv) -> int:
    if "--selftest" in argv:
        return selftest()
    if "--template" in argv:
        sys.stdout.write(json.dumps(TEMPLATE, indent=2, ensure_ascii=False) + "\n")
        return 0
    if "--record" in argv:
        idx = argv.index("--record")
        if idx + 1 >= len(argv):
            sys.stderr.write("--record 需要文件路径\n")
            return 2
        path = argv[idx + 1]
        try:
            with io.open(path, encoding="utf-8") as handle:
                record = json.load(handle)
        except FileNotFoundError:
            sys.stderr.write("FREEZE_RECORD_MISSING: %s\n" % path)
            return 1
        except ValueError as exc:
            sys.stderr.write("FREEZE_RECORD_NOT_JSON: %s\n" % exc)
            return 1
        errors = validate(record)
        if errors:
            sys.stderr.write("FREEZE_RECORD_REJECTED (%d):\n" % len(errors))
            for item in errors:
                sys.stderr.write("  - %s\n" % item)
            return 1
        sys.stdout.write("FREEZE_RECORD_OK\n")
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
