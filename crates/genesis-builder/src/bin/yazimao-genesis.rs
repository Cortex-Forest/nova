//! `yazimao-genesis` — YAZIMAO 生产 Genesis 构建 / 复核 CLI（无第三方 CLI 依赖）。
//!
//! ```text
//! yazimao-genesis build  --input <genesis.json> --out-dir <dir> [--force]
//! yazimao-genesis verify --genesis <genesis.bin> --hash <genesis_hash.txt>
//! yazimao-genesis --help | --version
//! ```
//!
//! 退出码：`0` 成功 ｜ `1` 用法错误 ｜ `2` 操作失败（解析 / 预检 / I-O / 复核失败）。
//! CLI 仅负责参数解析与结果打印，**不含任何编码 / 校验逻辑**（全部在库中）。

use std::path::PathBuf;
use std::process::ExitCode;

use nova_genesis_builder::{build_artifacts, verify_artifacts};

const USAGE: &str = "\
yazimao-genesis — YAZIMAO production Genesis builder (JSON -> canonical genesis.bin + hash)

USAGE:
  yazimao-genesis build  --input <genesis.json> --out-dir <dir> [--force]
  yazimao-genesis verify --genesis <genesis.bin> --hash <genesis_hash.txt>
  yazimao-genesis --help | --version

BUILD:
  --input <path>     strict genesis.json (see docs/genesis/genesis-input-schema-v1.md)
  --out-dir <path>   output directory (created if missing)
  --force            allow overwriting existing artifacts (default: refuse)

  outputs: genesis.bin, genesis_hash.txt, genesis_summary.json

VERIFY (read-only):
  --genesis <path>   canonical genesis.bin
  --hash <path>      genesis_hash.txt (64 lowercase hex)

EXIT CODES:
  0 success | 1 usage error | 2 operation failure

SECURITY:
  private keys / seeds / mnemonics are NEVER accepted (unknown+forbidden fields are rejected).
  no default values; genesis_timestamp must be provided by the owner (never auto-generated).";

enum CliExit {
    Usage(String),
    Failure(String),
}

impl CliExit {
    fn message(&self) -> &str {
        match self {
            Self::Usage(m) | Self::Failure(m) => m,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(exit) => {
            eprintln!("error: {}", exit.message());
            if matches!(exit, CliExit::Usage(_)) {
                eprintln!();
                eprintln!("{USAGE}");
                ExitCode::from(1u8)
            } else {
                ExitCode::from(2u8)
            }
        }
    }
}

fn run(args: &[String]) -> Result<(), CliExit> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(CliExit::Usage("missing subcommand".to_string()));
    };
    match command {
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        "--version" | "-V" | "version" => {
            println!("yazimao-genesis {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "build" => run_build(&args[1..]),
        "verify" => run_verify(&args[1..]),
        other => Err(CliExit::Usage(format!("unknown subcommand `{other}`"))),
    }
}

fn run_build(rest: &[String]) -> Result<(), CliExit> {
    let mut input: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut force = false;

    let mut i = 0usize;
    while i < rest.len() {
        let arg = rest[i].as_str();
        match arg {
            "--input" => {
                if input.is_some() {
                    return Err(CliExit::Usage("duplicate `--input`".to_string()));
                }
                input = Some(take_value(rest, &mut i, "--input")?);
            }
            "--out-dir" => {
                if out_dir.is_some() {
                    return Err(CliExit::Usage("duplicate `--out-dir`".to_string()));
                }
                out_dir = Some(take_value(rest, &mut i, "--out-dir")?);
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => {
                return Err(CliExit::Usage(format!("unknown argument `{other}`")));
            }
        }
    }

    let input = input.ok_or_else(|| CliExit::Usage("missing required `--input`".to_string()))?;
    let out_dir =
        out_dir.ok_or_else(|| CliExit::Usage("missing required `--out-dir`".to_string()))?;

    let text =
        std::fs::read_to_string(&input).map_err(|e| CliExit::Failure(format!("{input}: {e}")))?;

    let report = build_artifacts(&text, PathBuf::from(&out_dir).as_path(), force)
        .map_err(|e| CliExit::Failure(e.to_string()))?;

    println!("genesis.bin          : {}", report.genesis_bin.display());
    println!(
        "genesis_hash.txt     : {}",
        report.genesis_hash_file.display()
    );
    println!(
        "genesis_summary.json : {}",
        report.genesis_summary_file.display()
    );
    println!("network_id           : {:#04x}", report.network_id);
    println!("chain_id             : {}", report.chain_id);
    println!("genesis_timestamp    : {}", report.genesis_timestamp);
    println!("canonical_len        : {}", report.canonical_len);
    println!("genesis_hash         : {}", report.genesis_hash_hex);
    println!("validators           : {}", report.validator_count);
    println!("accounts             : {}", report.account_count);
    println!(
        "reordered            : validators={} accounts={}",
        report.reorder.validators_reordered, report.reorder.accounts_reordered
    );
    println!("OK: artifacts written (self-verified via decode + validate)");
    Ok(())
}

fn run_verify(rest: &[String]) -> Result<(), CliExit> {
    let mut genesis: Option<String> = None;
    let mut hash: Option<String> = None;

    let mut i = 0usize;
    while i < rest.len() {
        let arg = rest[i].as_str();
        match arg {
            "--genesis" => {
                if genesis.is_some() {
                    return Err(CliExit::Usage("duplicate `--genesis`".to_string()));
                }
                genesis = Some(take_value(rest, &mut i, "--genesis")?);
            }
            "--hash" => {
                if hash.is_some() {
                    return Err(CliExit::Usage("duplicate `--hash`".to_string()));
                }
                hash = Some(take_value(rest, &mut i, "--hash")?);
            }
            other => {
                return Err(CliExit::Usage(format!("unknown argument `{other}`")));
            }
        }
    }

    let genesis =
        genesis.ok_or_else(|| CliExit::Usage("missing required `--genesis`".to_string()))?;
    let hash = hash.ok_or_else(|| CliExit::Usage("missing required `--hash`".to_string()))?;

    let report = verify_artifacts(
        PathBuf::from(&genesis).as_path(),
        PathBuf::from(&hash).as_path(),
    )
    .map_err(|e| CliExit::Failure(e.to_string()))?;

    println!("network_id        : {:#04x}", report.network_id);
    println!("chain_id          : {}", report.chain_id);
    println!("genesis_timestamp : {}", report.genesis_timestamp);
    println!("canonical_len     : {}", report.canonical_len);
    println!("genesis_hash      : {}", report.genesis_hash_hex);
    println!("validators        : {}", report.validator_count);
    println!("accounts          : {}", report.account_count);
    println!("OK: genesis.bin decoded + validated against genesis_hash.txt");
    Ok(())
}

fn take_value(rest: &[String], i: &mut usize, flag: &str) -> Result<String, CliExit> {
    let value = rest
        .get(*i + 1)
        .ok_or_else(|| CliExit::Usage(format!("`{flag}` requires a value")))?;
    if value.starts_with("--") {
        return Err(CliExit::Usage(format!("`{flag}` requires a value")));
    }
    *i += 2;
    Ok(value.clone())
}
