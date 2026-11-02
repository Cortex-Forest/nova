//! Validator startup guard for the low-budget Console Air deployment.
//!
//! This is a TESTNET-ONLY, Provider-visible software-key path explicitly
//! accepted by the Owner. It reads two seed values from environment variables
//! only on first boot, writes them to persistent files with mode 0600, removes
//! the variables from the child environment, drops to UID/GID 10001, and then
//! executes `nova-validator-start`.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;
use std::process::ExitCode;

use zeroize::Zeroizing;

use nova_crypto::signature::SigningKey;
use nova_network::node_id::NodeId;

const VALIDATOR_START_BIN: &str = "/usr/local/bin/nova-validator-start";
const NETWORK_SEED_VAR: &str = "NOVA_NETWORK_SEED_HEX";
const VALIDATOR_SEED_VAR: &str = "NOVA_VALIDATOR_SEED_HEX";
const EXPECTED_NODE_ID_VAR: &str = "NOVA_EXPECTED_NETWORK_NODE_ID";
const EXPECTED_CONSENSUS_PUBKEY_VAR: &str = "NOVA_EXPECTED_CONSENSUS_PUBKEY";
const STORAGE_ROOT: &str = "/storage";
const SAFETY_ROOT: &str = "/safety";
const ANCHOR_ROOT: &str = "/anchor";
const NETWORK_SEED_FILE: &str = "/storage/network-seed.hex";
const VALIDATOR_SEED_FILE: &str = "/storage/validator-seed.hex";
const SERVICE_UID: u32 = 10001;
#[cfg_attr(not(unix), allow(dead_code))]
const SERVICE_GID: u32 = 10001;
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_IOERR: u8 = 74;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    Created,
    Reused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatorInitError {
    Usage,
    MissingSeed,
    InvalidSeed,
    IdentityMismatch,
    Directory,
    Metadata,
    Read,
    Create,
    Write,
    Ownership,
    #[cfg_attr(not(unix), allow(dead_code))]
    Exec,
}

impl ValidatorInitError {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => EX_USAGE,
            Self::MissingSeed | Self::InvalidSeed | Self::IdentityMismatch => EX_DATAERR,
            Self::Directory
            | Self::Metadata
            | Self::Read
            | Self::Create
            | Self::Write
            | Self::Ownership
            | Self::Exec => EX_IOERR,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::MissingSeed => "missing_seed",
            Self::InvalidSeed => "invalid_seed",
            Self::IdentityMismatch => "identity_mismatch",
            Self::Directory => "directory",
            Self::Metadata => "metadata",
            Self::Read => "read",
            Self::Create => "create",
            Self::Write => "write",
            Self::Ownership => "ownership",
            Self::Exec => "exec",
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NOVA_VALIDATOR_INIT error={}", error.code());
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(args: &[OsString]) -> Result<(), ValidatorInitError> {
    let node_args = parse(args)?;
    prepare_root(Path::new(STORAGE_ROOT))?;
    prepare_root(Path::new(SAFETY_ROOT))?;
    prepare_root(Path::new(ANCHOR_ROOT))?;

    let network_env = read_seed_env(NETWORK_SEED_VAR)?;
    let validator_env = read_seed_env(VALIDATOR_SEED_VAR)?;
    let network_state = ensure_seed_file(
        Path::new(NETWORK_SEED_FILE),
        network_env.as_ref().map(|value| value.as_str()),
        NETWORK_SEED_VAR,
    )?;
    let validator_state = ensure_seed_file(
        Path::new(VALIDATOR_SEED_FILE),
        validator_env.as_ref().map(|value| value.as_str()),
        VALIDATOR_SEED_VAR,
    )?;
    validate_identity()?;

    eprintln!(
        "NOVA_VALIDATOR_INIT network_seed={} validator_seed={} runtime_uid={SERVICE_UID}",
        file_state(network_state),
        file_state(validator_state)
    );
    exec_validator(&node_args)
}

const fn file_state(state: FileState) -> &'static str {
    match state {
        FileState::Created => "created",
        FileState::Reused => "reused",
    }
}

fn parse(args: &[OsString]) -> Result<Vec<OsString>, ValidatorInitError> {
    if args.len() < 2 || args[0] != "--" || args[1] != VALIDATOR_START_BIN {
        return Err(ValidatorInitError::Usage);
    }
    Ok(args[1..].to_vec())
}

fn read_seed_env(name: &str) -> Result<Option<Zeroizing<String>>, ValidatorInitError> {
    match std::env::var(name) {
        Ok(value) => {
            let normalized = normalize_env_text(&value);
            eprintln!(
                "NOVA_VALIDATOR_INIT environment name={name} bytes={} normalized_bytes={}",
                value.len(),
                normalized.len()
            );
            validate_seed_text(normalized)?;
            Ok(Some(Zeroizing::new(normalized.to_owned())))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ValidatorInitError::InvalidSeed),
    }
}

fn prepare_root(path: &Path) -> Result<(), ValidatorInitError> {
    fs::create_dir_all(path).map_err(|_| ValidatorInitError::Directory)?;
    if is_root()? {
        fix_owner(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o750))
                .map_err(|_| ValidatorInitError::Ownership)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn fix_owner(path: &Path) -> Result<(), ValidatorInitError> {
    std::os::unix::fs::chown(path, Some(SERVICE_UID), Some(SERVICE_GID))
        .map_err(|_| ValidatorInitError::Ownership)
}

#[cfg(not(unix))]
fn fix_owner(_path: &Path) -> Result<(), ValidatorInitError> {
    Err(ValidatorInitError::Ownership)
}

#[cfg(unix)]
fn is_root() -> Result<bool, ValidatorInitError> {
    use std::os::unix::fs::MetadataExt;

    Ok(fs::metadata("/proc/self")
        .map_err(|_| ValidatorInitError::Ownership)?
        .uid()
        == 0)
}

#[cfg(not(unix))]
fn is_root() -> Result<bool, ValidatorInitError> {
    Ok(false)
}

fn ensure_seed_file(
    path: &Path,
    provided: Option<&str>,
    env_name: &str,
) -> Result<FileState, ValidatorInitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(ValidatorInitError::InvalidSeed);
            }
            validate_seed_file(path)?;
            if is_root()? {
                fix_owner(path)?;
            }
            Ok(FileState::Reused)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let provided = provided.ok_or(ValidatorInitError::MissingSeed)?;
            write_seed_file(path, provided)?;
            eprintln!("NOVA_VALIDATOR_INIT source={env_name} state=created");
            Ok(FileState::Created)
        }
        Err(_) => Err(ValidatorInitError::Metadata),
    }
}

fn validate_seed_file(path: &Path) -> Result<(), ValidatorInitError> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| ValidatorInitError::Read)?);
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(ValidatorInitError::InvalidSeed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ValidatorInitError::InvalidSeed)?;
    validate_seed_text(text.trim_end())
}

fn validate_seed_text(text: &str) -> Result<(), ValidatorInitError> {
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ValidatorInitError::InvalidSeed)
    }
}

fn validate_identity() -> Result<(), ValidatorInitError> {
    let expected_node_id = required_public_env(EXPECTED_NODE_ID_VAR)?;
    let expected_consensus = required_public_env(EXPECTED_CONSENSUS_PUBKEY_VAR)?;
    let network_seed = read_seed_bytes(Path::new(NETWORK_SEED_FILE))?;
    let validator_seed = read_seed_bytes(Path::new(VALIDATOR_SEED_FILE))?;

    let network_key = SigningKey::from_seed(*network_seed);
    let network_verifying = network_key.verifying_key();
    let node_id = NodeId::from_verifying_key(&network_verifying);
    if node_id.as_bytes() != &expected_node_id {
        return Err(ValidatorInitError::IdentityMismatch);
    }

    let validator_key = SigningKey::from_seed(*validator_seed);
    if validator_key.verifying_key().to_bytes() != expected_consensus {
        return Err(ValidatorInitError::IdentityMismatch);
    }
    Ok(())
}

fn required_public_env(name: &str) -> Result<[u8; 32], ValidatorInitError> {
    let value = std::env::var(name).map_err(|_| ValidatorInitError::IdentityMismatch)?;
    parse_hex32(normalize_env_text(&value)).ok_or(ValidatorInitError::IdentityMismatch)
}

fn normalize_env_text(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

fn read_seed_bytes(path: &Path) -> Result<Zeroizing<[u8; 32]>, ValidatorInitError> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| ValidatorInitError::Read)?);
    let text = std::str::from_utf8(&bytes).map_err(|_| ValidatorInitError::InvalidSeed)?;
    let parsed = parse_hex32(text.trim_end()).ok_or(ValidatorInitError::InvalidSeed)?;
    Ok(Zeroizing::new(parsed))
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn write_seed_file(path: &Path, value: &str) -> Result<(), ValidatorInitError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| ValidatorInitError::Create)?;
    let mut encoded = Zeroizing::new(value.trim_end().to_owned());
    encoded.push('\n');
    if file.write_all(encoded.as_bytes()).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(ValidatorInitError::Write);
    }
    if is_root()? {
        fix_owner(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn exec_validator(node_args: &[OsString]) -> Result<(), ValidatorInitError> {
    use std::os::unix::process::CommandExt;

    let error = Command::new(VALIDATOR_START_BIN)
        .args(&node_args[1..])
        .env_remove(NETWORK_SEED_VAR)
        .env_remove(VALIDATOR_SEED_VAR)
        .env_remove(EXPECTED_NODE_ID_VAR)
        .env_remove(EXPECTED_CONSENSUS_PUBKEY_VAR)
        .uid(SERVICE_UID)
        .gid(SERVICE_GID)
        .exec();
    eprintln!(
        "NOVA_VALIDATOR_INIT error=exec errno={}",
        error.raw_os_error().unwrap_or(0)
    );
    Err(ValidatorInitError::Exec)
}

#[cfg(not(unix))]
fn exec_validator(_node_args: &[OsString]) -> Result<(), ValidatorInitError> {
    Err(ValidatorInitError::Usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nova-validator-init-{}-{name}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parse_requires_fixed_validator_start_binary() {
        assert_eq!(
            parse(&[
                OsString::from("--"),
                OsString::from("/usr/local/bin/yazimao-node")
            ]),
            Err(ValidatorInitError::Usage)
        );
    }

    #[test]
    fn parse_accepts_validator_start_binary() {
        let parsed = parse(&[
            OsString::from("--"),
            OsString::from(VALIDATOR_START_BIN),
            OsString::from("--help"),
        ])
        .expect("valid validator wrapper arguments");
        assert_eq!(
            parsed,
            vec![
                OsString::from(VALIDATOR_START_BIN),
                OsString::from("--help")
            ]
        );
    }

    #[test]
    fn rejects_invalid_seed_text() {
        assert_eq!(
            validate_seed_text("abcd"),
            Err(ValidatorInitError::InvalidSeed)
        );
    }

    #[test]
    fn normalizes_one_surrounding_quote_pair() {
        let seed = "11".repeat(32);
        assert_eq!(normalize_env_text(&format!("\"{seed}\"")), seed.as_str());
        assert_eq!(normalize_env_text(&format!("  '{seed}'  ")), seed.as_str());
        validate_seed_text(normalize_env_text(&format!("\"{seed}\"")))
            .expect("quoted environment value");
    }

    #[test]
    fn writes_only_64_hex_characters() {
        let dir = TempDir::new("write");
        let path = dir.0.join("validator-seed.hex");
        let seed = "11".repeat(32);
        write_seed_file(&path, &seed).expect("write redacted test seed");
        let stored = fs::read(&path).expect("read file");
        assert_eq!(stored.len(), 65);
        assert_eq!(stored.last(), Some(&b'\n'));
        assert_eq!(validate_seed_file(&path), Ok(()));
    }
}
