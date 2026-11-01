//! Seed-only startup guard.
//!
//! This binary is intentionally limited to ephemeral/testnet Seed nodes:
//! - it creates one random 32-byte network identity seed only when the target
//!   file does not exist;
//! - it never overwrites or repairs an existing file;
//! - it rejects symlinks, non-regular files, BOM, malformed hex and extra data;
//! - it never prints the seed;
//! - after the file is valid, it replaces itself with `yazimao-node`.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::process::ExitCode;

use zeroize::{Zeroize, Zeroizing};

const NODE_BIN: &str = "/usr/local/bin/yazimao-node";
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_SOFTWARE: u8 = 70;
const EX_IOERR: u8 = 74;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedState {
    Created,
    Reused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedInitError {
    Usage,
    InvalidExistingSeed,
    Io,
    Rng,
}

impl SeedInitError {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => EX_USAGE,
            Self::InvalidExistingSeed => EX_DATAERR,
            Self::Io => EX_IOERR,
            Self::Rng => EX_SOFTWARE,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::InvalidExistingSeed => "invalid_existing_seed",
            Self::Io => "io",
            Self::Rng => "rng",
        }
    }
}

#[derive(Debug)]
struct Config {
    seed_file: PathBuf,
    node_args: Vec<OsString>,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NOVA_SEED_INIT error={}", error.code());
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(args: &[OsString]) -> Result<(), SeedInitError> {
    let config = parse(args)?;
    let parent = config.seed_file.parent().ok_or(SeedInitError::Usage)?;
    fs::create_dir_all(parent).map_err(|_| SeedInitError::Io)?;
    let state = ensure_seed_file(&config.seed_file)?;
    eprintln!(
        "NOVA_SEED_INIT state={} path={}",
        match state {
            SeedState::Created => "created",
            SeedState::Reused => "reused",
        },
        config.seed_file.display()
    );
    exec_node(&config.node_args)
}

fn parse(args: &[OsString]) -> Result<Config, SeedInitError> {
    if args.len() < 4 || args[0] != "--seed-file" || args[2] != "--" || args[3] != NODE_BIN {
        return Err(SeedInitError::Usage);
    }
    Ok(Config {
        seed_file: PathBuf::from(&args[1]),
        node_args: args[3..].to_vec(),
    })
}

fn ensure_seed_file(path: &Path) -> Result<SeedState, SeedInitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(SeedInitError::InvalidExistingSeed);
            }
            validate_seed_file(path)?;
            Ok(SeedState::Reused)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_seed_file(path),
        Err(_) => Err(SeedInitError::Io),
    }
}

fn create_seed_file(path: &Path) -> Result<SeedState, SeedInitError> {
    let mut seed = [0u8; 32];
    random_seed(&mut seed)?;
    let mut encoded = Zeroizing::new(hex32(&seed));
    seed.zeroize();
    encoded.push('\n');

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| SeedInitError::Io)?;
            if !metadata.file_type().is_file() {
                return Err(SeedInitError::InvalidExistingSeed);
            }
            validate_seed_file(path)?;
            return Ok(SeedState::Reused);
        }
        Err(_) => return Err(SeedInitError::Io),
    };

    if file.write_all(encoded.as_bytes()).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(SeedInitError::Io);
    }
    Ok(SeedState::Created)
}

fn validate_seed_file(path: &Path) -> Result<(), SeedInitError> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| SeedInitError::Io)?);
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SeedInitError::InvalidExistingSeed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| SeedInitError::InvalidExistingSeed)?;
    let text = text.trim_end();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SeedInitError::InvalidExistingSeed);
    }
    Ok(())
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(65);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(unix)]
fn random_seed(seed: &mut [u8; 32]) -> Result<(), SeedInitError> {
    let mut source = fs::File::open("/dev/urandom").map_err(|_| SeedInitError::Rng)?;
    source.read_exact(seed).map_err(|_| SeedInitError::Rng)
}

#[cfg(not(unix))]
fn random_seed(_seed: &mut [u8; 32]) -> Result<(), SeedInitError> {
    Err(SeedInitError::Rng)
}

#[cfg(unix)]
fn exec_node(node_args: &[OsString]) -> Result<(), SeedInitError> {
    use std::os::unix::process::CommandExt;

    if node_args.first().map(OsString::as_os_str) != Some(std::ffi::OsStr::new(NODE_BIN)) {
        return Err(SeedInitError::Usage);
    }
    let error = Command::new(NODE_BIN).args(&node_args[1..]).exec();
    eprintln!(
        "NOVA_SEED_INIT error=node_exec errno={}",
        error.raw_os_error().unwrap_or(0)
    );
    Err(SeedInitError::Io)
}

#[cfg(not(unix))]
fn exec_node(_node_args: &[OsString]) -> Result<(), SeedInitError> {
    Err(SeedInitError::Usage)
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
                "nova-seed-init-{}-{name}-{serial}",
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
    fn parse_requires_explicit_node_delimiter() {
        assert!(matches!(
            parse(&[
                OsString::from("--seed-file"),
                OsString::from("/tmp/network-seed.hex"),
                OsString::from(NODE_BIN),
            ]),
            Err(SeedInitError::Usage)
        ));
    }

    #[test]
    fn parse_accepts_seed_file_and_node_arguments() {
        let parsed = parse(&[
            OsString::from("--seed-file"),
            OsString::from("/tmp/network-seed.hex"),
            OsString::from("--"),
            OsString::from(NODE_BIN),
            OsString::from("--help"),
        ])
        .expect("valid wrapper arguments");
        assert_eq!(parsed.seed_file, PathBuf::from("/tmp/network-seed.hex"));
        assert_eq!(
            parsed.node_args,
            vec![OsString::from(NODE_BIN), OsString::from("--help")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn creates_once_and_reuses_the_same_seed() {
        let dir = TempDir::new("create-reuse");
        let path = dir.0.join("network-seed.hex");
        assert_eq!(ensure_seed_file(&path), Ok(SeedState::Created));
        let first = fs::read(&path).expect("read created seed");
        assert_eq!(first.len(), 65);
        assert_eq!(first.last(), Some(&b'\n'));
        assert_eq!(ensure_seed_file(&path), Ok(SeedState::Reused));
        assert_eq!(fs::read(&path).expect("read reused seed"), first);
    }

    #[test]
    fn rejects_malformed_existing_seed_without_overwrite() {
        let dir = TempDir::new("malformed");
        let path = dir.0.join("network-seed.hex");
        fs::write(&path, b"abcd").expect("write malformed seed");
        assert!(matches!(
            ensure_seed_file(&path),
            Err(SeedInitError::InvalidExistingSeed)
        ));
        assert_eq!(fs::read(&path).expect("read original seed"), b"abcd");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new("symlink");
        let target = dir.0.join("target.hex");
        let link = dir.0.join("network-seed.hex");
        fs::write(&target, vec![b'a'; 64]).expect("write target");
        symlink(&target, &link).expect("create symlink");
        assert!(matches!(
            ensure_seed_file(&link),
            Err(SeedInitError::InvalidExistingSeed)
        ));
    }
}
