//! Minimal validator startup guard for container deployments.
//!
//! The release image has no shell. This binary preserves the reviewed wrapper
//! semantics while reducing the runtime attack surface and avoiding argv
//! re-tokenization.
//!
//! State matrix:
//! - both journals absent: add `--init-validator-safety` and exec the node;
//! - both journals present as regular files: exec the node without the flag;
//! - partial, symlinked, or non-regular state: fail closed before node startup.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const NODE_BIN: &str = "/usr/local/bin/yazimao-node";
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOPERM: u8 = 77;
const EX_CONFIG: u8 = 78;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafetyState {
    Fresh,
    Recover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardError {
    MissingSafetyDir,
    DuplicateSafetyDir,
    SafetyDirSymlink,
    SafetyDirMissing,
    InitFlagManaged,
    ValidatorFlagRequired,
    PartialState { vote: bool, block: bool },
    JournalSymlink,
    JournalNotRegular,
    Io,
    NodeNotExecutable,
}

impl GuardError {
    fn exit_code(self) -> u8 {
        match self {
            Self::MissingSafetyDir
            | Self::DuplicateSafetyDir
            | Self::InitFlagManaged
            | Self::ValidatorFlagRequired => EX_USAGE,
            Self::SafetyDirSymlink
            | Self::SafetyDirMissing
            | Self::PartialState { .. }
            | Self::JournalSymlink
            | Self::JournalNotRegular => EX_CONFIG,
            Self::Io => EX_DATAERR,
            Self::NodeNotExecutable => EX_NOPERM,
        }
    }

    fn message(self) -> String {
        match self {
            Self::MissingSafetyDir => "missing_safety_dir".to_string(),
            Self::DuplicateSafetyDir => "duplicate_safety_dir".to_string(),
            Self::SafetyDirSymlink => "safety_dir_symlink".to_string(),
            Self::SafetyDirMissing => "safety_dir_missing".to_string(),
            Self::InitFlagManaged => "init_flag_managed_by_wrapper".to_string(),
            Self::ValidatorFlagRequired => "validator_flag_required".to_string(),
            Self::PartialState { vote, block } => {
                format!("state=partial_fail_closed vote={vote} block={block}")
            }
            Self::JournalSymlink => "journal_symlink_refused".to_string(),
            Self::JournalNotRegular => "safety_journal_not_regular_file".to_string(),
            Self::Io => "safety_state_io_error".to_string(),
            Self::NodeNotExecutable => "node_binary_not_executable".to_string(),
        }
    }
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NOVA_VALIDATOR_START ERROR {}", error.message());
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(args: Vec<OsString>) -> Result<(), GuardError> {
    ensure_node_executable(Path::new(NODE_BIN))?;
    let (safety_dir, state) = inspect_safety_state(&args)?;
    eprintln!(
        "NOVA_VALIDATOR_START state={} safety_dir={}",
        match state {
            SafetyState::Fresh => "fresh",
            SafetyState::Recover => "recover",
        },
        safety_dir.display()
    );

    let mut command = Command::new(NODE_BIN);
    if state == SafetyState::Fresh {
        command.arg("--init-validator-safety");
    }
    command.args(args);
    exec_node(&mut command).map_err(|_| GuardError::Io)
}

fn ensure_node_executable(path: &Path) -> Result<(), GuardError> {
    let metadata = fs::metadata(path).map_err(|_| GuardError::NodeNotExecutable)?;
    if !metadata.is_file() {
        return Err(GuardError::NodeNotExecutable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(GuardError::NodeNotExecutable);
        }
    }
    Ok(())
}

fn inspect_safety_state(args: &[OsString]) -> Result<(PathBuf, SafetyState), GuardError> {
    let mut safety_dir = None;
    let mut await_safety_dir = false;
    let mut seen_validator = false;
    let mut seen_init = false;

    for arg in args {
        if await_safety_dir {
            if safety_dir.is_some() {
                return Err(GuardError::DuplicateSafetyDir);
            }
            safety_dir = Some(PathBuf::from(arg));
            await_safety_dir = false;
        }
        if arg == OsStr::new("--safety-dir") {
            await_safety_dir = true;
        } else if arg == OsStr::new("--validator") {
            seen_validator = true;
        } else if arg == OsStr::new("--init-validator-safety") {
            seen_init = true;
        }
    }

    let safety_dir = safety_dir.ok_or(GuardError::MissingSafetyDir)?;
    if await_safety_dir {
        return Err(GuardError::MissingSafetyDir);
    }
    if !seen_validator {
        return Err(GuardError::ValidatorFlagRequired);
    }
    if seen_init {
        return Err(GuardError::InitFlagManaged);
    }

    let safety_meta = fs::symlink_metadata(&safety_dir).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => GuardError::SafetyDirMissing,
        _ => GuardError::Io,
    })?;
    if safety_meta.file_type().is_symlink() {
        return Err(GuardError::SafetyDirSymlink);
    }
    if !safety_meta.is_dir() {
        return Err(GuardError::SafetyDirMissing);
    }

    let vote = journal_present(&safety_dir.join("safety.journal"))?;
    let block = journal_present(&safety_dir.join("block-safety.journal"))?;
    match (vote, block) {
        (false, false) => Ok((safety_dir, SafetyState::Fresh)),
        (true, true) => Ok((safety_dir, SafetyState::Recover)),
        _ => Err(GuardError::PartialState { vote, block }),
    }
}

fn journal_present(path: &Path) -> Result<bool, GuardError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(GuardError::Io),
    };
    if metadata.file_type().is_symlink() {
        return Err(GuardError::JournalSymlink);
    }
    if !metadata.is_file() {
        return Err(GuardError::JournalNotRegular);
    }
    Ok(true)
}

#[cfg(unix)]
fn exec_node(command: &mut Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let error = command.exec();
    Err(error)
}

#[cfg(not(unix))]
fn exec_node(_command: &mut Command) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "validator startup wrapper requires a Unix target",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(safety_dir: &Path, add_validator: bool, add_init: bool) -> Vec<OsString> {
        let mut out = vec![
            OsString::from("--safety-dir"),
            safety_dir.as_os_str().to_owned(),
        ];
        if add_validator {
            out.push(OsString::from("--validator"));
        }
        if add_init {
            out.push(OsString::from("--init-validator-safety"));
        }
        out
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nova-start-wrapper-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn both_absent_is_fresh() {
        let dir = temp_dir("fresh");
        assert_eq!(
            inspect_safety_state(&args(&dir, true, false)).unwrap().1,
            SafetyState::Fresh
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn both_regular_is_recover() {
        let dir = temp_dir("recover");
        fs::write(dir.join("safety.journal"), b"x").unwrap();
        fs::write(dir.join("block-safety.journal"), b"x").unwrap();
        assert_eq!(
            inspect_safety_state(&args(&dir, true, false)).unwrap().1,
            SafetyState::Recover
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn partial_state_fails_closed() {
        let dir = temp_dir("partial");
        fs::write(dir.join("safety.journal"), b"x").unwrap();
        assert_eq!(
            inspect_safety_state(&args(&dir, true, false)),
            Err(GuardError::PartialState {
                vote: true,
                block: false
            })
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn required_flags_and_wrapper_ownership_are_enforced() {
        let dir = temp_dir("flags");
        assert_eq!(
            inspect_safety_state(&args(&dir, false, false)),
            Err(GuardError::ValidatorFlagRequired)
        );
        assert_eq!(
            inspect_safety_state(&args(&dir, true, true)),
            Err(GuardError::InitFlagManaged)
        );
        assert_eq!(
            inspect_safety_state(&[OsString::from("--validator")]),
            Err(GuardError::MissingSafetyDir)
        );
        assert_eq!(
            inspect_safety_state(&[
                OsString::from("--safety-dir"),
                dir.as_os_str().to_owned(),
                OsString::from("--safety-dir"),
                dir.as_os_str().to_owned(),
                OsString::from("--validator"),
            ]),
            Err(GuardError::DuplicateSafetyDir)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink");
        let real = dir.join("real.journal");
        fs::write(&real, b"x").unwrap();
        symlink(&real, dir.join("safety.journal")).unwrap();
        symlink(&real, dir.join("block-safety.journal")).unwrap();
        assert_eq!(
            inspect_safety_state(&args(&dir, true, false)),
            Err(GuardError::JournalSymlink)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
