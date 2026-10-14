//! P-6 mount guard（Owner 授权的最小范围安全修复）。
//!
//! **目的**：拒绝把**容器可写层普通目录**（例如镜像内预创建的 `/storage`、`/safety`）
//! 当作持久化 `--storage-dir` / `--safety-dir` 使用。否则 chain 数据与 safety journal 会
//! 写入易失层：重启即丢失；并在 `--init-validator-safety` 下被误判为"全新节点"（double-vote 风险面）。
//!
//! **判据来源**：Linux 内核挂载表 `/proc/self/mountinfo`（权威、无需第三方依赖、覆盖独立文件系统与
//! bind mount）。**不**以"目录存在/可写"作为证据；**不**把应用自建标记文件当作唯一证据；
//! **不**新增任何绕过开关（生产默认 fail-closed）。
//!
//! **调用时机**：CLI `Action::Run` 的最开始 —— 早于 genesis pre-flight、早于任何
//! `create_dir_all` / journal 初始化 / block store 打开 ⇒ 失败路径**零写入**
//! （本模块只做 `canonicalize` + 只读挂载表查询）。
//!
//! **强制范围（诚实声明）**：
//! - 运行环境被判定为**容器** ⇒ **严格强制执行**：两枚目录都必须本身是挂载点，否则拒绝启动
//!   （fail-closed）。判定信号由 [`container_markers`] 实现，全部为**只读**探测：
//!   `/.dockerenv`；`/run/.containerenv`；`/proc/self/cgroup` 或 `/proc/1/cgroup` 含
//!   `docker`/`kubepods`/`containerd`/`libpod`；K8s service-account 目录
//!   `/var/run/secrets/kubernetes.io/serviceaccount`；环境变量 `KUBERNETES_SERVICE_HOST`
//!   （任一成立 ⇒ 容器）。
//! - 非容器化开发/CI 环境（无容器标记，例如 Windows 或裸机 Linux）⇒ **无法判定持久性**，
//!   返回 [`GuardOutcome::SkippedNotContainer`]，由调用方打印明确提示后继续。此分支**不是**
//!   安全保证，仅用于不阻断本地演练与既有测试。
//! - 残留限制：若生产运行未被容器标记识别（如裸机 systemd 部署且目录未挂载），本守卫会跳过；
//!   真正的持久化保证仍须由部署侧（SDL 卷声明 + 挂载核对）承担。

use std::fmt;
use std::path::{Path, PathBuf};

/// 受保护的目标目录角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountTarget {
    /// `--storage-dir`（blocks / WAL / snapshot / qc_history / finality fact）。
    Storage,
    /// `--safety-dir`（validator 专属：`safety.journal` + `block-safety.journal`）。
    Safety,
}

impl MountTarget {
    /// 稳定短名（用于错误信息；非敏感）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Safety => "safety",
        }
    }
}

/// 拒绝原因类别（**不含任何秘密**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountGuardReason {
    /// 路径可解析，但**不是**挂载点（普通目录 / 镜像内预创建目录 / 未挂载）。
    NotAMountPoint,
    /// 路径无法规范化（不存在 / 不可解析）⇒ 不得视为已挂载，也不得代其创建。
    CannotResolvePath,
    /// 无法读取挂载信息（平台不支持 `/proc`；或读取失败）⇒ fail-closed。
    InspectionUnavailable,
}

impl MountGuardReason {
    /// 稳定短句（用于错误信息；非敏感）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAMountPoint => {
                "not a mount point (plain directory on the container writable layer?)"
            }
            Self::CannotResolvePath => "path cannot be resolved (missing or unresolvable)",
            Self::InspectionUnavailable => {
                "mount information unavailable (cannot verify persistence; refusing to start)"
            }
        }
    }
}

/// mount guard 判定失败（明确包含角色、路径与原因；路径非秘密）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountGuardError {
    target: MountTarget,
    path: PathBuf,
    reason: MountGuardReason,
}

impl MountGuardError {
    /// 失败目标角色。
    pub const fn target(&self) -> MountTarget {
        self.target
    }

    /// 失败路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 失败原因类别。
    pub const fn reason(&self) -> MountGuardReason {
        self.reason
    }
}

impl fmt::Display for MountGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} dir `{}` rejected by mount guard: {}",
            self.target.as_str(),
            self.path.display(),
            self.reason.as_str()
        )
    }
}

impl std::error::Error for MountGuardError {}

/// 判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// 已严格判定（两枚目标均通过）。
    Enforced,
    /// 非容器化环境 ⇒ 未判定（调用方**必须**显式提示；不是安全保证）。
    SkippedNotContainer,
}

/// 挂载检查 seam：生产默认 = `/proc/self/mountinfo`；测试注入可控 fake。
///
/// 约定：`Err(String)` = **无法判定**（必须 fail-closed）；`Ok(false)` = 已判定"不是挂载点"。
pub trait MountInspector {
    /// `canonical`（已规范化路径）本身是否为挂载点。
    fn is_mount_point(&self, canonical: &Path) -> Result<bool, String>;
}

/// Linux 生产实现：解析 `/proc/self/mountinfo`（内核权威挂载表）。
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcSelfMountinfoInspector;

impl MountInspector for ProcSelfMountinfoInspector {
    fn is_mount_point(&self, canonical: &Path) -> Result<bool, String> {
        let raw = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| format!("read /proc/self/mountinfo failed: {e}"))?;
        Ok(mountinfo_contains(&raw, canonical))
    }
}

/// 纯函数（可测试）：给定各探测信号，判定当前进程是否运行在**容器**内。
///
/// 采用**多重、容器专属**信号（任一为真 ⇒ 容器）。全部信号都是容器/沙箱运行时的注入物，
/// 裸机（含 CI 虚拟机）不会出现 ⇒ 避免误判把非容器环境当作容器而错误放行/拒绝。
///
/// 信号清单（只读，无副作用）：
/// - `/.dockerenv`：Docker 注入
/// - `/run/.containerenv`：Podman 注入
/// - `/proc/self/cgroup` 或 `/proc/1/cgroup` 含 `docker`/`kubepods`/`containerd`/`libpod`
/// - `/var/run/secrets/kubernetes.io/serviceaccount`：K8s Pod（Akash = K8s）注入
/// - 环境变量 `KUBERNETES_SERVICE_HOST`：K8s 注入
///
/// **已知限制（诚实声明）**：若运行时为 cgroup v2 统一层级且其路径不含上述关键字、
/// 又未注入任何标记文件/环境变量（例如自定义 cri + 非 systemd cgroup 驱动），
/// 本判定会返回 `false` ⇒ 守卫跳过（非安全保证）。部署侧必须仍以 volume 挂载为准。
pub fn container_markers(
    dockerenv: bool,
    containerenv: bool,
    cgroup_self: Option<&str>,
    cgroup_init: Option<&str>,
    k8s_serviceaccount: bool,
    k8s_env: bool,
) -> bool {
    if dockerenv || containerenv || k8s_serviceaccount || k8s_env {
        return true;
    }
    cgroup_self.is_some_and(cgroup_marks_container) || cgroup_init.is_some_and(cgroup_marks_container)
}

/// 是否运行在容器内（生产 = Akash/K8s 容器）。**纯只读探测**（不创建、不写入）。
pub fn in_container_default() -> bool {
    let cgroup_self = std::fs::read_to_string("/proc/self/cgroup").ok();
    let cgroup_init = std::fs::read_to_string("/proc/1/cgroup").ok();
    container_markers(
        Path::new("/.dockerenv").exists(),
        Path::new("/run/.containerenv").exists(),
        cgroup_self.as_deref(),
        cgroup_init.as_deref(),
        Path::new("/var/run/secrets/kubernetes.io/serviceaccount").exists(),
        std::env::var_os("KUBERNETES_SERVICE_HOST").is_some(),
    )
}

/// 纯函数：cgroup 文本是否表明容器化运行时（docker / K8s / containerd / podman）。
pub fn cgroup_marks_container(cgroup: &str) -> bool {
    cgroup.contains("docker")
        || cgroup.contains("kubepods")
        || cgroup.contains("containerd")
        || cgroup.contains("libpod")
}

/// 在 `mountinfo` 文本中查找与 `canonical` **精确相等**的挂载点（第 5 字段）。
///
/// 只做精确匹配：不做前缀/子路径推断（避免把"子目录位于某挂载点之下"误判为"该子目录已被挂载"）。
pub fn mountinfo_contains(raw: &str, canonical: &Path) -> bool {
    let want = canonical.to_string_lossy();
    raw.lines().any(|line| {
        let mut fields = line.split(' ');
        // mountinfo: <id> <parent> <major:minor> <root> <mount_point> <options> [...] - <fstype> <source> <super_opts>
        let (Some(_id), Some(_parent), Some(_dev), Some(_root), Some(mount_point)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return false;
        };
        unescape_mountinfo(mount_point) == want
    })
}

/// 还原 mountinfo 的八进制转义：`\040`=space、`\011`=tab、`\012`=newline、`\134`=backslash。
pub fn unescape_mountinfo(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let mut oct = String::with_capacity(3);
        for _ in 0..3 {
            match chars.next() {
                Some(d) => oct.push(d),
                None => break,
            }
        }
        match oct.as_str() {
            "040" => out.push(' '),
            "011" => out.push('\t'),
            "012" => out.push('\n'),
            "134" => out.push('\\'),
            other => {
                out.push('\\');
                out.push_str(other);
            }
        }
    }
    out
}

/// 对单个目录执行判定（**不创建、不打开、不写入任何东西**）。
///
/// 失败语义（均 fail-closed）：
/// - 路径无法规范化 ⇒ [`MountGuardReason::CannotResolvePath`]（且**不**代其创建目录）；
/// - 可解析但不是挂载点 ⇒ [`MountGuardReason::NotAMountPoint`]；
/// - inspector 无法判定 ⇒ [`MountGuardReason::InspectionUnavailable`]。
pub fn enforce_mount_point(
    target: MountTarget,
    raw_path: &Path,
    inspector: &dyn MountInspector,
) -> Result<PathBuf, MountGuardError> {
    let canonical = match std::fs::canonicalize(raw_path) {
        Ok(p) => p,
        Err(_) => {
            return Err(MountGuardError {
                target,
                path: raw_path.to_path_buf(),
                reason: MountGuardReason::CannotResolvePath,
            });
        }
    };
    match inspector.is_mount_point(&canonical) {
        Ok(true) => Ok(canonical),
        Ok(false) => Err(MountGuardError {
            target,
            path: canonical,
            reason: MountGuardReason::NotAMountPoint,
        }),
        Err(_) => Err(MountGuardError {
            target,
            path: canonical,
            reason: MountGuardReason::InspectionUnavailable,
        }),
    }
}

/// 对 `--storage-dir`（总是）与 `--safety-dir`（**只要 CLI 提供了就检查**，与是否 `--validator` 无关）**分别**判定。
///
/// 当 `in_container == false` 时返回 [`GuardOutcome::SkippedNotContainer`]（调用方须显式提示）；
/// 否则任一项失败 ⇒ 立即返回错误（**零写入**）。**不**存在"仅凭可写即视为有效"的路径。
pub fn enforce_persistent_dirs_with(
    storage_dir: &Path,
    safety_dir: Option<&Path>,
    inspector: &dyn MountInspector,
    in_container: bool,
) -> Result<GuardOutcome, MountGuardError> {
    if !in_container {
        return Ok(GuardOutcome::SkippedNotContainer);
    }
    enforce_mount_point(MountTarget::Storage, storage_dir, inspector)?;
    if let Some(safety) = safety_dir {
        enforce_mount_point(MountTarget::Safety, safety, inspector)?;
    }
    Ok(GuardOutcome::Enforced)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可控 fake：给定"被接受的规范化路径"集合；`available=false` ⇒ 模拟无法判定（非 Linux）。
    struct FakeInspector {
        accepted: Vec<PathBuf>,
        available: bool,
    }

    impl FakeInspector {
        fn accepting(paths: &[&Path]) -> Self {
            Self {
                accepted: paths.iter().map(|p| p.to_path_buf()).collect(),
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                accepted: Vec::new(),
                available: false,
            }
        }
    }

    impl MountInspector for FakeInspector {
        fn is_mount_point(&self, canonical: &Path) -> Result<bool, String> {
            if !self.available {
                return Err("inspection unavailable (fake)".to_string());
            }
            Ok(self.accepted.iter().any(|a| a == canonical))
        }
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("nova_mount_guard_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp root");
        dir
    }

    fn dir_entries(path: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(path)
            .map(|it| {
                it.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// T-MOUNT-01（storage 非挂载 ⇒ 失败）+ T-MOUNT-10（零写入）。
    #[test]
    fn t_mount_01_storage_not_a_mount_point_is_rejected_with_zero_writes() {
        let root = tmp_root("t01");
        let storage = root.join("storage");
        std::fs::create_dir_all(&storage).unwrap();

        let err = enforce_persistent_dirs_with(
            &storage,
            None,
            &FakeInspector::accepting(&[]),
            true,
        )
        .expect_err("plain directory must be rejected");
        assert_eq!(err.target(), MountTarget::Storage);
        assert_eq!(err.reason(), MountGuardReason::NotAMountPoint);
        assert!(dir_entries(&storage).is_empty(), "guard 失败必须零写入");
    }

    /// T-MOUNT-02（safety 非挂载 ⇒ 失败）+ 零写入。
    #[test]
    fn t_mount_02_safety_not_a_mount_point_is_rejected_with_zero_writes() {
        let root = tmp_root("t02");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();
        let storage_c = std::fs::canonicalize(&storage).unwrap();

        let err = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[&storage_c]),
            true,
        )
        .expect_err("unmounted safety dir must be rejected");
        assert_eq!(err.target(), MountTarget::Safety);
        assert_eq!(err.reason(), MountGuardReason::NotAMountPoint);
        assert!(dir_entries(&safety).is_empty(), "guard 失败必须零写入");
        assert!(dir_entries(&storage).is_empty(), "不得出现半初始化");
    }

    /// T-MOUNT-03（storage 有效、safety 缺失 ⇒ 整体 fail-closed，无半初始化）。
    #[test]
    fn t_mount_03_valid_storage_with_invalid_safety_fails_closed() {
        let root = tmp_root("t03");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();
        let storage_c = std::fs::canonicalize(&storage).unwrap();

        let err = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[&storage_c]),
            true,
        )
        .expect_err("half-valid configuration must fail closed");
        assert_eq!(err.target(), MountTarget::Safety);
        assert!(dir_entries(&storage).is_empty() && dir_entries(&safety).is_empty());
    }

    /// T-MOUNT-04（safety 有效、storage 缺失 ⇒ 整体 fail-closed，零写入）。
    #[test]
    fn t_mount_04_valid_safety_with_invalid_storage_fails_closed() {
        let root = tmp_root("t04");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();
        let safety_c = std::fs::canonicalize(&safety).unwrap();

        let err = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[&safety_c]),
            true,
        )
        .expect_err("storage must be checked independently");
        assert_eq!(err.target(), MountTarget::Storage);
        assert!(dir_entries(&storage).is_empty() && dir_entries(&safety).is_empty());
    }

    /// T-MOUNT-05（两枚均为挂载点 ⇒ 通过，进入既有初始化流程）。
    #[test]
    fn t_mount_05_both_mount_points_pass() {
        let root = tmp_root("t05");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();
        let storage_c = std::fs::canonicalize(&storage).unwrap();
        let safety_c = std::fs::canonicalize(&safety).unwrap();

        let outcome = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[&storage_c, &safety_c]),
            true,
        )
        .expect("both mount points must pass");
        assert_eq!(outcome, GuardOutcome::Enforced);
    }

    /// T-MOUNT-07（写入前拒绝：缺失路径**不得**被代其创建）。
    #[test]
    fn t_mount_07_missing_path_is_rejected_before_any_write() {
        let root = tmp_root("t07");
        let storage = root.join("does-not-exist");
        let err = enforce_persistent_dirs_with(&storage, None, &FakeInspector::accepting(&[]), true)
            .expect_err("missing path must be rejected");
        assert_eq!(err.reason(), MountGuardReason::CannotResolvePath);
        assert!(!storage.exists(), "guard 不得创建目录");
    }

    /// 无法判定挂载信息 ⇒ fail-closed（容器内）。
    #[test]
    fn inspection_unavailable_is_fail_closed_in_container() {
        let root = tmp_root("unavail");
        let storage = root.join("storage");
        std::fs::create_dir_all(&storage).unwrap();
        let err =
            enforce_persistent_dirs_with(&storage, None, &FakeInspector::unavailable(), true)
                .expect_err("unavailable inspection must fail closed");
        assert_eq!(err.reason(), MountGuardReason::InspectionUnavailable);
    }

    /// 非容器环境 ⇒ 显式跳过（不是安全保证；调用方会打印提示）。
    #[test]
    fn non_container_environment_is_skipped_explicitly() {
        let root = tmp_root("skip");
        let storage = root.join("storage");
        std::fs::create_dir_all(&storage).unwrap();
        let outcome =
            enforce_persistent_dirs_with(&storage, None, &FakeInspector::accepting(&[]), false)
                .expect("non-container environment returns an explicit skip");
        assert_eq!(outcome, GuardOutcome::SkippedNotContainer);
    }

    /// 容器探测纯函数：cgroup 文本判定。
    #[test]
    fn cgroup_container_detection_is_exact_on_markers() {
        assert!(cgroup_marks_container("0::/kubepods/besteffort/pod123/abc"));
        assert!(cgroup_marks_container("1:name=systemd:/docker/abc"));
        assert!(cgroup_marks_container("0::/containerd.service"));
        assert!(!cgroup_marks_container("0::/user.slice/user-1000.slice"));
    }

    /// mountinfo 解析：精确匹配 + 八进制转义（含"仅前缀相同"不得匹配）。
    #[test]
    fn mountinfo_matches_exact_mount_point_only() {
        let raw = "36 25 0:32 / / rw,relatime - overlay overlay rw\n\
                   37 36 8:1 / /storage rw,relatime - ext4 /dev/sdb rw\n\
                   38 36 8:2 / /safety\\040dir rw,relatime - ext4 /dev/sdc rw\n";

        assert!(mountinfo_contains(raw, Path::new("/")));
        assert!(mountinfo_contains(raw, Path::new("/storage")));
        assert!(mountinfo_contains(raw, Path::new("/safety dir")));
        // 子路径**不**等于挂载点（保守：不接受"位于挂载点之下"作为证据）。
        assert!(!mountinfo_contains(raw, Path::new("/storage/sub")));
        assert!(!mountinfo_contains(raw, Path::new("/not-mounted")));
    }

    /// 转义还原单元测试。
    #[test]
    fn mountinfo_unescape_handles_known_octal_sequences() {
        assert_eq!(unescape_mountinfo("/a\\040b"), "/a b");
        assert_eq!(unescape_mountinfo("/a\\011b"), "/a\tb");
        assert_eq!(unescape_mountinfo("/a\\012b"), "/a\nb");
        assert_eq!(unescape_mountinfo("/a\\134b"), "/a\\b");
        assert_eq!(unescape_mountinfo("/plain"), "/plain");
    }

    /// T-MOUNT-11：挂载点**之下**的子目录本身不是挂载点 ⇒ 必须拒绝。
    ///
    /// 反例动机：若判据改成“位于某挂载点之下”或 `starts_with`，则子目录会被误认为持久化。
    #[test]
    fn t_mount_11_nested_dir_under_mounted_parent_is_rejected() {
        let root = tmp_root("t11");
        let mount_parent = root.join("data");
        let nested = mount_parent.join("storage");
        std::fs::create_dir_all(&nested).unwrap();
        let parent_c = std::fs::canonicalize(&mount_parent).unwrap();

        let err = enforce_persistent_dirs_with(
            &nested,
            None,
            &FakeInspector::accepting(&[&parent_c]),
            true,
        )
        .expect_err("mount point subdirectory must not be accepted as a mount point");
        assert_eq!(err.target(), MountTarget::Storage);
        assert_eq!(err.reason(), MountGuardReason::NotAMountPoint);
        assert!(dir_entries(&nested).is_empty(), "拒绝必须零写入");
    }

    /// T-MOUNT-12：storage 与 safety **同时**未挂载 ⇒ 拒绝；两枚目录均不得被创建或写入。
    #[test]
    fn t_mount_12_both_dirs_unmounted_fails_closed() {
        let root = tmp_root("t12");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();

        let err = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[]),
            true,
        )
        .expect_err("two unmounted directories must fail closed");
        assert_eq!(err.target(), MountTarget::Storage, "判定顺序必须确定：先 storage");
        assert_eq!(err.reason(), MountGuardReason::NotAMountPoint);
        assert!(dir_entries(&storage).is_empty() && dir_entries(&safety).is_empty());
    }

    /// T-MOUNT-13：拒绝路径**不得修改**既有内容（哨兵文件字节不变、目录项集合不变）。
    ///
    /// 这是对 P-6 失败路径副作用的直接回归测试（历史缺陷：失败路径创建了空 journal）。
    #[test]
    fn t_mount_13_rejection_does_not_mutate_existing_content() {
        let root = tmp_root("t13");
        let storage = root.join("storage");
        let safety = root.join("safety");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::create_dir_all(&safety).unwrap();
        std::fs::write(storage.join("sentinel.bin"), b"owner-wip-must-survive").unwrap();
        std::fs::write(safety.join("safety.journal"), b"existing-journal").unwrap();
        let before_storage = dir_entries(&storage);
        let before_safety = dir_entries(&safety);

        let err = enforce_persistent_dirs_with(
            &storage,
            Some(&safety),
            &FakeInspector::accepting(&[]),
            true,
        )
        .expect_err("unmounted dirs must be rejected even when they already contain files");
        assert_eq!(err.reason(), MountGuardReason::NotAMountPoint);
        assert_eq!(dir_entries(&storage), before_storage, "目录项集合不得变化");
        assert_eq!(dir_entries(&safety), before_safety, "目录项集合不得变化");
        assert_eq!(
            std::fs::read(storage.join("sentinel.bin")).unwrap(),
            b"owner-wip-must-survive"
        );
        assert_eq!(
            std::fs::read(safety.join("safety.journal")).unwrap(),
            b"existing-journal"
        );
    }

    /// mountinfo：**前缀相似**或**子路径**不得被当作挂载点（防 `starts_with` 类天真实现）。
    #[test]
    fn mountinfo_prefix_similar_paths_are_not_matched() {
        let raw = "36 25 0:32 / / rw,relatime - overlay overlay rw\n\
                   37 36 8:1 / /storage rw,relatime - ext4 /dev/sdb rw\n";
        assert!(mountinfo_contains(raw, Path::new("/storage")));
        for candidate in ["/storage2", "/storage-extra", "/storage/sub", "/storag", "/"] {
            let expected = candidate == "/";
            assert_eq!(
                mountinfo_contains(raw, Path::new(candidate)),
                expected,
                "前缀/子路径不得被误判为挂载点: {candidate}"
            );
        }
    }

    /// mountinfo：行字段不足 / 畸形行不得 panic，也不得误判。
    #[test]
    fn mountinfo_malformed_lines_are_ignored_without_panic() {
        let raw = "36 25\n\nnot-a-mountinfo-line\n37 36 8:1 / /storage rw - ext4 /dev/sdb rw\n";
        assert!(mountinfo_contains(raw, Path::new("/storage")));
        assert!(!mountinfo_contains(raw, Path::new("/other")));
        assert!(!mountinfo_contains("", Path::new("/storage")));
    }

    /// 容器探测：K8s（Akash）与 Podman 信号必须被识别；裸机 systemd 主机不得误判。
    #[test]
    fn container_detection_covers_k8s_and_podman_without_bare_metal_false_positives() {
        // K8s / Akash：ServiceAccount 目录 或 KUBERNETES_SERVICE_HOST。
        assert!(container_markers(false, false, None, None, true, false));
        assert!(container_markers(false, false, None, None, false, true));
        // Docker / Podman 注入文件。
        assert!(container_markers(true, false, None, None, false, false));
        assert!(container_markers(false, true, None, None, false, false));
        // cgroup（self 或 PID 1）出现运行时关键字。
        assert!(container_markers(
            false,
            false,
            Some("0::/kubepods.slice/kubepods-burstable.slice"),
            None,
            false,
            false
        ));
        assert!(container_markers(
            false,
            false,
            None,
            Some("0::/libpod-abc"),
            false,
            false
        ));
        // 裸机 systemd（cgroup v2 统一层级 `0::/`）⇒ 不得误判。
        assert!(!container_markers(
            false,
            false,
            Some("0::/"),
            Some("0::/"),
            false,
            false
        ));
        assert!(!container_markers(false, false, None, None, false, false));
    }

    /// 容器探测**已知限制**：cgroup v2 统一层级 + 无任何注入标记 ⇒ 判定为“非容器”而跳过守卫。
    ///
    /// 该断言把限制**固定为可执行事实**（而非文档承诺），防止有人误以为守卫在任何环境都生效。
    #[test]
    fn container_detection_limitation_is_pinned_as_executable_fact() {
        assert!(!container_markers(
            false,
            false,
            Some("0::/"),
            Some("0::/"),
            false,
            false
        ));
    }
}
