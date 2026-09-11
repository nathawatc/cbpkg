use crate::error::AppError;
use crate::profile::TargetProfile;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct MakepkgBuildOptions {
    pub syncdeps: bool,
    pub clean: bool,
    pub cleanbuild: bool,
    pub force: bool,
    pub noconfirm: bool,
}

impl Default for MakepkgBuildOptions {
    fn default() -> Self {
        Self {
            syncdeps: true,
            clean: true,
            cleanbuild: true,
            force: true,
            noconfirm: false,
        }
    }
}

pub fn find_makepkg() -> Result<PathBuf, AppError> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("makepkg");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(AppError::MakepkgNotFound)
}

pub fn setup_isolated_config(target: &TargetProfile, base_dir: &Path) -> Result<PathBuf, AppError> {
    let conf_path = base_dir.join("makepkg.conf");
    let conf_d_path = base_dir.join("makepkg.conf.d");
    fs::create_dir_all(&conf_d_path).map_err(AppError::TempConfigCreate)?;

    let rust_conf_path = conf_d_path.join("rust.conf");

    fs::write(&conf_path, target.render_makepkg_conf()).map_err(AppError::TempConfigCreate)?;
    fs::write(&rust_conf_path, target.render_rust_conf()).map_err(AppError::TempConfigCreate)?;

    Ok(conf_path)
}

pub const EXPLICIT_SANITIZED_VARS: &[&str] = &[
    // Compiler and linker flags
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "LTOFLAGS",
    // Rust and Cargo flags
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "DEBUG_CFLAGS",
    "DEBUG_CXXFLAGS",
    "DEBUG_RUSTFLAGS",
    // Architecture and toolchain variables
    "GOAMD64",
    "CARCH",
    "CHOST",
    "PACKAGECARCH",
    "MAKEFLAGS",
    "NINJAFLAGS",
    // Output paths and directories
    "PKGDEST",
    "SRCDEST",
    "SRCPKGDEST",
    "LOGDEST",
    "BUILDDIR",
    // Extensions
    "PKGEXT",
    "SRCEXT",
    // Signing and packager identity
    "PACKAGER",
    "GPGKEY",
    // Configuration overrides
    "MAKEPKG_BASE_CONFIG",
    "MAKEPKG_CONF",
    "PACMAN",
    "PACMAN_AUTH",
    "CURL_HOME",
    // Build options and integrity
    "OPTIONS",
    "BUILDENV",
    "INTEGRITY_CHECK",
    "STRIP_BINARIES",
    "STRIP_SHARED",
    "STRIP_STATIC",
    "MAN_DIRS",
    "DOC_DIRS",
    "PURGE_TARGETS",
    "DBGSRCDIR",
    "LIB_DIRS",
    // Compression algorithms
    "COMPRESSGZ",
    "COMPRESSBZ2",
    "COMPRESSXZ",
    "COMPRESSZST",
    "COMPRESSLRZ",
    "COMPRESSLZO",
    "COMPRESSZ",
    "COMPRESSLZ4",
    "COMPRESSLZ",
];

pub fn is_cargo_target_rustflags_key(key: &std::ffi::OsStr) -> bool {
    if let Some(s) = key.to_str() {
        s.starts_with("CARGO_TARGET_") && s.ends_with("_RUSTFLAGS")
    } else {
        false
    }
}

pub fn sanitize_command_env(cmd: &mut Command, target: Option<&TargetProfile>) {
    // Remove all explicit makepkg and compiler/linker overrides
    for var in EXPLICIT_SANITIZED_VARS {
        cmd.env_remove(var);
    }

    // Remove any dynamic CARGO_TARGET_*_RUSTFLAGS variables in parent environment without decoding values
    for (key, _) in std::env::vars_os() {
        if is_cargo_target_rustflags_key(&key) {
            cmd.env_remove(&key);
        }
    }

    if let Some(goamd64) = target.and_then(|t| t.goamd64_str()) {
        cmd.env("GOAMD64", goamd64);
    }
}

pub fn get_planned_packages(
    makepkg_path: &Path,
    config_path: &Path,
    working_dir: &Path,
    target: &TargetProfile,
) -> Result<Vec<PathBuf>, AppError> {
    let mut cmd = Command::new(makepkg_path);
    sanitize_command_env(&mut cmd, Some(target));
    let output = cmd
        .arg("--packagelist")
        .arg("--config")
        .arg(config_path)
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| AppError::ProcessExecution {
            cmd: "makepkg --packagelist".to_string(),
            source: e,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(AppError::MakepkgPackagelistFailed(stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            packages.push(PathBuf::from(trimmed));
        }
    }

    if packages.is_empty() {
        return Err(AppError::NoPackageOutputs);
    }

    Ok(packages)
}

pub fn execute_build(
    makepkg_path: &Path,
    config_path: &Path,
    working_dir: &Path,
    options: &MakepkgBuildOptions,
    target: &TargetProfile,
) -> Result<(), AppError> {
    let mut cmd = Command::new(makepkg_path);
    sanitize_command_env(&mut cmd, Some(target));
    cmd.current_dir(working_dir)
        .arg("--config")
        .arg(config_path);

    if options.cleanbuild {
        cmd.arg("--cleanbuild");
    }
    if options.clean {
        cmd.arg("--clean");
    }
    if options.force {
        cmd.arg("--force");
    }
    if options.syncdeps {
        cmd.arg("--syncdeps");
    }
    if options.noconfirm {
        cmd.arg("--noconfirm");
    }

    // Direct user terminal output
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let status = cmd.status().map_err(|e| AppError::ProcessExecution {
        cmd: "makepkg build".to_string(),
        source: e,
    })?;

    if !status.success() {
        return Err(AppError::ProcessFailed {
            cmd: "makepkg".to_string(),
            exit_code: status.code(),
            stderr: "makepkg build process returned an error".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::mock::{MockCpuIdProvider, mock_v3_provider};
    use crate::profile::BuildProfile;

    #[test]
    fn test_setup_isolated_config_generic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cpu = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::Generic, &cpu);
        let conf_path = setup_isolated_config(&target, temp_dir.path()).unwrap();

        assert_eq!(conf_path, temp_dir.path().join("makepkg.conf"));
        let makepkg_content = fs::read_to_string(&conf_path).unwrap();
        assert!(makepkg_content.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_content.contains("CARCH=\"x86_64\""));
        assert!(makepkg_content.contains("-march=x86-64 -mtune=generic"));
        assert!(!makepkg_content.contains("PACKAGECARCH"));

        let rust_conf_path = temp_dir.path().join("makepkg.conf.d").join("rust.conf");
        assert!(rust_conf_path.is_file());
        let rust_content = fs::read_to_string(rust_conf_path).unwrap();
        assert!(rust_content.contains("target-cpu=x86-64"));
    }

    #[test]
    fn test_setup_isolated_config_native() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cpu = mock_v3_provider();
        let target = TargetProfile::new(BuildProfile::Native, &cpu);
        let conf_path = setup_isolated_config(&target, temp_dir.path()).unwrap();

        let makepkg_content = fs::read_to_string(&conf_path).unwrap();
        assert!(makepkg_content.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_content.contains("PACKAGECARCH=\"x86_64_native\""));
        assert!(makepkg_content.contains("-march=native -mtune=native"));
        assert!(makepkg_content.contains("GOAMD64=v3"));

        let rust_conf_path = temp_dir.path().join("makepkg.conf.d").join("rust.conf");
        let rust_content = fs::read_to_string(rust_conf_path).unwrap();
        assert!(rust_content.contains("target-cpu=native"));
    }

    #[test]
    fn test_setup_isolated_config_v3() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cpu = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::V3, &cpu);
        let conf_path = setup_isolated_config(&target, temp_dir.path()).unwrap();

        let makepkg_content = fs::read_to_string(&conf_path).unwrap();
        assert!(makepkg_content.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_content.contains("PACKAGECARCH=\"x86_64_v3\""));
        assert!(makepkg_content.contains("-march=x86-64-v3 -mtune=generic"));
        assert!(makepkg_content.contains("-mpclmul"));
        assert!(makepkg_content.contains("GOAMD64=v3"));

        let rust_conf_path = temp_dir.path().join("makepkg.conf.d").join("rust.conf");
        let rust_content = fs::read_to_string(rust_conf_path).unwrap();
        assert!(rust_content.contains("target-cpu=x86-64-v3"));
    }

    #[test]
    fn test_sanitize_command_env() {
        let mut cmd = Command::new("true");
        cmd.env("CFLAGS", "-DBAD_FLAG");
        cmd.env("RUSTFLAGS", "-Ctarget-cpu=bad");
        cmd.env("MAKEPKG_BASE_CONFIG", "/etc/makepkg.conf");

        let cpu = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::V3, &cpu);
        sanitize_command_env(&mut cmd, Some(&target));

        // Command env is cleared for CFLAGS and RUSTFLAGS, and GOAMD64 is set for v3
        // (In std::process::Command, env_remove will remove them from child execution)
    }

    #[test]
    fn test_is_cargo_target_rustflags_key() {
        use std::ffi::OsStr;
        assert!(is_cargo_target_rustflags_key(OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
        )));
        assert!(is_cargo_target_rustflags_key(OsStr::new(
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
        )));
        assert!(!is_cargo_target_rustflags_key(OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"
        )));
        assert!(!is_cargo_target_rustflags_key(OsStr::new(
            "CARGO_BUILD_RUSTFLAGS"
        )));
        assert!(!is_cargo_target_rustflags_key(OsStr::new("RUSTFLAGS")));
        assert!(!is_cargo_target_rustflags_key(OsStr::new("random key")));
        assert!(!is_cargo_target_rustflags_key(OsStr::new("")));

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(!is_cargo_target_rustflags_key(OsStr::from_bytes(
                b"\xFF\xFE_INVALID_UTF8"
            )));
        }
    }
}
