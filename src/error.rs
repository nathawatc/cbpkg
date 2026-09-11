use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Missing required tool: makepkg not found in PATH")]
    MakepkgNotFound,

    #[error("makepkg does not support PACKAGECARCH (required for optimized profile '{0}')")]
    MakepkgMissingPackageCArch(String),

    #[error("PKGBUILD not found in directory: {0}")]
    PkgbuildNotFound(PathBuf),

    #[error("Cannot read base makepkg config '{path}': {source}")]
    BaseConfigUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to create temporary makepkg config: {0}")]
    TempConfigCreate(std::io::Error),

    #[error("Failed to execute command '{cmd}': {source}")]
    ProcessExecution { cmd: String, source: std::io::Error },

    #[error("Command '{cmd}' failed with status {exit_code:?}: {stderr}")]
    ProcessFailed {
        cmd: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("makepkg --packagelist failed: {0}")]
    MakepkgPackagelistFailed(String),

    #[error("makepkg --packagelist returned no package outputs")]
    NoPackageOutputs,

    #[error("Invalid package output filename: '{0}'")]
    InvalidPackageFilename(String),

    #[error(
        "Refusing to build: optimized profile '{profile}' would produce package '{package}' \
         labeled as baseline 'x86_64'. Publishing host- or ISA-specific code as baseline x86_64 \
         could cause illegal-instruction failures on older CPUs."
    )]
    BaselineArchitectureMismatch { profile: String, package: String },

    #[error(
        "Package '{package}' architecture mismatch: expected '{expected}' (or 'any'), found '{found}'"
    )]
    ArchitectureMismatch {
        package: String,
        expected: String,
        found: String,
    },

    #[error("Expected package was not created after build: {0}")]
    ExpectedPackageMissing(PathBuf),

    #[error("Failed to read .PKGINFO from '{path}': {reason}")]
    PkgInfoRead { path: PathBuf, reason: String },

    #[error("Missing 'arch' attribute in .PKGINFO from '{0}'")]
    PkgInfoMissingArch(PathBuf),

    #[error("Secret Service error: {0}")]
    SecretService(String),

    #[error("Secret Service collection is locked and could not be unlocked")]
    CollectionLocked,

    #[error("No Codeberg credential found for host '{0}'.\nRun: cbpkg auth login")]
    CredentialMissing(String),

    #[error("Codeberg authentication rejected: invalid username or token")]
    AuthenticationRejected,

    #[error("Token verification failed on host '{host}': {message}")]
    TokenVerificationFailed { host: String, message: String },

    #[error("Upload failed for '{package}' (HTTP {status}): {message}")]
    UploadFailed {
        package: String,
        status: u16,
        message: String,
    },

    #[error("Interactive input error: {0}")]
    InputError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
