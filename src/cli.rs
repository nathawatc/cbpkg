use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cbpkg",
    about = "Arch Linux package build orchestrator and Codeberg Packages publisher",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Authentication management for Codeberg Packages
    Auth(AuthArgs),

    /// Build Arch packages for selected profiles and optionally upload
    Build(BuildArgs),
}

#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Store verified Codeberg credentials in Linux D-Bus Secret Service
    Login {
        /// Codeberg host (e.g. codeberg.org)
        #[arg(long, default_value = "codeberg.org", env = "CODEBERG_HOST")]
        host: String,

        /// Codeberg username
        #[arg(long, short = 'u')]
        username: Option<String>,
    },

    /// Remove cbpkg-managed Codeberg credentials from Secret Service
    Logout {
        /// Codeberg host (e.g. codeberg.org)
        #[arg(long, default_value = "codeberg.org", env = "CODEBERG_HOST")]
        host: String,
    },

    /// Show non-secret authentication status
    Status {
        /// Codeberg host (e.g. codeberg.org)
        #[arg(long, default_value = "codeberg.org", env = "CODEBERG_HOST")]
        host: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct BuildArgs {
    /// Build profile: generic, v3, v4, native, or all
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Upload successfully built packages to Codeberg Packages
    #[arg(long, default_value_t = false)]
    pub upload: bool,

    /// Base makepkg configuration file
    #[arg(long, env = "MAKEPKG_BASE_CONFIG", default_value = "/etc/makepkg.conf")]
    pub base_config: PathBuf,

    /// Codeberg host
    #[arg(long, default_value = "codeberg.org", env = "CODEBERG_HOST")]
    pub host: String,

    /// Codeberg package owner / repository namespace
    #[arg(long, default_value = "nathawat", env = "CODEBERG_OWNER")]
    pub owner: String,

    /// Do not run makepkg with --syncdeps
    #[arg(long, default_value_t = false)]
    pub no_syncdeps: bool,

    /// Do not run makepkg with --clean
    #[arg(long, default_value_t = false)]
    pub no_clean: bool,

    /// Do not run makepkg with --cleanbuild
    #[arg(long, default_value_t = false)]
    pub no_cleanbuild: bool,

    /// Do not run makepkg with --force
    #[arg(long, default_value_t = false)]
    pub no_force: bool,

    /// Pass --noconfirm to makepkg
    #[arg(long, default_value_t = false)]
    pub noconfirm: bool,
}
