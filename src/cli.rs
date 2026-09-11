use clap::{Args, Parser, Subcommand};

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

    /// Codeberg host
    #[arg(long, default_value = "codeberg.org", env = "CODEBERG_HOST")]
    pub host: String,

    /// Codeberg package owner / repository namespace
    #[arg(long, env = "CODEBERG_OWNER")]
    pub owner: Option<String>,

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

pub fn resolve_login_username<F>(
    cli_user: Option<String>,
    prompt_fn: F,
) -> Result<String, crate::error::AppError>
where
    F: FnOnce() -> Result<String, crate::error::AppError>,
{
    match cli_user {
        Some(u) => {
            let trimmed = u.trim().to_string();
            if trimmed.is_empty() {
                return Err(crate::error::AppError::InputError(
                    "Username cannot be empty".to_string(),
                ));
            }
            Ok(trimmed)
        }
        None => {
            let input = prompt_fn()?;
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                return Err(crate::error::AppError::InputError(
                    "Username cannot be empty".to_string(),
                ));
            }
            Ok(trimmed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    #[test]
    fn test_auth_login_cli_has_no_default_username() {
        let cli = Cli::try_parse_from(["cbpkg", "auth", "login"]).unwrap();
        match cli.command {
            Some(Commands::Auth(AuthArgs {
                command: AuthCommand::Login { username, .. },
            })) => {
                assert_eq!(
                    username, None,
                    "auth login must not have a default username"
                );
            }
            other => panic!("Unexpected parsed command: {:?}", other),
        }
    }

    #[test]
    fn test_build_cli_has_no_default_owner() {
        let cli = Cli::try_parse_from(["cbpkg", "build"]).unwrap();
        match cli.command {
            Some(Commands::Build(BuildArgs { owner, .. })) => {
                assert_eq!(owner, None, "build must not have a hardcoded default owner");
            }
            other => panic!("Unexpected parsed command: {:?}", other),
        }
    }

    #[test]
    fn test_resolve_login_username_with_valid_explicit() {
        let res = resolve_login_username(Some("  alice  ".to_string()), || unreachable!()).unwrap();
        assert_eq!(res, "alice");
    }

    #[test]
    fn test_resolve_login_username_with_blank_explicit_rejected() {
        let res = resolve_login_username(Some("   ".to_string()), || unreachable!());
        assert!(
            matches!(res, Err(AppError::InputError(msg)) if msg.contains("Username cannot be empty"))
        );

        let res_empty = resolve_login_username(Some("".to_string()), || unreachable!());
        assert!(
            matches!(res_empty, Err(AppError::InputError(msg)) if msg.contains("Username cannot be empty"))
        );
    }

    #[test]
    fn test_resolve_login_username_with_valid_prompt() {
        let res = resolve_login_username(None, || Ok("  bob  ".to_string())).unwrap();
        assert_eq!(res, "bob");
    }

    #[test]
    fn test_resolve_login_username_with_blank_prompt_rejected() {
        let res = resolve_login_username(None, || Ok("   \n".to_string()));
        assert!(
            matches!(res, Err(AppError::InputError(msg)) if msg.contains("Username cannot be empty"))
        );

        let res_empty = resolve_login_username(None, || Ok("".to_string()));
        assert!(
            matches!(res_empty, Err(AppError::InputError(msg)) if msg.contains("Username cannot be empty"))
        );
    }
}
