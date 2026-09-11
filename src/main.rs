use cbpkg::cli::{AuthArgs, AuthCommand, BuildArgs, Cli, Commands};
use cbpkg::codeberg::{CodebergClient, UploadStatus, pacman_repo_url};
use cbpkg::cpu::{HostCpuIdProvider, validate_host_for_profile};
use cbpkg::error::AppError;
use cbpkg::makepkg::{
    MakepkgBuildOptions, execute_build, find_makepkg, get_planned_packages, setup_isolated_config,
};
use cbpkg::package::{validate_built_package, validate_planned_package};
use cbpkg::profile::{BuildProfile, TargetProfile};
use cbpkg::secret::{CredentialState, CredentialStore, SecretServiceStore, normalize_host};
use clap::{CommandFactory, Parser};
use std::io::{self, BufRead, Write};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Auth(auth_args)) => handle_auth(auth_args),
        Some(Commands::Build(build_args)) => handle_build(build_args),
        None => {
            let mut cmd = Cli::command();
            let _ = cmd.print_help();
            println!();
            Ok(())
        }
    };

    if let Err(err) = result {
        eprintln!("\x1b[1;31m==> ERROR:\x1b[0m {err}");
        std::process::exit(1);
    }
}

fn handle_auth(args: AuthArgs) -> Result<(), AppError> {
    let store = SecretServiceStore::new();

    match args.command {
        AuthCommand::Login { host, username } => {
            let host = normalize_host(&host)?;

            // Invariant: single-account-per-host. Refuse if credential already exists.
            match store.lookup_credential(&host)? {
                CredentialState::Present { username } => {
                    return Err(AppError::CredentialAlreadyExists { host, username });
                }
                CredentialState::Duplicate { .. } => {
                    return Err(AppError::DuplicateCredentials(host));
                }
                CredentialState::Missing => {}
            }

            let username = match username {
                Some(u) if !u.trim().is_empty() => u.trim().to_string(),
                _ => {
                    print!("Codeberg username [nathawat]: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().lock().read_line(&mut input)?;
                    let trimmed = input.trim();
                    if trimmed.is_empty() {
                        "nathawat".to_string()
                    } else {
                        trimmed.to_string()
                    }
                }
            };

            let token = rpassword::prompt_password("Codeberg access token: ")
                .map_err(|e| AppError::InputError(format!("Failed reading token: {e}")))?;

            let token = token.trim();
            if token.is_empty() {
                return Err(AppError::InputError("Token cannot be empty".to_string()));
            }

            println!("\x1b[1;34m==>\x1b[0m Verifying token with {host}...");
            let client = CodebergClient::new()?;
            client.verify_token(&host, &username, token)?;

            println!("\x1b[1;34m==>\x1b[0m Storing credential in Secret Service...");
            store.store_credential(&host, &username, token)?;

            println!(
                "\x1b[1;32m==>\x1b[0m Successfully authenticated and stored credential for '{username}' on '{host}'."
            );
            Ok(())
        }
        AuthCommand::Logout { host } => {
            let host = normalize_host(&host)?;
            if store.delete_credential(&host)? {
                println!("\x1b[1;32m==>\x1b[0m Removed Codeberg credential for '{host}'.");
            } else {
                println!("Codeberg credential: not configured for '{host}'");
            }
            Ok(())
        }
        AuthCommand::Status { host } => {
            let host = normalize_host(&host)?;
            match store.lookup_credential(&host)? {
                CredentialState::Present { username } => {
                    println!("Codeberg credential: available");
                    println!("Host: {host}");
                    println!("Username: {username}");
                }
                CredentialState::Missing => {
                    println!("Codeberg credential: not configured");
                    println!("Host: {host}");
                }
                CredentialState::Duplicate { .. } => {
                    return Err(AppError::DuplicateCredentials(host));
                }
            }
            Ok(())
        }
    }
}

fn handle_build(args: BuildArgs) -> Result<(), AppError> {
    let working_dir = std::env::current_dir()?;
    let pkgbuild_path = working_dir.join("PKGBUILD");
    if !pkgbuild_path.is_file() {
        return Err(AppError::PkgbuildNotFound(working_dir));
    }

    let makepkg_path = find_makepkg()?;
    let cpu_provider = HostCpuIdProvider::new();

    let (selected_profiles, upload_enabled) = if let Some(ref profile_str) = args.profile {
        let profiles = parse_cli_profiles(profile_str)?;
        (profiles, args.upload)
    } else {
        interactive_prompt(&args)?
    };

    if selected_profiles.is_empty() {
        println!("No profiles selected. Exiting.");
        return Ok(());
    }

    // Host architecture preflight for selected profiles
    for profile in &selected_profiles {
        validate_host_for_profile(&cpu_provider, profile.as_str())?;
    }

    let host = normalize_host(&args.host)?;

    // Verify authentication BEFORE build if upload is requested (metadata lookup only; no secret retrieval)
    if upload_enabled {
        let store = SecretServiceStore::new();
        match store.lookup_credential(&host)? {
            CredentialState::Present { .. } => {}
            CredentialState::Missing => return Err(AppError::CredentialMissing(host.clone())),
            CredentialState::Duplicate { .. } => {
                return Err(AppError::DuplicateCredentials(host.clone()));
            }
        }
    }

    let build_options = MakepkgBuildOptions {
        syncdeps: !args.no_syncdeps,
        clean: !args.no_clean,
        cleanbuild: !args.no_cleanbuild,
        force: !args.no_force,
        noconfirm: args.noconfirm,
    };

    let mut packages_to_upload = Vec::new();

    for profile in selected_profiles {
        let target = TargetProfile::new(profile, &cpu_provider);

        println!();
        println!("\x1b[1;34m==>\x1b[0m Profile: {}", target.name());
        println!(
            "\x1b[1;34m==>\x1b[0m Compiler: -march={} -mtune={}",
            target.march(),
            target.mtune()
        );
        println!(
            "\x1b[1;34m==>\x1b[0m Package arch: {}",
            target.package_carch()
        );
        println!(
            "\x1b[1;34m==>\x1b[0m Codeberg group: {}",
            target.codeberg_group()
        );
        if target.profile == BuildProfile::Native
            && let Some(goamd64) = target.goamd64_str()
        {
            println!("\x1b[1;34m==>\x1b[0m Detected Go microarchitecture level: {goamd64}");
        }

        // 1. Create isolated temporary directory
        let temp_dir = tempfile::tempdir().map_err(AppError::TempConfigCreate)?;

        // 2. Setup isolated configuration (makepkg.conf and makepkg.conf.d/rust.conf)
        let temp_conf_path = setup_isolated_config(&target, temp_dir.path())?;

        // 3 & 4. Determine planned outputs
        let planned_pkgs =
            get_planned_packages(&makepkg_path, &temp_conf_path, &working_dir, &target)?;

        println!("\x1b[1;34m==>\x1b[0m Planned package output:");
        for pkg in &planned_pkgs {
            println!("    {}", pkg.display());
        }

        // 5. Validate architecture labeling before building
        for pkg in &planned_pkgs {
            validate_planned_package(pkg, &target)?;
        }

        // 6. Run actual build through makepkg
        execute_build(
            &makepkg_path,
            &temp_conf_path,
            &working_dir,
            &build_options,
            &target,
        )?;

        // 7 & 8. Validate output existence and .PKGINFO metadata
        for pkg in &planned_pkgs {
            let actual_path = if pkg.is_absolute() {
                pkg.clone()
            } else {
                working_dir.join(pkg)
            };

            let arch = validate_built_package(&actual_path, &target)?;
            let file_name = actual_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| actual_path.display().to_string());

            println!("\x1b[1;32m==>\x1b[0m Built {file_name} [arch={arch}]");

            if upload_enabled {
                packages_to_upload.push((
                    actual_path,
                    target.codeberg_group().to_string(),
                    file_name,
                ));
            }
        }

        println!("\nRepository URL for pacman:");
        println!(
            "  {}",
            pacman_repo_url(
                &host,
                &args.owner,
                target.codeberg_group(),
                target.package_carch()
            )
        );
    }

    let mut upload_errors = Vec::new();
    if upload_enabled && !packages_to_upload.is_empty() {
        println!();
        println!("\x1b[1;34m==>\x1b[0m Uploading packages to Codeberg...");
        let store = SecretServiceStore::new();
        let cred = store.load_credential(&host)?;
        let client = CodebergClient::new()?;

        for (actual_path, group, file_name) in packages_to_upload {
            println!(
                "\x1b[1;34m==>\x1b[0m Uploading {file_name} to {}/{}...",
                args.owner, group
            );
            match client.upload_package(
                &host,
                &args.owner,
                &group,
                &cred.username,
                &cred.token,
                &actual_path,
            ) {
                Ok(UploadStatus::Success(status)) => {
                    println!("\x1b[1;32m==>\x1b[0m Uploaded: {file_name} (HTTP {status})");
                }
                Ok(UploadStatus::AlreadyExists(msg)) => {
                    eprintln!(
                        "\x1b[1;33m==> WARNING:\x1b[0m Codeberg returned HTTP 409 for {file_name}: {msg}"
                    );
                }
                Err(e) => {
                    eprintln!("\x1b[1;31m==> ERROR:\x1b[0m Failed uploading {file_name}: {e}");
                    upload_errors.push((file_name, e.to_string()));
                }
            }
        }
        drop(cred);
    }

    if !upload_errors.is_empty() {
        let list: Vec<String> = upload_errors
            .into_iter()
            .map(|(pkg, err)| format!("{pkg}: {err}"))
            .collect();
        return Err(AppError::UploadFailed {
            package: "one or more packages".to_string(),
            status: 0,
            message: list.join("; "),
        });
    }

    println!("\x1b[1;32m==>\x1b[0m Done.");
    Ok(())
}

fn parse_cli_profiles(s: &str) -> Result<Vec<BuildProfile>, AppError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(BuildProfile::ALL.to_vec()),
        other => {
            let profile = other
                .parse::<BuildProfile>()
                .map_err(AppError::InputError)?;
            Ok(vec![profile])
        }
    }
}

fn interactive_prompt(args: &BuildArgs) -> Result<(Vec<BuildProfile>, bool), AppError> {
    println!("\x1b[1;34m==>\x1b[0m Codeberg owner: {}", args.owner);
    println!();
    println!("Select build profile:");
    println!("  1) generic   x86-64     (package arch: x86_64)");
    println!("  2) v3        x86-64-v3  (package arch: x86_64_v3)");
    println!("  3) v4        x86-64-v4  (package arch: x86_64_v4)");
    println!("  4) native    host-tuned (package arch: x86_64_native)");
    println!("  5) all       build generic + v3 + v4 + native");
    println!("  0) exit");

    print!("Choice: ");
    io::stdout().flush()?;

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let choice = line.trim();

    let profiles = match choice {
        "1" => vec![BuildProfile::Generic],
        "2" => vec![BuildProfile::V3],
        "3" => vec![BuildProfile::V4],
        "4" => vec![BuildProfile::Native],
        "5" => BuildProfile::ALL.to_vec(),
        "0" => {
            println!("Exiting.");
            return Ok((vec![], false));
        }
        _ => {
            return Err(AppError::InputError(format!(
                "Invalid selection: '{choice}'"
            )));
        }
    };

    let upload = if args.upload {
        true
    } else {
        confirm("Upload successful builds to Codeberg Packages?")?
    };

    println!();
    println!(
        "\x1b[1;34m==>\x1b[0m Build directory: {}",
        std::env::current_dir()?.display()
    );
    if !confirm("Start build?")? {
        println!("\x1b[1;34m==>\x1b[0m Cancelled.");
        return Ok((vec![], false));
    }

    Ok((profiles, upload))
}

fn confirm(prompt: &str) -> Result<bool, AppError> {
    print!("{prompt} [y/N] ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
