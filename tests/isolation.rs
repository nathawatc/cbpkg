use cbpkg::cpu::mock::MockCpuIdProvider;
use cbpkg::makepkg::{
    EXPLICIT_SANITIZED_VARS, find_makepkg, get_planned_packages, sanitize_command_env,
    setup_isolated_config,
};
use cbpkg::profile::{BuildProfile, TargetProfile};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_hostile_environment_isolation() {
    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);

    let temp_dir = tempfile::tempdir().unwrap();
    let conf_path = setup_isolated_config(&target, temp_dir.path()).unwrap();
    let content = fs::read_to_string(&conf_path).unwrap();

    // Verify generated configuration contains internal CachyOS policy, not host policy
    assert!(!content.contains("BAD_HOST_CONFIG"));
    assert!(!content.contains("totally-wrong"));
    assert!(content.contains("-march=x86-64 -mtune=generic"));
    assert!(content.contains("-flto=auto"));

    // Verify sanitize_command_env clears hostile variables from child processes
    let mut cmd = Command::new("env");

    // Populate every single explicitly sanitized variable with hostile values
    for var in EXPLICIT_SANITIZED_VARS {
        cmd.env(var, format!("HOSTILE_VALUE_FOR_{var}"));
    }

    sanitize_command_env(&mut cmd, Some(&target));

    // Run 'env' under child command and inspect output
    let output = cmd.output().expect("Failed to execute env");
    let out_str = String::from_utf8_lossy(&output.stdout);

    for var in EXPLICIT_SANITIZED_VARS {
        // GOAMD64 is only set if the profile defines it (Generic has None)
        assert!(
            !out_str.contains(&format!("{var}=HOSTILE_VALUE_FOR_{var}")),
            "Hostile variable '{var}' survived sanitize_command_env!"
        );
    }
}

#[test]
#[ignore]
fn worker_test_dynamic_cargo_target_rustflags() {
    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);

    // Verify the variable was inherited by this child process
    assert!(std::env::var("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS").is_ok());

    let mut cmd = Command::new("env");
    sanitize_command_env(&mut cmd, Some(&target));

    let output = cmd.output().expect("Failed to execute env");
    let out_str = String::from_utf8_lossy(&output.stdout);

    assert!(
        !out_str.contains("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="),
        "Dynamic Cargo target rustflags survived sanitize_command_env!"
    );
}

#[test]
fn test_dynamic_cargo_target_rustflags_in_subprocess() {
    let current_exe = std::env::current_exe().expect("Failed to get current_exe");
    let mut cmd = Command::new(current_exe);
    cmd.arg("worker_test_dynamic_cargo_target_rustflags");
    cmd.arg("--exact");
    cmd.arg("--ignored");
    cmd.arg("--nocapture");
    cmd.env(
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
        "-Ctarget-cpu=totally-wrong",
    );

    let output = cmd.output().expect("Failed to execute worker subprocess");
    if !output.status.success() {
        panic!(
            "Subprocess worker_test_dynamic_cargo_target_rustflags failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
#[ignore]
fn worker_test_non_utf8_env() {
    // Calling sanitize_command_env with non-UTF-8 parent environment variables must not panic
    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);
    let mut cmd = Command::new("true");
    sanitize_command_env(&mut cmd, Some(&target));
}

#[cfg(unix)]
#[test]
fn test_non_utf8_env_in_subprocess() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let current_exe = std::env::current_exe().expect("Failed to get current_exe");
    let mut cmd = Command::new(current_exe);
    cmd.arg("worker_test_non_utf8_env");
    cmd.arg("--exact");
    cmd.arg("--ignored");
    cmd.arg("--nocapture");
    cmd.env(
        OsStr::from_bytes(b"HOSTILE_NON_UTF8_VALUE"),
        OsStr::from_bytes(b"bad_utf8_\xFF\xFE_value"),
    );

    let output = cmd.output().expect("Failed to execute worker subprocess");
    if !output.status.success() {
        panic!(
            "Subprocess worker_test_non_utf8_env panicked or failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore]
fn worker_test_hostile_packagelist() {
    let makepkg_path = find_makepkg().expect("makepkg not found");
    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);

    let work_dir_str = std::env::var("CBPKG_TEST_WORK_DIR").expect("CBPKG_TEST_WORK_DIR not set");
    let conf_path_str =
        std::env::var("CBPKG_TEST_CONF_PATH").expect("CBPKG_TEST_CONF_PATH not set");
    let work_dir = Path::new(&work_dir_str);
    let conf_path = Path::new(&conf_path_str);

    // Verify hostile variables are in fact present in this worker process environment
    assert_eq!(
        std::env::var("PKGDEST").as_deref(),
        Ok("/tmp/cbpkg-hostile-pkgdest")
    );
    assert_eq!(std::env::var("PKGEXT").as_deref(), Ok(".evil"));
    assert_eq!(std::env::var("PACKAGER").as_deref(), Ok("Hostile Packager"));

    // Call real get_planned_packages() from within hostile environment!
    let planned = get_planned_packages(&makepkg_path, conf_path, work_dir, &target)
        .expect("get_planned_packages failed in hostile environment");

    assert_eq!(planned.len(), 1);
    let planned_path = &planned[0];

    // Must be in work_dir, not /tmp/cbpkg-hostile-pkgdest
    assert_eq!(planned_path.parent().unwrap(), work_dir);
    assert!(planned_path.to_string_lossy().ends_with(".pkg.tar.zst"));
    assert!(!planned_path.to_string_lossy().contains(".evil"));
    assert!(
        !planned_path
            .to_string_lossy()
            .contains("/tmp/cbpkg-hostile-pkgdest")
    );
}

#[test]
fn test_hostile_packagelist_in_subprocess() {
    let _makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => return,
    };

    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);

    let temp_conf_dir = tempfile::tempdir().unwrap();
    let conf_path = setup_isolated_config(&target, temp_conf_dir.path()).unwrap();

    let work_dir = tempfile::tempdir().unwrap();
    let pkgbuild = r#"
pkgname=hostilepkgdest
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
license=('MIT')

package() {
    true
}
"#;
    fs::write(work_dir.path().join("PKGBUILD"), pkgbuild).unwrap();

    let current_exe = std::env::current_exe().expect("Failed to get current_exe");
    let mut cmd = Command::new(current_exe);
    cmd.arg("worker_test_hostile_packagelist");
    cmd.arg("--exact");
    cmd.arg("--ignored");
    cmd.arg("--nocapture");
    cmd.env("PKGDEST", "/tmp/cbpkg-hostile-pkgdest");
    cmd.env("PKGEXT", ".evil");
    cmd.env("PACKAGER", "Hostile Packager");
    cmd.env("CBPKG_TEST_WORK_DIR", work_dir.path());
    cmd.env("CBPKG_TEST_CONF_PATH", &conf_path);

    let output = cmd.output().expect("Failed to execute worker subprocess");
    if !output.status.success() {
        panic!(
            "Subprocess worker_test_hostile_packagelist failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn test_makepkg_dropin_and_rust_policy_behavioral() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => return, // Skip behavioral test if makepkg is not installed
    };

    let dummy = MockCpuIdProvider::default();
    let profiles = [
        (BuildProfile::Generic, "x86-64"),
        (BuildProfile::V3, "x86-64-v3"),
        (BuildProfile::V4, "x86-64-v4"),
        (BuildProfile::Native, "native"),
    ];

    for (profile, expected_cpu) in profiles {
        let target = TargetProfile::new(profile, &dummy);
        let temp_conf_dir = tempfile::tempdir().unwrap();
        let conf_path = setup_isolated_config(&target, temp_conf_dir.path()).unwrap();

        let work_dir = tempfile::tempdir().unwrap();
        let pkgbuild = r#"
pkgname=rustenvtest
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
license=('MIT')

prepare() {
    echo "EFFECTIVE_RUSTFLAGS=$RUSTFLAGS" > "$srcdir/effective_rustflags.txt"
}

build() {
    true
}
package() {
    true
}
"#;
        fs::write(work_dir.path().join("PKGBUILD"), pkgbuild).unwrap();

        let mut cmd = Command::new(&makepkg_path);
        cmd.current_dir(work_dir.path());
        cmd.arg("--config").arg(&conf_path);
        cmd.arg("-o").arg("-f").arg("--nodeps");

        // Inject hostile parent environment overrides
        cmd.env("RUSTFLAGS", "-Ctarget-cpu=totally-wrong");
        cmd.env("CARGO_ENCODED_RUSTFLAGS", "totally-wrong");
        cmd.env("CFLAGS", "-DBAD_HOST_CONFIG");

        sanitize_command_env(&mut cmd, Some(&target));

        let status = cmd.status().expect("Failed to execute makepkg");
        assert!(status.success(), "makepkg failed for profile {:?}", profile);

        let record_path = work_dir.path().join("src/effective_rustflags.txt");
        assert!(
            record_path.is_file(),
            "effective_rustflags.txt not generated!"
        );
        let record = fs::read_to_string(&record_path).unwrap();

        assert!(
            record.contains(&format!("-C target-cpu={expected_cpu}")),
            "Profile {:?} effective RUSTFLAGS ({}) did not contain expected target-cpu={}",
            profile,
            record,
            expected_cpu
        );
        assert!(
            !record.contains("totally-wrong"),
            "Hostile RUSTFLAGS leaked into effective build environment: {}",
            record
        );
    }
}

#[test]
fn test_hostile_pkgdest_and_pkgext_real_makepkg() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => return,
    };

    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(BuildProfile::Generic, &dummy);

    let temp_conf_dir = tempfile::tempdir().unwrap();
    let conf_path = setup_isolated_config(&target, temp_conf_dir.path()).unwrap();

    let work_dir = tempfile::tempdir().unwrap();
    let hostile_pkgdest_dir = tempfile::tempdir().unwrap();

    let pkgbuild = r#"
pkgname=hostilepkgdest
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
license=('MIT')

package() {
    install -d "$pkgdir/usr/share/hostile"
    echo "content" > "$pkgdir/usr/share/hostile/file.txt"
}
"#;
    fs::write(work_dir.path().join("PKGBUILD"), pkgbuild).unwrap();

    // Perform actual makepkg build with hostile variables set
    let mut build_cmd = Command::new(&makepkg_path);
    build_cmd.current_dir(work_dir.path());
    build_cmd.arg("--config").arg(&conf_path);
    build_cmd.arg("-f").arg("--nodeps");
    build_cmd.env("PKGDEST", hostile_pkgdest_dir.path());
    build_cmd.env("PKGEXT", ".evil");
    build_cmd.env("SRCDEST", "/tmp/hostile-srcdest");
    build_cmd.env("LOGDEST", "/tmp/hostile-logdest");
    build_cmd.env("BUILDDIR", "/tmp/hostile-builddir");
    build_cmd.env("PACKAGER", "Hostile Packager");

    sanitize_command_env(&mut build_cmd, Some(&target));

    let status = build_cmd.status().expect("Failed to execute makepkg");
    assert!(status.success(), "makepkg build failed");

    // Package must be built in work_dir with .pkg.tar.zst, NOT in hostile_pkgdest_dir and NOT with .evil
    let expected_built = work_dir
        .path()
        .join("hostilepkgdest-1.0.0-1-x86_64.pkg.tar.zst");
    assert!(
        expected_built.is_file(),
        "Built package was not created in working directory: {:?}",
        expected_built
    );

    // Verify hostile_pkgdest_dir is completely empty
    let hostile_entries: Vec<_> = fs::read_dir(hostile_pkgdest_dir.path()).unwrap().collect();
    assert!(
        hostile_entries.is_empty(),
        "Hostile PKGDEST directory was written to! Contains: {:?}",
        hostile_entries
    );
}
