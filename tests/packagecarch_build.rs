use cbpkg::cpu::HostCpuIdProvider;
use cbpkg::makepkg::{
    MakepkgBuildOptions, execute_build, find_makepkg, get_planned_packages, setup_isolated_config,
};
use cbpkg::package::{
    StagedPackage, read_pkginfo_arch, validate_built_package, validate_planned_package,
};
use cbpkg::profile::{BuildProfile, TargetProfile};
use std::fs;
use std::process::Command;

#[test]
fn test_packagecarch_packagelist_and_build_flow() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("makepkg not found in PATH; skipping real build integration test");
            return;
        }
    };

    let cpu = HostCpuIdProvider::new();
    let profiles = [
        BuildProfile::Generic,
        BuildProfile::V3,
        BuildProfile::Native,
    ];

    for profile in profiles {
        let target = TargetProfile::new(profile, &cpu);
        let temp_dir = tempfile::tempdir().unwrap();
        let build_dir = temp_dir.path().join("build");
        fs::create_dir_all(&build_dir).unwrap();

        let pkgbuild = r#"
pkgname=dummytest
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
pkgdesc="Dummy package for cbpkg PACKAGECARCH testing"
package() {
    mkdir -p "$pkgdir/usr/share/dummytest"
    echo "test" > "$pkgdir/usr/share/dummytest/test.txt"
}
"#;
        fs::write(build_dir.join("PKGBUILD"), pkgbuild).unwrap();

        let conf_path = setup_isolated_config(&target, &build_dir).unwrap();

        // 1. Check planned package
        let planned = get_planned_packages(&makepkg_path, &conf_path, &build_dir, &target).unwrap();
        assert_eq!(planned.len(), 1);
        validate_planned_package(&planned[0], &target).unwrap();

        let filename = planned[0].file_name().unwrap().to_str().unwrap();
        let expected_arch = target.package_carch();
        assert!(
            filename.contains(&format!("-{expected_arch}.pkg.tar.zst")),
            "Expected filename to contain -{expected_arch}.pkg.tar.zst, got {filename}"
        );

        // 2. Execute build
        let options = MakepkgBuildOptions {
            syncdeps: false,
            clean: false,
            cleanbuild: false,
            force: true,
            noconfirm: true,
        };
        execute_build(&makepkg_path, &conf_path, &build_dir, &options, &target).unwrap();

        // 3. Verify actual built package and .PKGINFO arch
        let actual_pkg = if planned[0].is_absolute() {
            planned[0].clone()
        } else {
            build_dir.join(&planned[0])
        };
        assert!(
            actual_pkg.is_file(),
            "Built package missing: {:?}",
            actual_pkg
        );

        let validated_arch = validate_built_package(&actual_pkg, &target).unwrap();
        assert_eq!(validated_arch, target.package_carch());

        let pkginfo_arch = read_pkginfo_arch(&actual_pkg).unwrap();
        assert_eq!(pkginfo_arch, target.package_carch());
    }
}

fn read_file_from_package(archive_path: &std::path::Path, target_file: &str) -> String {
    let file = fs::File::open(archive_path).unwrap();
    let decoder = zstd::stream::Decoder::new(file).unwrap();
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap();
        if path.to_str().unwrap().ends_with(target_file) {
            let mut content = String::new();
            std::io::Read::read_to_string(&mut entry, &mut content).unwrap();
            return content;
        }
    }
    panic!(
        "File {} not found in archive {:?}",
        target_file, archive_path
    );
}

#[test]
fn test_profile_all_staged_any_artifacts_retains_bytes_per_profile() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("makepkg not found in PATH; skipping real build integration test");
            return;
        }
    };

    let cpu = HostCpuIdProvider::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let build_dir = temp_dir.path().join("build");
    fs::create_dir_all(&build_dir).unwrap();

    let pkgbuild = r#"
pkgname=anytest
pkgver=1.0.0
pkgrel=1
arch=('any')
pkgdesc="Test any arch package staging"
package() {
    mkdir -p "$pkgdir/usr/share/anytest"
    echo "BUILD_FLAGS=$CFLAGS" > "$pkgdir/usr/share/anytest/build_marker.txt"
}
"#;
    fs::write(build_dir.join("PKGBUILD"), pkgbuild).unwrap();

    let mut queued_staged_packages: Vec<StagedPackage> = Vec::new();

    for profile in BuildProfile::ALL {
        let target = TargetProfile::new(profile, &cpu);
        let conf_path = setup_isolated_config(&target, &build_dir).unwrap();

        let planned = get_planned_packages(&makepkg_path, &conf_path, &build_dir, &target).unwrap();
        assert_eq!(planned.len(), 1);
        validate_planned_package(&planned[0], &target).unwrap();

        let options = MakepkgBuildOptions {
            syncdeps: false,
            clean: false,
            cleanbuild: false,
            force: true,
            noconfirm: true,
        };
        execute_build(&makepkg_path, &conf_path, &build_dir, &options, &target).unwrap();

        let actual_pkg = if planned[0].is_absolute() {
            planned[0].clone()
        } else {
            build_dir.join(&planned[0])
        };

        let arch = validate_built_package(&actual_pkg, &target).unwrap();
        assert_eq!(arch, "any");

        let staged = StagedPackage::stage(&actual_pkg, target.codeberg_group()).unwrap();
        queued_staged_packages.push(staged);
    }

    assert_eq!(queued_staged_packages.len(), 4);

    // Verify each staged package retained the bytes from its OWN profile build
    let generic_marker =
        read_file_from_package(&queued_staged_packages[0].staged_path, "build_marker.txt");
    assert!(generic_marker.contains("-march=x86-64 -mtune=generic"));
    assert!(!generic_marker.contains("-march=x86-64-v3"));

    let v3_marker =
        read_file_from_package(&queued_staged_packages[1].staged_path, "build_marker.txt");
    assert!(v3_marker.contains("-march=x86-64-v3"));

    let v4_marker =
        read_file_from_package(&queued_staged_packages[2].staged_path, "build_marker.txt");
    assert!(v4_marker.contains("-march=x86-64-v4"));

    let native_marker =
        read_file_from_package(&queued_staged_packages[3].staged_path, "build_marker.txt");
    assert!(native_marker.contains("-march=native -mtune=native"));

    // Verify build_dir only has the last built artifact bytes (native), proving that earlier artifacts
    // would have been overwritten without RAII staging!
    let live_output = build_dir.join("anytest-1.0.0-1-any.pkg.tar.zst");
    let live_marker = read_file_from_package(&live_output, "build_marker.txt");
    assert!(live_marker.contains("-march=native -mtune=native"));

    // Verify RAII cleanup of staged snapshots
    let paths: Vec<_> = queued_staged_packages
        .iter()
        .map(|s| s.staged_path.clone())
        .collect();
    drop(queued_staged_packages);
    for p in paths {
        assert!(!p.exists(), "Staged snapshot was not cleaned up: {:?}", p);
    }
}

#[test]
fn test_local_build_without_owner_does_not_touch_secret_service_or_dbus() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("makepkg not found in PATH; skipping test");
            return;
        }
    };
    let _ = makepkg_path;

    let temp_dir = tempfile::tempdir().unwrap();
    let build_dir = temp_dir.path().join("build");
    fs::create_dir_all(&build_dir).unwrap();

    let pkgbuild = r#"
pkgname=localonlytest
pkgver=1.0.0
pkgrel=1
arch=('any')
pkgdesc="Test local-only build without owner or secret service"
package() {
    mkdir -p "$pkgdir/usr/share/localonlytest"
    echo "local" > "$pkgdir/usr/share/localonlytest/test.txt"
}
"#;
    fs::write(build_dir.join("PKGBUILD"), pkgbuild).unwrap();

    let bin = env!("CARGO_BIN_EXE_cbpkg");
    let output = Command::new(bin)
        .arg("build")
        .arg("-p")
        .arg("generic")
        .arg("--no-syncdeps")
        .arg("--noconfirm")
        .current_dir(&build_dir)
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("CODEBERG_OWNER")
        .output()
        .expect("Failed to execute cbpkg binary");

    assert!(
        output.status.success(),
        "Local build failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Built localonlytest-1.0.0-1-any.pkg.tar.zst"));
    // Owner is not specified, so no repository URL should be printed
    assert!(
        !stdout.contains("Repository URL for pacman:"),
        "Repository URL must be omitted in local-only build without owner"
    );

    let pkg_file = build_dir.join("localonlytest-1.0.0-1-any.pkg.tar.zst");
    assert!(pkg_file.is_file(), "Expected built package file to exist");
}

#[test]
fn test_local_build_with_explicit_owner_prints_repo_url_without_secret_service() {
    let makepkg_path = match find_makepkg() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("makepkg not found in PATH; skipping test");
            return;
        }
    };
    let _ = makepkg_path;

    let temp_dir = tempfile::tempdir().unwrap();
    let build_dir = temp_dir.path().join("build");
    fs::create_dir_all(&build_dir).unwrap();

    let pkgbuild = r#"
pkgname=explicitownertest
pkgver=1.0.0
pkgrel=1
arch=('any')
pkgdesc="Test local-only build with explicit owner"
package() {
    mkdir -p "$pkgdir/usr/share/explicitownertest"
    echo "explicit" > "$pkgdir/usr/share/explicitownertest/test.txt"
}
"#;
    fs::write(build_dir.join("PKGBUILD"), pkgbuild).unwrap();

    let bin = env!("CARGO_BIN_EXE_cbpkg");
    let output = Command::new(bin)
        .arg("build")
        .arg("-p")
        .arg("generic")
        .arg("--owner")
        .arg("mycustomowner")
        .arg("--no-syncdeps")
        .arg("--noconfirm")
        .current_dir(&build_dir)
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .output()
        .expect("Failed to execute cbpkg binary");

    assert!(
        output.status.success(),
        "Local build failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Built explicitownertest-1.0.0-1-any.pkg.tar.zst"));
    assert!(
        stdout.contains("Repository URL for pacman:"),
        "Repository URL should be printed when owner is explicitly given"
    );
    assert!(
        stdout.contains("mycustomowner"),
        "Repository URL must contain explicit owner"
    );
}
