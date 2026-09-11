use cbpkg::cpu::HostCpuIdProvider;
use cbpkg::makepkg::{
    MakepkgBuildOptions, execute_build, find_makepkg, get_planned_packages, setup_isolated_config,
};
use cbpkg::package::{read_pkginfo_arch, validate_built_package, validate_planned_package};
use cbpkg::profile::{BuildProfile, TargetProfile};
use std::fs;

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
