use crate::error::AppError;
use crate::profile::TargetProfile;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPackage {
    pub pkgname: String,
    pub pkgver: String,
    pub pkgrel: String,
    pub arch: String,
}

pub fn parse_package_filename(path: &Path) -> Result<ParsedPackage, AppError> {
    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| AppError::InvalidPackageFilename(path.display().to_string()))?;

    // Must contain .pkg.tar
    let pkg_tar_idx = filename
        .find(".pkg.tar")
        .ok_or_else(|| AppError::InvalidPackageFilename(filename.to_string()))?;

    let stem = &filename[..pkg_tar_idx];
    let parts: Vec<&str> = stem.split('-').collect();

    // Format is <pkgname>-<pkgver>-<pkgrel>-<arch>
    // pkgname itself may contain hyphens, but pkgver, pkgrel, arch do not.
    if parts.len() < 4 {
        return Err(AppError::InvalidPackageFilename(filename.to_string()));
    }

    let arch = parts[parts.len() - 1].to_string();
    let pkgrel = parts[parts.len() - 2].to_string();
    let pkgver = parts[parts.len() - 3].to_string();
    let pkgname = parts[..parts.len() - 3].join("-");

    if pkgname.is_empty() || pkgver.is_empty() || pkgrel.is_empty() || arch.is_empty() {
        return Err(AppError::InvalidPackageFilename(filename.to_string()));
    }

    Ok(ParsedPackage {
        pkgname,
        pkgver,
        pkgrel,
        arch,
    })
}

pub fn validate_planned_package(path: &Path, target: &TargetProfile) -> Result<(), AppError> {
    let parsed = parse_package_filename(path)?;
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    if target.is_optimized() && parsed.arch == "x86_64" {
        return Err(AppError::BaselineArchitectureMismatch {
            profile: target.name().to_string(),
            package: filename,
        });
    }

    if parsed.arch != target.package_carch() && parsed.arch != "any" {
        return Err(AppError::ArchitectureMismatch {
            package: filename,
            expected: target.package_carch().to_string(),
            found: parsed.arch,
        });
    }

    Ok(())
}

pub fn read_pkginfo_arch(archive_path: &Path) -> Result<String, AppError> {
    let file = File::open(archive_path).map_err(|e| AppError::PkgInfoRead {
        path: archive_path.to_path_buf(),
        reason: format!("Could not open file: {e}"),
    })?;

    let decoder = zstd::stream::Decoder::new(file).map_err(|e| AppError::PkgInfoRead {
        path: archive_path.to_path_buf(),
        reason: format!("zstd decompression initialization failed: {e}"),
    })?;

    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|e| AppError::PkgInfoRead {
        path: archive_path.to_path_buf(),
        reason: format!("Failed to read tar entries: {e}"),
    })?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| AppError::PkgInfoRead {
            path: archive_path.to_path_buf(),
            reason: format!("Failed reading tar entry: {e}"),
        })?;

        let entry_path = entry.path().map_err(|e| AppError::PkgInfoRead {
            path: archive_path.to_path_buf(),
            reason: format!("Failed reading entry path: {e}"),
        })?;

        if entry_path.to_str() == Some(".PKGINFO") {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| AppError::PkgInfoRead {
                    path: archive_path.to_path_buf(),
                    reason: format!("Failed reading .PKGINFO content: {e}"),
                })?;

            for line in content.lines() {
                let trimmed = line.trim();
                if let Some((key, val)) = trimmed.split_once('=')
                    && key.trim() == "arch"
                {
                    let arch = val.trim().to_string();
                    if !arch.is_empty() {
                        return Ok(arch);
                    }
                }
            }

            return Err(AppError::PkgInfoMissingArch(archive_path.to_path_buf()));
        }
    }

    Err(AppError::PkgInfoRead {
        path: archive_path.to_path_buf(),
        reason: ".PKGINFO entry not found in archive".to_string(),
    })
}

pub fn validate_built_package(
    archive_path: &Path,
    target: &TargetProfile,
) -> Result<String, AppError> {
    if !archive_path.is_file() {
        return Err(AppError::ExpectedPackageMissing(archive_path.to_path_buf()));
    }

    let arch = read_pkginfo_arch(archive_path)?;
    let filename = archive_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| archive_path.display().to_string());

    if target.is_optimized() && arch == "x86_64" {
        return Err(AppError::BaselineArchitectureMismatch {
            profile: target.name().to_string(),
            package: filename,
        });
    }

    if arch != target.package_carch() && arch != "any" {
        return Err(AppError::ArchitectureMismatch {
            package: filename,
            expected: target.package_carch().to_string(),
            found: arch,
        });
    }

    Ok(arch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::CpuFeatures;
    use crate::profile::BuildProfile;
    use std::io::Write;

    #[test]
    fn test_parse_regular_package() {
        let path = Path::new("/var/cache/pkg/foo-1.2.3-4-x86_64.pkg.tar.zst");
        let parsed = parse_package_filename(path).unwrap();
        assert_eq!(parsed.pkgname, "foo");
        assert_eq!(parsed.pkgver, "1.2.3");
        assert_eq!(parsed.pkgrel, "4");
        assert_eq!(parsed.arch, "x86_64");
    }

    #[test]
    fn test_parse_split_package_with_hyphens() {
        let path = Path::new("/var/cache/pkg/foo-bar-extra-2.0.1-1-x86_64_v3.pkg.tar.zst");
        let parsed = parse_package_filename(path).unwrap();
        assert_eq!(parsed.pkgname, "foo-bar-extra");
        assert_eq!(parsed.pkgver, "2.0.1");
        assert_eq!(parsed.pkgrel, "1");
        assert_eq!(parsed.arch, "x86_64_v3");
    }

    #[test]
    fn test_parse_package_with_x86_64_in_name() {
        let path = Path::new("/tmp/build/tool-x86_64-utils-1.0-2-any.pkg.tar.zst");
        let parsed = parse_package_filename(path).unwrap();
        assert_eq!(parsed.pkgname, "tool-x86_64-utils");
        assert_eq!(parsed.pkgver, "1.0");
        assert_eq!(parsed.pkgrel, "2");
        assert_eq!(parsed.arch, "any");
    }

    #[test]
    fn test_parse_native_package() {
        let path = Path::new("mypkg-0.9-1-x86_64_native.pkg.tar.zst");
        let parsed = parse_package_filename(path).unwrap();
        assert_eq!(parsed.pkgname, "mypkg");
        assert_eq!(parsed.arch, "x86_64_native");
    }

    #[test]
    fn test_parse_invalid_filename() {
        assert!(parse_package_filename(Path::new("not_a_package.tar.gz")).is_err());
        assert!(parse_package_filename(Path::new("short-1-x86_64.pkg.tar.zst")).is_err());
    }

    #[test]
    fn test_validate_planned_package_safety() {
        let cpu = CpuFeatures::default();
        let generic = TargetProfile::new(BuildProfile::Generic, &cpu);
        let v3 = TargetProfile::new(BuildProfile::V3, &cpu);
        let v4 = TargetProfile::new(BuildProfile::V4, &cpu);
        let native = TargetProfile::new(BuildProfile::Native, &cpu);

        // Generic accepts x86_64 and any
        assert!(
            validate_planned_package(Path::new("pkg-1-1-x86_64.pkg.tar.zst"), &generic).is_ok()
        );
        assert!(validate_planned_package(Path::new("pkg-1-1-any.pkg.tar.zst"), &generic).is_ok());

        // Optimized profiles REJECT x86_64
        assert!(matches!(
            validate_planned_package(Path::new("pkg-1-1-x86_64.pkg.tar.zst"), &v3),
            Err(AppError::BaselineArchitectureMismatch { .. })
        ));
        assert!(matches!(
            validate_planned_package(Path::new("pkg-1-1-x86_64.pkg.tar.zst"), &v4),
            Err(AppError::BaselineArchitectureMismatch { .. })
        ));
        assert!(matches!(
            validate_planned_package(Path::new("pkg-1-1-x86_64.pkg.tar.zst"), &native),
            Err(AppError::BaselineArchitectureMismatch { .. })
        ));

        // Optimized profiles ACCEPT their respective arches and any
        assert!(validate_planned_package(Path::new("pkg-1-1-x86_64_v3.pkg.tar.zst"), &v3).is_ok());
        assert!(validate_planned_package(Path::new("pkg-1-1-any.pkg.tar.zst"), &v3).is_ok());

        assert!(validate_planned_package(Path::new("pkg-1-1-x86_64_v4.pkg.tar.zst"), &v4).is_ok());
        assert!(validate_planned_package(Path::new("pkg-1-1-any.pkg.tar.zst"), &v4).is_ok());

        assert!(
            validate_planned_package(Path::new("pkg-1-1-x86_64_native.pkg.tar.zst"), &native)
                .is_ok()
        );
        assert!(validate_planned_package(Path::new("pkg-1-1-any.pkg.tar.zst"), &native).is_ok());
    }

    #[test]
    fn test_pkginfo_inspection() {
        let temp_dir = tempfile::tempdir().unwrap();
        let archive_path = temp_dir.path().join("test-1.0-1-x86_64_v3.pkg.tar.zst");

        // Synthesize an in-memory tar.zst archive containing .PKGINFO
        let pkginfo_content = b"# makepkg\npkgname = test\narch = x86_64_v3\n";
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path(".PKGINFO").unwrap();
        header.set_size(pkginfo_content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &pkginfo_content[..]).unwrap();
        let uncompressed = tar_builder.into_inner().unwrap();

        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(&uncompressed).unwrap();
        let compressed = encoder.finish().unwrap();

        std::fs::write(&archive_path, compressed).unwrap();

        let cpu = CpuFeatures::default();
        let v3 = TargetProfile::new(BuildProfile::V3, &cpu);
        let arch = validate_built_package(&archive_path, &v3).unwrap();
        assert_eq!(arch, "x86_64_v3");
    }
}
