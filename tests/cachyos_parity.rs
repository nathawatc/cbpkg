use cbpkg::cpu::mock::{MockCpuIdProvider, mock_v3_provider};
use cbpkg::profile::{BuildProfile, TargetProfile};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn extract_variables(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        // Skip indented lines (e.g. inside if blocks or array continuation)
        if line.starts_with(' ') || line.starts_with('\t') || line.starts_with('#') {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("if ") || trimmed == "fi" {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            if key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                let mut full_val = val.trim().to_string();
                // Handle backslash line continuations
                while full_val.ends_with('\\') {
                    full_val.pop(); // remove '\'
                    if let Some(next_line) = lines.next() {
                        full_val.push(' ');
                        full_val.push_str(next_line.trim());
                    } else {
                        break;
                    }
                }
                // Handle multi-line arrays like DLAGENTS=(...)
                if full_val.starts_with('(') && !full_val.ends_with(')') {
                    for next_line in lines.by_ref() {
                        let next_trimmed = next_line.trim();
                        full_val.push(' ');
                        full_val.push_str(next_trimmed);
                        if next_trimmed.ends_with(')') {
                            break;
                        }
                    }
                }
                let full_val = full_val.trim();
                // Strip enclosing quotes if single or double
                let stripped = if (full_val.starts_with('"') && full_val.ends_with('"'))
                    || (full_val.starts_with('\'') && full_val.ends_with('\''))
                {
                    full_val[1..full_val.len() - 1].to_string()
                } else {
                    full_val.to_string()
                };
                map.insert(key.to_string(), stripped);
            }
        }
    }
    map
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const PINNED_COMMIT: &str = "9b0259d98e535487de07b44d7e0e7d73b7a6be29";

fn assert_profile_pinned_parity(profile: BuildProfile, prefix: &str) {
    let dummy = MockCpuIdProvider::default();
    let target = TargetProfile::new(profile, &dummy);
    let makepkg_conf = target.render_makepkg_conf();
    let rust_conf = target.render_rust_conf();

    let makepkg_vars = extract_variables(&makepkg_conf);
    let rust_vars = extract_variables(&rust_conf);

    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cachyos")
        .join(PINNED_COMMIT);
    let upstream_makepkg_path = fixture_dir.join(format!("{prefix}.makepkg.conf"));
    let upstream_rust_path = fixture_dir.join(format!("{prefix}.rust.conf"));

    let upstream_makepkg_content = fs::read_to_string(&upstream_makepkg_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read pinned fixture {:?}: {e}",
            upstream_makepkg_path
        )
    });
    let upstream_rust_content = fs::read_to_string(&upstream_rust_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read pinned fixture {:?}: {e}",
            upstream_rust_path
        )
    });

    let upstream_makepkg_vars = extract_variables(&upstream_makepkg_content);
    let upstream_rust_vars = extract_variables(&upstream_rust_content);

    // 1. Rust policy exact match
    assert_eq!(
        rust_vars.get("RUSTFLAGS"),
        upstream_rust_vars.get("RUSTFLAGS")
    );
    assert_eq!(
        rust_vars.get("DEBUG_RUSTFLAGS"),
        upstream_rust_vars.get("DEBUG_RUSTFLAGS")
    );

    // 2. All relevant build-policy fields comparison
    let checked_fields = [
        "DLAGENTS",
        "VCSCLIENTS",
        "CARCH",
        "CHOST",
        "CFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "LTOFLAGS",
        "MAKEFLAGS",
        "NINJAFLAGS",
        "DEBUG_CFLAGS",
        "DEBUG_CXXFLAGS",
        "BUILDENV",
        "OPTIONS",
        "INTEGRITY_CHECK",
        "STRIP_BINARIES",
        "STRIP_SHARED",
        "STRIP_STATIC",
        "MAN_DIRS",
        "DOC_DIRS",
        "PURGE_TARGETS",
        "DBGSRCDIR",
        "LIB_DIRS",
        "COMPRESSGZ",
        "COMPRESSBZ2",
        "COMPRESSXZ",
        "COMPRESSZST",
        "COMPRESSLRZ",
        "COMPRESSLZO",
        "COMPRESSZ",
        "COMPRESSLZ4",
        "COMPRESSLZ",
        "PKGEXT",
        "SRCEXT",
    ];

    for field in checked_fields {
        let actual = makepkg_vars
            .get(field)
            .unwrap_or_else(|| panic!("Missing field in cbpkg: {field}"));
        let expected = upstream_makepkg_vars
            .get(field)
            .unwrap_or_else(|| panic!("Missing field in upstream: {field}"));
        assert_eq!(
            normalize_ws(actual),
            normalize_ws(expected),
            "Mismatch in field {field} for profile {:?}",
            profile
        );
    }

    if upstream_makepkg_vars.contains_key("PACKAGECARCH") {
        assert_eq!(
            makepkg_vars.get("PACKAGECARCH"),
            upstream_makepkg_vars.get("PACKAGECARCH")
        );
    }
    if upstream_makepkg_vars.contains_key("GOAMD64") {
        assert_eq!(
            makepkg_vars.get("GOAMD64"),
            upstream_makepkg_vars.get("GOAMD64")
        );
    }
}

#[test]
fn test_generic_parity() {
    assert_profile_pinned_parity(BuildProfile::Generic, "generic");
}

#[test]
fn test_v3_parity() {
    assert_profile_pinned_parity(BuildProfile::V3, "v3");
}

#[test]
fn test_v4_parity() {
    assert_profile_pinned_parity(BuildProfile::V4, "v4");
}

#[test]
fn test_native_derived_parity() {
    let dummy = mock_v3_provider();
    let target = TargetProfile::new(BuildProfile::Native, &dummy);
    let makepkg_conf = target.render_makepkg_conf();
    let rust_conf = target.render_rust_conf();

    let makepkg_vars = extract_variables(&makepkg_conf);
    let rust_vars = extract_variables(&rust_conf);

    assert_eq!(makepkg_vars.get("CARCH").unwrap(), "x86_64");
    assert_eq!(makepkg_vars.get("PACKAGECARCH").unwrap(), "x86_64_native");
    assert_eq!(makepkg_vars.get("GOAMD64").unwrap(), "v3");

    // Native must use march=native mtune=native without forcing -mpclmul
    assert!(
        makepkg_vars
            .get("CFLAGS")
            .unwrap()
            .contains("-march=native -mtune=native")
    );
    assert!(!makepkg_vars.get("CFLAGS").unwrap().contains("-mpclmul"));

    // Rust target must be native
    assert_eq!(
        rust_vars.get("RUSTFLAGS").unwrap(),
        "-C opt-level=3 -C target-cpu=native -Clink-arg=-z -Clink-arg=pack-relative-relocs"
    );

    // Common policy (LDFLAGS, LTOFLAGS, OPTIONS) must match CachyOS
    assert_eq!(makepkg_vars.get("LTOFLAGS").unwrap(), "-flto=auto");
    assert!(makepkg_vars.get("OPTIONS").unwrap().contains("lto"));
    assert_eq!(
        normalize_ws(makepkg_vars.get("LDFLAGS").unwrap()),
        "-Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,pack-relative-relocs"
    );
}

#[test]
fn test_exact_bidirectional_differences() {
    // Test for generic, v3, v4 that ALL differences between cbpkg and upstream CachyOS
    // are strictly in the documented allowlist and that NO unexpected differences exist.
    let profiles = [
        (BuildProfile::Generic, "generic"),
        (BuildProfile::V3, "v3"),
        (BuildProfile::V4, "v4"),
    ];

    for (profile, fixture_prefix) in profiles {
        let dummy = MockCpuIdProvider::default();
        let target = TargetProfile::new(profile, &dummy);
        let makepkg_conf = target.render_makepkg_conf();
        let cbpkg_vars = extract_variables(&makepkg_conf);

        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/cachyos/{PINNED_COMMIT}/{fixture_prefix}.makepkg.conf"
        ));
        let upstream_content = fs::read_to_string(&fixture_path).unwrap();
        let upstream_vars = extract_variables(&upstream_content);

        // Documented allowlist of intentional differences in variables:
        // 1. PKGDEST: Upstream sets /home/notroot/packages, cbpkg omits so packages build to current directory.
        // 2. LOGDEST: Upstream sets /home/notroot/packages, cbpkg omits so logs stay in current directory.
        let allowed_omitted_in_cbpkg = ["PKGDEST", "LOGDEST"];

        // Check every variable in upstream: must either match cbpkg or be on allowlist
        for (key, upstream_val) in &upstream_vars {
            if allowed_omitted_in_cbpkg.contains(&key.as_str()) {
                assert!(
                    !cbpkg_vars.contains_key(key),
                    "cbpkg unexpectedly defined {key} in profile {:?}, but it should be omitted per allowlist",
                    profile
                );
            } else {
                let cbpkg_val = cbpkg_vars.get(key).unwrap_or_else(|| {
                    panic!(
                        "cbpkg forgot to include upstream variable {key} in profile {:?}",
                        profile
                    )
                });
                assert_eq!(
                    normalize_ws(cbpkg_val),
                    normalize_ws(upstream_val),
                    "cbpkg variable {key} differs from upstream without being on allowlist in profile {:?}",
                    profile
                );
            }
        }

        // Check every variable in cbpkg: must exist in upstream
        for key in cbpkg_vars.keys() {
            assert!(
                upstream_vars.contains_key(key),
                "cbpkg defined unexpected variable {key} not present in upstream CachyOS for profile {:?}",
                profile
            );
        }

        // Check documented structural differences:
        // - cbpkg has PACKAGELIST bridge for optimized profiles (v3, v4)
        if target.is_optimized() {
            assert!(
                makepkg_conf.contains("PACKAGELIST bridge for PACKAGECARCH support"),
                "cbpkg missing required PACKAGELIST bridge in profile {:?}",
                profile
            );
            assert!(
                !upstream_content.contains("PACKAGELIST bridge for PACKAGECARCH support"),
                "upstream unexpectedly had PACKAGELIST bridge"
            );
        }
        // - cbpkg has dynamic header comments
        assert!(makepkg_conf.contains("# Generated by cbpkg for profile:"));
        assert!(!upstream_content.contains("# Generated by cbpkg for profile:"));
    }
}
