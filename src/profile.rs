use crate::cpu::{CpuIdProvider, Goamd64Level, detect_native_goamd64};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildProfile {
    Generic,
    V3,
    V4,
    Native,
}

impl BuildProfile {
    pub const ALL: [BuildProfile; 4] = [
        BuildProfile::Generic,
        BuildProfile::V3,
        BuildProfile::V4,
        BuildProfile::Native,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::V3 => "v3",
            Self::V4 => "v4",
            Self::Native => "native",
        }
    }
}

impl fmt::Display for BuildProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for BuildProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "generic" => Ok(Self::Generic),
            "v3" => Ok(Self::V3),
            "v4" => Ok(Self::V4),
            "native" => Ok(Self::Native),
            other => Err(format!(
                "Unknown profile: '{other}'. Expected one of: generic, v3, v4, native, all"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetProfile {
    pub profile: BuildProfile,
    pub goamd64: Option<Goamd64Level>,
}

impl TargetProfile {
    pub fn new(profile: BuildProfile, provider: &impl CpuIdProvider) -> Self {
        let goamd64 = match profile {
            BuildProfile::Generic => None,
            BuildProfile::V3 => Some(Goamd64Level::V3),
            BuildProfile::V4 => Some(Goamd64Level::V4),
            BuildProfile::Native => Some(detect_native_goamd64(provider)),
        };

        Self { profile, goamd64 }
    }

    pub fn from_parts(profile: BuildProfile, goamd64: Option<Goamd64Level>) -> Self {
        Self { profile, goamd64 }
    }

    pub fn name(&self) -> &'static str {
        self.profile.as_str()
    }

    pub fn codeberg_group(&self) -> &'static str {
        match self.profile {
            BuildProfile::Generic => "x86-64",
            BuildProfile::V3 => "x86-64-v3",
            BuildProfile::V4 => "x86-64-v4",
            BuildProfile::Native => "native",
        }
    }

    pub fn package_carch(&self) -> &'static str {
        match self.profile {
            BuildProfile::Generic => "x86_64",
            BuildProfile::V3 => "x86_64_v3",
            BuildProfile::V4 => "x86_64_v4",
            BuildProfile::Native => "x86_64_native",
        }
    }

    pub fn is_optimized(&self) -> bool {
        self.profile != BuildProfile::Generic
    }

    pub fn march(&self) -> &'static str {
        match self.profile {
            BuildProfile::Generic => "x86-64",
            BuildProfile::V3 => "x86-64-v3",
            BuildProfile::V4 => "x86-64-v4",
            BuildProfile::Native => "native",
        }
    }

    pub fn mtune(&self) -> &'static str {
        match self.profile {
            BuildProfile::Generic | BuildProfile::V3 | BuildProfile::V4 => "generic",
            BuildProfile::Native => "native",
        }
    }

    pub fn rust_target_cpu(&self) -> &'static str {
        match self.profile {
            BuildProfile::Generic => "x86-64",
            BuildProfile::V3 => "x86-64-v3",
            BuildProfile::V4 => "x86-64-v4",
            BuildProfile::Native => "native",
        }
    }

    pub fn goamd64_str(&self) -> Option<&'static str> {
        self.goamd64.map(|l| l.as_str())
    }

    pub fn extra_cflags(&self) -> &'static str {
        match self.profile {
            BuildProfile::V3 | BuildProfile::V4 => " -mpclmul",
            BuildProfile::Generic | BuildProfile::Native => "",
        }
    }

    pub fn cflags(&self) -> String {
        format!(
            "-march={} -mtune={} -O3 -pipe -fno-plt -fexceptions \
        -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security \
        -fstack-clash-protection -fcf-protection{}",
            self.march(),
            self.mtune(),
            self.extra_cflags()
        )
    }

    pub fn cxxflags(&self) -> &'static str {
        "$CFLAGS -Wp,-D_GLIBCXX_ASSERTIONS"
    }

    pub fn ldflags(&self) -> &'static str {
        "-Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now \\\n         -Wl,-z,pack-relative-relocs"
    }

    pub fn ltoflags(&self) -> &'static str {
        "-flto=auto"
    }

    pub fn rustflags(&self) -> String {
        format!(
            "-C opt-level=3 -C target-cpu={} -Clink-arg=-z -Clink-arg=pack-relative-relocs",
            self.rust_target_cpu()
        )
    }

    pub fn debug_rustflags(&self) -> &'static str {
        "-C debuginfo=2"
    }

    pub fn render_makepkg_conf(&self) -> String {
        let arch_lines = match self.profile {
            BuildProfile::Generic => "CARCH=\"x86_64\"\nCHOST=\"x86_64-pc-linux-gnu\"".to_string(),
            BuildProfile::V3 => "CARCH=\"x86_64\"\n#CARCH=\"x86_64_v3\"\nCHOST=\"x86_64-pc-linux-gnu\"\nPACKAGECARCH=\"x86_64_v3\"".to_string(),
            BuildProfile::V4 => "CARCH=\"x86_64\"\n#CARCH=\"x86_64_v4\"\nCHOST=\"x86_64-pc-linux-gnu\"\nPACKAGECARCH=\"x86_64_v4\"".to_string(),
            BuildProfile::Native => "CARCH=\"x86_64\"\n#CARCH=\"x86_64_native\"\nCHOST=\"x86_64-pc-linux-gnu\"\nPACKAGECARCH=\"x86_64_native\"".to_string(),
        };

        let goamd64_line = match self.goamd64 {
            Some(level) => format!("\nGOAMD64={}", level.as_str()),
            None => String::new(),
        };

        let bridge = if self.is_optimized() {
            r#"
# PACKAGELIST bridge for PACKAGECARCH support
if (( PACKAGELIST )); then
    if [[ -n "$PACKAGECARCH" ]]; then
        IGNOREARCH=1
        CARCH="$PACKAGECARCH"
    fi
fi
"#
        } else {
            ""
        };

        format!(
            r#"#!/hint/bash
#
# Generated by cbpkg for profile: {profile}
# Source: CachyOS docker-makepkg (upstream build policy)
# This file is temporary and isolated from host makepkg configuration.
#

#########################################################################
# SOURCE ACQUISITION
#########################################################################
#
#-- The download utilities that makepkg should use to acquire sources
#  Format: 'protocol::agent'
DLAGENTS=('file::/usr/bin/curl -qgC - -o %o %u'
          'ftp::/usr/bin/curl -qgfC - --ftp-pasv --retry 3 --retry-delay 3 -o %o %u'
          'http::/usr/bin/curl -qgb "" -fLC - --retry 3 --retry-delay 3 -o %o %u'
          'https::/usr/bin/curl -qgb "" -fLC - --retry 3 --retry-delay 3 -o %o %u'
          'rsync::/usr/bin/rsync --no-motd -z %u %o'
          'scp::/usr/bin/scp -C %u %o')

# Other common tools:
# /usr/bin/snarf
# /usr/bin/lftpget -c
# /usr/bin/wget

#-- The package required by makepkg to download VCS sources
#  Format: 'protocol::package'
VCSCLIENTS=('bzr::bzr'
            'fossil::fossil'
            'git::git'
            'hg::mercurial'
            'svn::subversion')

#########################################################################
# ARCHITECTURE, COMPILE FLAGS
#########################################################################
#
{arch_lines}

#-- Compiler and Linker Flags
CFLAGS="{cflags}"
CXXFLAGS="$CFLAGS -Wp,-D_GLIBCXX_ASSERTIONS"
LDFLAGS="-Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now \
         -Wl,-z,pack-relative-relocs"
LTOFLAGS="-flto=auto"
#-- Make Flags: change this for DistCC/SMP systems
MAKEFLAGS="-j$(nproc)"
NINJAFLAGS="-j$(nproc)"
#-- Debugging flags
DEBUG_CFLAGS="-g"
DEBUG_CXXFLAGS="$DEBUG_CFLAGS"
#DEBUG_RUSTFLAGS="-C debuginfo=2"{goamd64_line}
#########################################################################
# BUILD ENVIRONMENT
#########################################################################
#
# Makepkg defaults: BUILDENV=(!distcc !color !ccache check !sign)
#  A negated environment option will do the opposite of the comments below.
#
#-- distcc:   Use the Distributed C/C++/ObjC compiler
#-- color:    Colorize output messages
#-- ccache:   Use ccache to cache compilation
#-- check:    Run the check() function if present in the PKGBUILD
#-- sign:     Generate PGP signature file
#
BUILDENV=(!distcc color !ccache check !sign)
#
#-- If using DistCC, your MAKEFLAGS will also need modification. In addition,
#-- specify a space-delimited list of hosts running in the DistCC cluster.
#DISTCC_HOSTS=""
#
#-- Specify a directory for package building.
#BUILDDIR=/tmp/makepkg

#########################################################################
# GLOBAL PACKAGE OPTIONS
#   These are default values for the options=() settings
#########################################################################
#
# Makepkg defaults: OPTIONS=(!strip docs libtool staticlibs emptydirs !zipman !purge !debug !lto)
#  A negated option will do the opposite of the comments below.
#
#-- strip:      Strip symbols from binaries/libraries
#-- docs:       Save doc directories specified by DOC_DIRS
#-- libtool:    Leave libtool (.la) files in packages
#-- staticlibs: Leave static library (.a) files in packages
#-- emptydirs:  Leave empty directories in packages
#-- zipman:     Compress manual (man and info) pages in MAN_DIRS with gzip
#-- purge:      Remove files specified by PURGE_TARGETS
#-- debug:      Add debugging flags as specified in DEBUG_* variables
#-- lto:        Add compile flags for building with link time optimization
#
OPTIONS=(strip docs !libtool !staticlibs emptydirs zipman purge !debug lto !autodeps)
#-- File integrity checks to use. Valid: md5, sha1, sha224, sha256, sha384, sha512, b2
INTEGRITY_CHECK=(sha256)
#-- Options to be used when stripping binaries. See `man strip' for details.
STRIP_BINARIES="--strip-all"
#-- Options to be used when stripping shared libraries. See `man strip' for details.
STRIP_SHARED="--strip-unneeded"
#-- Options to be used when stripping static libraries. See `man strip' for details.
STRIP_STATIC="--strip-debug"
#-- Manual (man and info) directories to compress (if zipman is specified)
MAN_DIRS=({{usr{{,/local}}{{,/share}},opt/*}}/{{man,info}})
#-- Doc directories to remove (if !docs is specified)
DOC_DIRS=(usr/{{,local/}}{{,share/}}{{doc,gtk-doc}} opt/*/{{doc,gtk-doc}})
#-- Files to be removed from all packages (if purge is specified)
PURGE_TARGETS=(usr/{{,share}}/info/dir .packlist *.pod)
#-- Directory to store source code in for debug packages
DBGSRCDIR="/usr/src/debug"
#-- Prefix and directories for library autodeps
LIB_DIRS=('lib:usr/lib' 'lib32:usr/lib32')


#########################################################################
# PACKAGE OUTPUT
#########################################################################
#
# Default: put built package and cached source in build directory
#
#-- Destination: specify a fixed directory where all packages will be placed
#PKGDEST=/home/packages
#-- Source cache: specify a fixed directory where source files will be cached
#SRCDEST=/home/sources
#-- Source packages: specify a fixed directory where all src packages will be placed
#SRCPKGDEST=/home/srcpackages
#-- Log files: specify a fixed directory where all log files will be placed
#-- Packager: name/email of the person or organization building packages
#PACKAGER=""
#-- Specify a key to use for package signing
#GPGKEY=""



#########################################################################
# COMPRESSION DEFAULTS
#########################################################################
#0
COMPRESSGZ=(gzip -c -f -n)
COMPRESSBZ2=(bzip2 -c -f)
COMPRESSXZ=(xz -c -z --threads=0 -)
COMPRESSZST=(zstd -c -T0 --ultra -20 -)
COMPRESSLRZ=(lrzip -q)
COMPRESSLZO=(lzop -q)
COMPRESSZ=(compress -c -f)
COMPRESSLZ4=(lz4 -q)
COMPRESSLZ=(lzip -c -f)

#########################################################################
# EXTENSION DEFAULTS
#########################################################################
#
PKGEXT='.pkg.tar.zst'
SRCEXT='.src.tar.gz'

#########################################################################
# OTHER
#########################################################################
#
#-- Command used to run pacman as root, instead of trying sudo and su
PACMAN_AUTH=(run0)
{bridge}"#,
            profile = self.name(),
            arch_lines = arch_lines,
            cflags = self.cflags(),
            goamd64_line = goamd64_line,
            bridge = bridge,
        )
    }

    pub fn render_rust_conf(&self) -> String {
        format!(
            r#"#!/hint/bash
# shellcheck disable=2034

#
# Generated by cbpkg for profile: {profile}
# Source: CachyOS docker-makepkg (upstream build policy)
#

#########################################################################
# RUST LANGUAGE SUPPORT
#########################################################################

# Flags used for the Rust compiler, similar in spirit to CFLAGS. Read
# linkman:rustc[1] for more details on the available flags.
RUSTFLAGS="{rustflags}"

# Additional compiler flags appended to `RUSTFLAGS` for use in debugging.
# Usually this would include: ``-C debuginfo=2''. Read linkman:rustc[1] for
# more details on the available flags.
DEBUG_RUSTFLAGS="{debug_rustflags}"
"#,
            profile = self.name(),
            rustflags = self.rustflags(),
            debug_rustflags = self.debug_rustflags(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::mock::{MockCpuIdProvider, mock_v3_provider};

    #[test]
    fn test_profile_generic() {
        let dummy = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::Generic, &dummy);
        assert_eq!(target.name(), "generic");
        assert_eq!(target.codeberg_group(), "x86-64");
        assert_eq!(target.package_carch(), "x86_64");
        assert_eq!(target.march(), "x86-64");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64");
        assert_eq!(target.goamd64_str(), None);
        assert!(!target.is_optimized());
        assert!(!target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64"));

        assert_eq!(target.cxxflags(), "$CFLAGS -Wp,-D_GLIBCXX_ASSERTIONS");
        assert_eq!(target.ltoflags(), "-flto=auto");
        assert!(target.ldflags().contains("pack-relative-relocs"));

        let parts = TargetProfile::from_parts(BuildProfile::Generic, None);
        assert_eq!(parts, target);

        let makepkg_conf = target.render_makepkg_conf();
        assert!(makepkg_conf.contains("CARCH=\"x86_64\""));
        assert!(!makepkg_conf.contains("PACKAGECARCH"));
        assert!(!makepkg_conf.contains("GOAMD64"));
        assert!(makepkg_conf.contains("LTOFLAGS=\"-flto=auto\""));
        assert!(makepkg_conf.contains(
            "OPTIONS=(strip docs !libtool !staticlibs emptydirs zipman purge !debug lto !autodeps)"
        ));
        assert!(makepkg_conf.contains("PACMAN_AUTH=(run0)"));
        assert!(!makepkg_conf.contains("PKGDEST=/home/notroot/packages"));

        let rust_conf = target.render_rust_conf();
        assert!(rust_conf.contains("target-cpu=x86-64"));
        assert!(rust_conf.contains("DEBUG_RUSTFLAGS=\"-C debuginfo=2\""));
    }

    #[test]
    fn test_profile_v3() {
        let dummy = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::V3, &dummy);
        assert_eq!(target.name(), "v3");
        assert_eq!(target.codeberg_group(), "x86-64-v3");
        assert_eq!(target.package_carch(), "x86_64_v3");
        assert_eq!(target.march(), "x86-64-v3");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64-v3");
        assert_eq!(target.goamd64_str(), Some("v3"));
        assert!(target.is_optimized());
        assert!(target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64-v3"));

        let makepkg_conf = target.render_makepkg_conf();
        assert!(makepkg_conf.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_conf.contains("PACKAGECARCH=\"x86_64_v3\""));
        assert!(makepkg_conf.contains("GOAMD64=v3"));
        assert!(makepkg_conf.contains("-march=x86-64-v3 -mtune=generic"));
        assert!(makepkg_conf.contains("PACKAGELIST bridge"));

        let rust_conf = target.render_rust_conf();
        assert!(rust_conf.contains("target-cpu=x86-64-v3"));
    }

    #[test]
    fn test_profile_v4() {
        let dummy = MockCpuIdProvider::default();
        let target = TargetProfile::new(BuildProfile::V4, &dummy);
        assert_eq!(target.name(), "v4");
        assert_eq!(target.codeberg_group(), "x86-64-v4");
        assert_eq!(target.package_carch(), "x86_64_v4");
        assert_eq!(target.march(), "x86-64-v4");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64-v4");
        assert_eq!(target.goamd64_str(), Some("v4"));
        assert!(target.is_optimized());
        assert!(target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64-v4"));

        let makepkg_conf = target.render_makepkg_conf();
        assert!(makepkg_conf.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_conf.contains("PACKAGECARCH=\"x86_64_v4\""));
        assert!(makepkg_conf.contains("GOAMD64=v4"));
        assert!(makepkg_conf.contains("-march=x86-64-v4 -mtune=generic"));

        let rust_conf = target.render_rust_conf();
        assert!(rust_conf.contains("target-cpu=x86-64-v4"));
    }

    #[test]
    fn test_profile_native() {
        let dummy = mock_v3_provider();
        let target = TargetProfile::new(BuildProfile::Native, &dummy);
        assert_eq!(target.name(), "native");
        assert_eq!(target.codeberg_group(), "native");
        assert_eq!(target.package_carch(), "x86_64_native");
        assert_eq!(target.march(), "native");
        assert_eq!(target.mtune(), "native");
        assert_eq!(target.rust_target_cpu(), "native");
        assert_eq!(target.goamd64_str(), Some("v3"));
        assert!(target.is_optimized());
        assert!(!target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=native"));

        let makepkg_conf = target.render_makepkg_conf();
        assert!(makepkg_conf.contains("PACMAN_AUTH=(run0)"));
        assert!(makepkg_conf.contains("PACKAGECARCH=\"x86_64_native\""));
        assert!(makepkg_conf.contains("-march=native -mtune=native"));
        assert!(makepkg_conf.contains("GOAMD64=v3"));

        let rust_conf = target.render_rust_conf();
        assert!(rust_conf.contains("target-cpu=native"));
    }
}
