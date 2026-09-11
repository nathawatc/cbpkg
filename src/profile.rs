use crate::cpu::{CpuFeatures, Goamd64Level};
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
    pub goamd64: Goamd64Level,
}

impl TargetProfile {
    pub fn new(profile: BuildProfile, host_features: &CpuFeatures) -> Self {
        let goamd64 = match profile {
            BuildProfile::Generic => Goamd64Level::V1,
            BuildProfile::V3 => Goamd64Level::V3,
            BuildProfile::V4 => Goamd64Level::V4,
            BuildProfile::Native => host_features.detect_goamd64(),
        };

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

    pub fn goamd64_str(&self) -> &'static str {
        self.goamd64.as_str()
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

    pub fn cxxflags(&self) -> String {
        "$CFLAGS -Wp,-D_GLIBCXX_ASSERTIONS".to_string()
    }

    pub fn rustflags(&self) -> String {
        format!(
            "-C opt-level=3 -C target-cpu={} -Clink-arg=-z -Clink-arg=pack-relative-relocs",
            self.rust_target_cpu()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_generic() {
        let dummy = CpuFeatures::default();
        let target = TargetProfile::new(BuildProfile::Generic, &dummy);
        assert_eq!(target.name(), "generic");
        assert_eq!(target.codeberg_group(), "x86-64");
        assert_eq!(target.package_carch(), "x86_64");
        assert_eq!(target.march(), "x86-64");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64");
        assert_eq!(target.goamd64_str(), "v1");
        assert!(!target.is_optimized());
        assert!(!target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64"));
    }

    #[test]
    fn test_profile_v3() {
        let dummy = CpuFeatures::default();
        let target = TargetProfile::new(BuildProfile::V3, &dummy);
        assert_eq!(target.name(), "v3");
        assert_eq!(target.codeberg_group(), "x86-64-v3");
        assert_eq!(target.package_carch(), "x86_64_v3");
        assert_eq!(target.march(), "x86-64-v3");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64-v3");
        assert_eq!(target.goamd64_str(), "v3");
        assert!(target.is_optimized());
        assert!(target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64-v3"));
    }

    #[test]
    fn test_profile_v4() {
        let dummy = CpuFeatures::default();
        let target = TargetProfile::new(BuildProfile::V4, &dummy);
        assert_eq!(target.name(), "v4");
        assert_eq!(target.codeberg_group(), "x86-64-v4");
        assert_eq!(target.package_carch(), "x86_64_v4");
        assert_eq!(target.march(), "x86-64-v4");
        assert_eq!(target.mtune(), "generic");
        assert_eq!(target.rust_target_cpu(), "x86-64-v4");
        assert_eq!(target.goamd64_str(), "v4");
        assert!(target.is_optimized());
        assert!(target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=x86-64-v4"));
    }

    #[test]
    fn test_profile_native() {
        let dummy = CpuFeatures::new(vec![
            "cx16", "lahf_lm", "popcnt", "pni", "ssse3", "sse4_1", "sse4_2", "avx", "avx2", "bmi1",
            "bmi2", "f16c", "fma", "abm", "movbe", "xsave",
        ]);
        let target = TargetProfile::new(BuildProfile::Native, &dummy);
        assert_eq!(target.name(), "native");
        assert_eq!(target.codeberg_group(), "native");
        assert_eq!(target.package_carch(), "x86_64_native");
        assert_eq!(target.march(), "native");
        assert_eq!(target.mtune(), "native");
        assert_eq!(target.rust_target_cpu(), "native");
        assert_eq!(target.goamd64_str(), "v3");
        assert!(target.is_optimized());
        assert!(!target.cflags().contains("-mpclmul"));
        assert!(target.rustflags().contains("target-cpu=native"));
    }
}
