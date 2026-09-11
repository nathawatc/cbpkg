use crate::error::AppError;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Goamd64Level {
    V1,
    V2,
    V3,
    V4,
}

impl Goamd64Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V4 => "v4",
        }
    }
}

impl fmt::Display for Goamd64Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub trait CpuIdProvider {
    fn cpuid(&self, leaf: u32, sub_leaf: u32) -> (u32, u32, u32, u32);
    fn xgetbv(&self, xcr: u32) -> u64;
}

#[derive(Default, Debug, Clone, Copy)]
pub struct HostCpuIdProvider;

impl HostCpuIdProvider {
    pub fn new() -> Self {
        Self
    }
}

impl CpuIdProvider for HostCpuIdProvider {
    fn cpuid(&self, leaf: u32, sub_leaf: u32) -> (u32, u32, u32, u32) {
        #[cfg(target_arch = "x86_64")]
        {
            let res = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
            (res.eax, res.ebx, res.ecx, res.edx)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (leaf, sub_leaf);
            (0, 0, 0, 0)
        }
    }

    fn xgetbv(&self, xcr: u32) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { core::arch::x86_64::_xgetbv(xcr) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = xcr;
            0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsAbiFeatures {
    // v2
    pub cx16: bool,
    pub lahf_lm: bool,
    pub popcnt: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,

    // v3
    pub avx: bool,
    pub avx2: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub f16c: bool,
    pub fma: bool,
    pub lzcnt: bool,
    pub movbe: bool,
    pub osxsave: bool,
    pub xcr0_ymm: bool,

    // v4
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512cd: bool,
    pub avx512dq: bool,
    pub avx512vl: bool,
    pub xcr0_zmm: bool,

    // CachyOS extra
    pub pclmulqdq: bool,
}

impl PsAbiFeatures {
    pub fn from_provider(provider: &impl CpuIdProvider) -> Self {
        let (_, _, ecx1, _) = provider.cpuid(1, 0);
        let (_, ebx7, _, _) = provider.cpuid(7, 0);
        let (_, _, ecx_ext, _) = provider.cpuid(0x80000001, 0);

        let osxsave = (ecx1 & (1 << 27)) != 0;
        let xcr0 = if osxsave { provider.xgetbv(0) } else { 0 };

        let xcr0_ymm = osxsave && (xcr0 & 0x6) == 0x6;
        let xcr0_zmm = osxsave && (xcr0 & 0xE6) == 0xE6;

        Self {
            cx16: (ecx1 & (1 << 13)) != 0,
            lahf_lm: (ecx_ext & (1 << 0)) != 0,
            popcnt: (ecx1 & (1 << 23)) != 0,
            sse3: (ecx1 & (1 << 0)) != 0,
            ssse3: (ecx1 & (1 << 9)) != 0,
            sse4_1: (ecx1 & (1 << 19)) != 0,
            sse4_2: (ecx1 & (1 << 20)) != 0,

            avx: (ecx1 & (1 << 28)) != 0,
            avx2: (ebx7 & (1 << 5)) != 0,
            bmi1: (ebx7 & (1 << 3)) != 0,
            bmi2: (ebx7 & (1 << 8)) != 0,
            f16c: (ecx1 & (1 << 29)) != 0,
            fma: (ecx1 & (1 << 12)) != 0,
            lzcnt: (ecx_ext & (1 << 5)) != 0,
            movbe: (ecx1 & (1 << 22)) != 0,
            osxsave,
            xcr0_ymm,

            avx512f: (ebx7 & (1 << 16)) != 0,
            avx512bw: (ebx7 & (1 << 30)) != 0,
            avx512cd: (ebx7 & (1 << 28)) != 0,
            avx512dq: (ebx7 & (1 << 17)) != 0,
            avx512vl: (ebx7 & (1 << 31)) != 0,
            xcr0_zmm,

            pclmulqdq: (ecx1 & (1 << 1)) != 0,
        }
    }

    pub fn first_missing_v2(&self) -> Option<&'static str> {
        if !self.cx16 {
            Some("CMPXCHG16B (cx16)")
        } else if !self.lahf_lm {
            Some("LAHF/SAHF (lahf_lm)")
        } else if !self.popcnt {
            Some("POPCNT (popcnt)")
        } else if !self.sse3 {
            Some("SSE3 (sse3)")
        } else if !self.ssse3 {
            Some("SSSE3 (ssse3)")
        } else if !self.sse4_1 {
            Some("SSE4.1 (sse4_1)")
        } else if !self.sse4_2 {
            Some("SSE4.2 (sse4_2)")
        } else {
            None
        }
    }

    pub fn satisfies_v2(&self) -> bool {
        self.first_missing_v2().is_none()
    }

    pub fn first_missing_v3(&self) -> Option<&'static str> {
        if let Some(missing) = self.first_missing_v2() {
            return Some(missing);
        }

        if !self.avx {
            Some("AVX")
        } else if !self.avx2 {
            Some("AVX2")
        } else if !self.bmi1 {
            Some("BMI1")
        } else if !self.bmi2 {
            Some("BMI2")
        } else if !self.f16c {
            Some("F16C")
        } else if !self.fma {
            Some("FMA")
        } else if !self.lzcnt {
            Some("LZCNT (lzcnt/abm)")
        } else if !self.movbe {
            Some("MOVBE")
        } else if !self.osxsave {
            Some("OSXSAVE (OS-enabled extended state)")
        } else if !self.xcr0_ymm {
            Some("XCR0 YMM state (OS AVX support)")
        } else {
            None
        }
    }

    pub fn satisfies_v3(&self) -> bool {
        self.first_missing_v3().is_none()
    }

    pub fn first_missing_v4(&self) -> Option<&'static str> {
        if let Some(missing) = self.first_missing_v3() {
            return Some(missing);
        }

        if !self.avx512f {
            Some("AVX512F")
        } else if !self.avx512bw {
            Some("AVX512BW")
        } else if !self.avx512cd {
            Some("AVX512CD")
        } else if !self.avx512dq {
            Some("AVX512DQ")
        } else if !self.avx512vl {
            Some("AVX512VL")
        } else if !self.xcr0_zmm {
            Some("XCR0 ZMM state (OS AVX-512 support)")
        } else {
            None
        }
    }

    pub fn satisfies_v4(&self) -> bool {
        self.first_missing_v4().is_none()
    }

    pub fn detect_goamd64(&self) -> Goamd64Level {
        if self.satisfies_v4() {
            Goamd64Level::V4
        } else if self.satisfies_v3() {
            Goamd64Level::V3
        } else if self.satisfies_v2() {
            Goamd64Level::V2
        } else {
            Goamd64Level::V1
        }
    }
}

pub fn detect_native_goamd64(provider: &impl CpuIdProvider) -> Goamd64Level {
    let features = PsAbiFeatures::from_provider(provider);
    features.detect_goamd64()
}

pub fn validate_host_for_profile_with_features(
    features: &PsAbiFeatures,
    profile_name: &str,
) -> Result<(), AppError> {
    match profile_name {
        "v3" => {
            if let Some(missing) = features.first_missing_v3() {
                return Err(AppError::HostArchitectureUnsupported {
                    profile: "v3".to_string(),
                    reason: format!("missing psABI feature: {missing}"),
                });
            }
            if !features.pclmulqdq {
                return Err(AppError::HostArchitectureUnsupported {
                    profile: "v3".to_string(),
                    reason: "Selected CachyOS v3 policy requires PCLMUL on the build host."
                        .to_string(),
                });
            }
        }
        "v4" => {
            if let Some(missing) = features.first_missing_v4() {
                return Err(AppError::HostArchitectureUnsupported {
                    profile: "v4".to_string(),
                    reason: format!("missing psABI feature: {missing}"),
                });
            }
            if !features.pclmulqdq {
                return Err(AppError::HostArchitectureUnsupported {
                    profile: "v4".to_string(),
                    reason: "Selected CachyOS v4 policy requires PCLMUL on the build host."
                        .to_string(),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_host_for_profile(
    provider: &impl CpuIdProvider,
    profile_name: &str,
) -> Result<(), AppError> {
    let features = PsAbiFeatures::from_provider(provider);
    validate_host_for_profile_with_features(&features, profile_name)
}

pub mod mock {
    use super::*;

    #[derive(Default)]
    pub struct MockCpuIdProvider {
        pub ecx1: u32,
        pub ebx7: u32,
        pub ecx_ext: u32,
        pub xcr0: u64,
    }

    impl CpuIdProvider for MockCpuIdProvider {
        fn cpuid(&self, leaf: u32, _sub_leaf: u32) -> (u32, u32, u32, u32) {
            match leaf {
                1 => (0, 0, self.ecx1, 0),
                7 => (0, self.ebx7, 0, 0),
                0x80000001 => (0, 0, self.ecx_ext, 0),
                _ => (0, 0, 0, 0),
            }
        }

        fn xgetbv(&self, _xcr: u32) -> u64 {
            self.xcr0
        }
    }

    pub fn mock_v2_provider() -> MockCpuIdProvider {
        // sse3(0), ssse3(9), cx16(13), sse4_1(19), sse4_2(20), popcnt(23)
        // lahf_lm(0)
        MockCpuIdProvider {
            ecx1: (1 << 0) | (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 23),
            ecx_ext: 1 << 0,
            ..Default::default()
        }
    }

    pub fn mock_v3_provider() -> MockCpuIdProvider {
        let mut p = mock_v2_provider();
        // pclmulqdq(1), fma(12), movbe(22), osxsave(27), avx(28), f16c(29)
        p.ecx1 |= (1 << 1) | (1 << 12) | (1 << 22) | (1 << 27) | (1 << 28) | (1 << 29);
        // bmi1(3), avx2(5), bmi2(8)
        p.ebx7 |= (1 << 3) | (1 << 5) | (1 << 8);
        // lzcnt(5)
        p.ecx_ext |= 1 << 5;
        // XCR0 YMM: bits 1, 2 = 0x6
        p.xcr0 = 0x6;
        p
    }

    pub fn mock_v4_provider() -> MockCpuIdProvider {
        let mut p = mock_v3_provider();
        // avx512f(16), avx512dq(17), avx512cd(28), avx512bw(30), avx512vl(31)
        p.ebx7 |= (1 << 16) | (1 << 17) | (1 << 28) | (1 << 30) | (1 << 31);
        // XCR0 ZMM: bits 1, 2, 5, 6, 7 = 0xE6
        p.xcr0 = 0xE6;
        p
    }
}

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;

    #[test]
    fn test_v1_detection() {
        let p = MockCpuIdProvider::default();
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V1);
    }

    #[test]
    fn test_v2_detection() {
        let p = mock_v2_provider();
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V2);
    }

    #[test]
    fn test_v2_missing_popcnt() {
        let mut p = mock_v2_provider();
        p.ecx1 &= !(1 << 23); // clear popcnt
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V1);
    }

    #[test]
    fn test_v3_detection() {
        let p = mock_v3_provider();
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V3);
    }

    #[test]
    fn test_v3_missing_fma() {
        let mut p = mock_v3_provider();
        p.ecx1 &= !(1 << 12); // clear FMA
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V2);
    }

    #[test]
    fn test_v3_missing_osxsave() {
        let mut p = mock_v3_provider();
        p.ecx1 &= !(1 << 27); // clear OSXSAVE
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V2);
    }

    #[test]
    fn test_v3_missing_xcr0_ymm() {
        let mut p = mock_v3_provider();
        p.xcr0 = 0x2; // only XMM, missing YMM (bit 2)
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V2);
    }

    #[test]
    fn test_v4_detection() {
        let p = mock_v4_provider();
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V4);
    }

    #[test]
    fn test_v4_missing_avx512vl() {
        let mut p = mock_v4_provider();
        p.ebx7 &= !(1 << 31); // clear AVX512VL
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V3);
    }

    #[test]
    fn test_v4_missing_xcr0_zmm() {
        let mut p = mock_v4_provider();
        p.xcr0 = 0x6; // has YMM, missing ZMM state
        assert_eq!(detect_native_goamd64(&p), Goamd64Level::V3);
    }

    #[test]
    fn test_validate_host_v3_success() {
        let p = mock_v3_provider();
        assert!(validate_host_for_profile(&p, "v3").is_ok());
    }

    #[test]
    fn test_validate_host_v3_missing_pclmul() {
        let mut p = mock_v3_provider();
        p.ecx1 &= !(1 << 1); // clear pclmulqdq
        let res = validate_host_for_profile(&p, "v3");
        assert!(matches!(
            res,
            Err(AppError::HostArchitectureUnsupported { .. })
        ));
        if let Err(AppError::HostArchitectureUnsupported { reason, .. }) = res {
            assert!(reason.contains("PCLMUL"));
        }
    }

    #[test]
    fn test_validate_host_v4_missing_feature() {
        let p = mock_v3_provider(); // only satisfies v3
        let res = validate_host_for_profile(&p, "v4");
        assert!(matches!(
            res,
            Err(AppError::HostArchitectureUnsupported { .. })
        ));
        if let Err(AppError::HostArchitectureUnsupported { reason, .. }) = res {
            assert!(reason.contains("AVX512F"));
        }
    }
}
