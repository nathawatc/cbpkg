use crate::error::AppError;
use std::collections::HashSet;
use std::fmt;
use std::fs;

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

#[derive(Debug, Clone, Default)]
pub struct CpuFeatures {
    flags: HashSet<String>,
}

impl CpuFeatures {
    #[cfg(test)]
    pub fn new(flags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let set = flags
            .into_iter()
            .map(|f| f.into().trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self { flags: set }
    }

    pub fn from_host() -> Result<Self, AppError> {
        let content =
            fs::read_to_string("/proc/cpuinfo").map_err(|e| AppError::ProcessExecution {
                cmd: "read /proc/cpuinfo".to_string(),
                source: e,
            })?;
        Ok(Self::from_proc_cpuinfo(&content))
    }

    pub fn from_proc_cpuinfo(content: &str) -> Self {
        let mut flags = HashSet::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // Typical line: flags\t\t: fpu vme de ...
            if (trimmed.starts_with("flags") || trimmed.starts_with("Features"))
                && let Some((_, rest)) = trimmed.split_once(':')
            {
                for flag in rest.split_whitespace() {
                    flags.insert(flag.trim().to_ascii_lowercase());
                }
            }
        }
        Self { flags }
    }

    pub fn has(&self, flag: &str) -> bool {
        self.flags.contains(&flag.to_ascii_lowercase())
    }

    fn satisfies_v2(&self) -> bool {
        let has_sse3 = self.has("pni") || self.has("sse3");
        let has_sse4_1 = self.has("sse4_1") || self.has("sse4.1");
        let has_sse4_2 = self.has("sse4_2") || self.has("sse4.2");

        self.has("cx16")
            && self.has("lahf_lm")
            && self.has("popcnt")
            && has_sse3
            && self.has("ssse3")
            && has_sse4_1
            && has_sse4_2
    }

    fn satisfies_v3(&self) -> bool {
        if !self.satisfies_v2() {
            return false;
        }

        let has_lzcnt = self.has("lzcnt") || self.has("abm");
        let has_xsave = self.has("osxsave") || self.has("xsave");

        self.has("avx")
            && self.has("avx2")
            && self.has("bmi1")
            && self.has("bmi2")
            && self.has("f16c")
            && self.has("fma")
            && has_lzcnt
            && self.has("movbe")
            && has_xsave
    }

    fn satisfies_v4(&self) -> bool {
        if !self.satisfies_v3() {
            return false;
        }

        self.has("avx512f")
            && self.has("avx512bw")
            && self.has("avx512cd")
            && self.has("avx512dq")
            && self.has("avx512vl")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_features() -> Vec<&'static str> {
        vec![
            "cx16", "lahf_lm", "popcnt", "pni", "ssse3", "sse4_1", "sse4_2",
        ]
    }

    fn v3_features() -> Vec<&'static str> {
        let mut f = v2_features();
        f.extend([
            "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave",
        ]);
        f
    }

    fn v4_features() -> Vec<&'static str> {
        let mut f = v3_features();
        f.extend(["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"]);
        f
    }

    #[test]
    fn test_v1_baseline() {
        let feats = CpuFeatures::new(vec!["fpu", "vme", "mmx", "sse", "sse2"]);
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V1);
    }

    #[test]
    fn test_v2_detection() {
        let feats = CpuFeatures::new(v2_features());
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V2);
    }

    #[test]
    fn test_v2_missing_one_feature() {
        let mut flags = v2_features();
        flags.retain(|&f| f != "popcnt");
        let feats = CpuFeatures::new(flags);
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V1);
    }

    #[test]
    fn test_v3_detection() {
        let feats = CpuFeatures::new(v3_features());
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V3);
    }

    #[test]
    fn test_v3_with_lzcnt_instead_of_abm() {
        let mut flags = v3_features();
        flags.retain(|&f| f != "abm");
        flags.push("lzcnt");
        let feats = CpuFeatures::new(flags);
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V3);
    }

    #[test]
    fn test_v3_missing_fma() {
        let mut flags = v3_features();
        flags.retain(|&f| f != "fma");
        let feats = CpuFeatures::new(flags);
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V2);
    }

    #[test]
    fn test_v4_detection() {
        let feats = CpuFeatures::new(v4_features());
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V4);
    }

    #[test]
    fn test_v4_missing_avx512vl() {
        let mut flags = v4_features();
        flags.retain(|&f| f != "avx512vl");
        let feats = CpuFeatures::new(flags);
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V3);
    }

    #[test]
    fn test_parse_proc_cpuinfo() {
        let sample = r#"
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
model name	: AMD Ryzen
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local user_shstk clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm debug_swap
bugs		: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass srso
"#;
        let feats = CpuFeatures::from_proc_cpuinfo(sample);
        assert!(feats.has("avx2"));
        assert!(feats.has("bmi2"));
        assert!(!feats.has("avx512f"));
        assert_eq!(feats.detect_goamd64(), Goamd64Level::V3);
    }
}
