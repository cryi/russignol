use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SYSFS_POLICY: &str = "/sys/devices/system/cpu/cpufreq/policy0";

struct CpuBoostInner {
    setspeed_path: PathBuf,
    min_freq: String,
    max_freq: String,
}

/// CPU frequency controller for the userspace governor.
///
/// Brackets CPU-intensive work (BLS signing, scrypt) with `boost()` and
/// `restore()` calls. Designed for the `RPi` Zero 2W where signing takes
/// ~5ms per operation.
///
/// When idle (99.9% of the time), the CPU runs at minimum frequency (~600 MHz).
/// Callers set max frequency (~1000 MHz) before work and restore min after.
#[derive(Clone)]
pub struct CpuBoost(Arc<CpuBoostInner>);

impl CpuBoost {
    /// Initialize CPU frequency control.
    ///
    /// The init scripts chown `scaling_setspeed` to russignol before starting
    /// the signer, so the file is already writable.
    pub fn new() -> io::Result<Self> {
        Self::init(Path::new(SYSFS_POLICY))
    }

    fn init(policy_path: &Path) -> io::Result<Self> {
        let min_freq = fs::read_to_string(policy_path.join("cpuinfo_min_freq"))?
            .trim()
            .to_string();
        let max_freq = fs::read_to_string(policy_path.join("cpuinfo_max_freq"))?
            .trim()
            .to_string();
        let setspeed_path = policy_path.join("scaling_setspeed");

        log::info!("CPU freq control: min={min_freq} max={max_freq} kHz");

        // Start at minimum frequency
        fs::write(&setspeed_path, &min_freq)?;

        Ok(Self(Arc::new(CpuBoostInner {
            setspeed_path,
            min_freq,
            max_freq,
        })))
    }

    /// Set CPU to maximum frequency before CPU-intensive work.
    pub fn boost(&self) {
        if let Err(e) = fs::write(&self.0.setspeed_path, &self.0.max_freq) {
            log::warn!("Failed to set CPU max freq: {e}");
        }
    }

    /// Return CPU to minimum frequency after work completes.
    pub fn restore(&self) {
        if let Err(e) = fs::write(&self.0.setspeed_path, &self.0.min_freq) {
            log::warn!("Failed to set CPU min freq: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_sysfs(dir: &Path) {
        fs::write(dir.join("cpuinfo_min_freq"), "600000\n").unwrap();
        fs::write(dir.join("cpuinfo_max_freq"), "1000000\n").unwrap();
        fs::write(dir.join("scaling_setspeed"), "").unwrap();
    }

    #[test]
    fn initial_freq_is_min() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let _boost = CpuBoost::init(dir.path()).unwrap();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }

    #[test]
    fn boost_sets_max_freq() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.boost();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");
    }

    #[test]
    fn restore_sets_min_freq() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.boost();
        cpu.restore();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }
}
