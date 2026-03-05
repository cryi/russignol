use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long to hold max frequency after the last boost request.
/// Covers a burst of 3 signatures (~18ms) plus scheduling overhead.
const BOOST_HOLD: Duration = Duration::from_millis(50);

const SYSFS_POLICY: &str = "/sys/devices/system/cpu/cpufreq/policy0";

struct CpuBoostInner {
    setspeed_path: PathBuf,
    min_freq: String,
    max_freq: String,
    /// Millis since `epoch` when boost should expire. 0 = not boosted.
    deadline_millis: AtomicU64,
    epoch: Instant,
}

/// CPU frequency controller for the userspace governor.
///
/// Boosts CPU to max frequency when signing requests arrive and returns to
/// min frequency after the burst completes. Designed for the `RPi` Zero 2W
/// where ~3 signing requests arrive in quick succession every ~6 seconds.
///
/// When idle (99.9% of the time), the CPU runs at minimum frequency (~600 MHz).
/// On each signing request, `boost()` sets max frequency (~1000 MHz) and
/// resets a 50ms deadline. A background watcher thread restores min frequency
/// once the deadline expires without further boosts.
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
            deadline_millis: AtomicU64::new(0),
            epoch: Instant::now(),
        })))
    }

    /// Boost CPU to maximum frequency and extend the hold deadline.
    ///
    /// Called at the start of each signing request. Multiple rapid calls
    /// extend the deadline rather than stacking.
    pub fn boost(&self) {
        let deadline =
            u64::try_from((self.0.epoch.elapsed() + BOOST_HOLD).as_millis()).unwrap_or(u64::MAX);
        self.0.deadline_millis.store(deadline, Ordering::Release);
        if let Err(e) = fs::write(&self.0.setspeed_path, &self.0.max_freq) {
            log::warn!("Failed to set CPU max freq: {e}");
        }
    }

    /// Spawn a background thread that returns CPU to min frequency after boost expires.
    pub fn spawn_watcher(&self) {
        let inner = self.0.clone();
        std::thread::Builder::new()
            .name("cpu-freq".into())
            .spawn(move || {
                loop {
                    let deadline = inner.deadline_millis.load(Ordering::Acquire);
                    if deadline == 0 {
                        std::thread::sleep(BOOST_HOLD);
                        continue;
                    }
                    let now_millis =
                        u64::try_from(inner.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
                    if now_millis < deadline {
                        std::thread::sleep(Duration::from_millis(deadline - now_millis));
                        continue;
                    }
                    // Deadline expired — CAS to prevent race with concurrent boost()
                    if inner
                        .deadline_millis
                        .compare_exchange(deadline, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        if let Err(e) = fs::write(&inner.setspeed_path, &inner.min_freq) {
                            log::warn!("Failed to set CPU min freq: {e}");
                        } else {
                            log::debug!("CPU freq returned to minimum");
                        }
                    }
                }
            })
            .expect("failed to spawn cpu-freq thread");
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

        let boost = CpuBoost::init(dir.path()).unwrap();
        boost.boost();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");
    }

    #[test]
    fn watcher_restores_min_freq() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let boost = CpuBoost::init(dir.path()).unwrap();
        boost.spawn_watcher();
        boost.boost();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");

        // Wait for BOOST_HOLD + watcher poll interval + margin
        std::thread::sleep(Duration::from_millis(150));

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }

    #[test]
    fn burst_extends_deadline() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let boost = CpuBoost::init(dir.path()).unwrap();
        boost.spawn_watcher();

        // Simulate burst: 3 boosts over 20ms
        boost.boost();
        std::thread::sleep(Duration::from_millis(10));
        boost.boost();
        std::thread::sleep(Duration::from_millis(10));
        boost.boost();

        // 30ms after first boost, 10ms after last: still at max
        std::thread::sleep(Duration::from_millis(10));
        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");

        // Wait for BOOST_HOLD after last boost + margin
        std::thread::sleep(Duration::from_millis(150));
        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }
}
