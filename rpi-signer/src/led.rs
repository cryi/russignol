use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SYSFS_LED: &str = "/sys/class/leds/ACT";
const MIN_ON_DURATION: Duration = Duration::from_millis(200);

struct LedInner {
    brightness_path: PathBuf,
    on_at: Mutex<Option<Instant>>,
}

/// Activity LED controller.
///
/// Turns the LED on when a signer connection opens and off when it closes.
#[derive(Clone)]
pub struct Led(Arc<LedInner>);

impl Led {
    /// Initialize LED control, starting in the off state.
    ///
    /// The init scripts chown `brightness` to russignol before starting
    /// the signer, so the file is already writable.
    pub fn new() -> io::Result<Self> {
        Self::init(Path::new(SYSFS_LED))
    }

    fn init(path: &Path) -> io::Result<Self> {
        let brightness_path = path.join("brightness");
        fs::write(&brightness_path, "0")?;
        log::info!("LED control initialized");
        Ok(Self(Arc::new(LedInner {
            brightness_path,
            on_at: Mutex::new(None),
        })))
    }

    /// Turn the LED on.
    pub fn on(&self) {
        *self.0.on_at.lock().unwrap() = Some(Instant::now());
        if let Err(e) = fs::write(&self.0.brightness_path, "1") {
            log::warn!("Failed to turn LED on: {e}");
        }
    }

    /// Turn the LED off, ensuring it stays on for at least [`MIN_ON_DURATION`].
    pub fn off(&self) {
        if let Some(on_at) = self.0.on_at.lock().unwrap().take() {
            let remaining = MIN_ON_DURATION.saturating_sub(on_at.elapsed());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
        if let Err(e) = fs::write(&self.0.brightness_path, "0") {
            log::warn!("Failed to turn LED off: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_is_off() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("brightness"), "").unwrap();

        let _led = Led::init(dir.path()).unwrap();

        let val = fs::read_to_string(dir.path().join("brightness")).unwrap();
        assert_eq!(val, "0");
    }

    #[test]
    fn test_on_writes_one() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("brightness"), "").unwrap();

        let led = Led::init(dir.path()).unwrap();
        led.on();

        let val = fs::read_to_string(dir.path().join("brightness")).unwrap();
        assert_eq!(val, "1");
    }

    #[test]
    fn test_off_writes_zero() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("brightness"), "").unwrap();

        let led = Led::init(dir.path()).unwrap();
        led.on();
        led.off();

        let val = fs::read_to_string(dir.path().join("brightness")).unwrap();
        assert_eq!(val, "0");
    }

    #[test]
    fn test_off_holds_minimum_duration() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("brightness"), "").unwrap();

        let led = Led::init(dir.path()).unwrap();
        led.on();
        let start = Instant::now();
        led.off();
        assert!(start.elapsed() >= MIN_ON_DURATION);
    }
}
