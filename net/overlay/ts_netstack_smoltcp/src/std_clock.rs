use std::sync::LazyLock;

use netcore::smoltcp;

/// Global lazily-initialized instance of [`StdClock`].
pub static CLOCK: LazyLock<StdClock> = LazyLock::new(Default::default);

/// Utility type that supports producing [`smoltcp::time::Instant`] relative to an initial
/// [`std::time::Instant`].
pub struct StdClock {
    start: std::time::Instant,
}

impl StdClock {
    /// Construct a new clock that uses [`std::time::Instant::now`] as its base
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Get the [`smoltcp::time::Instant`] corresponding to now in this clock.
    pub fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.start.elapsed().as_micros() as i64)
    }
}

impl Default for StdClock {
    fn default() -> Self {
        Self::new()
    }
}
