use core::fmt::{Debug, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout,
    byteorder::big_endian::{U32, U64},
};

/// An instant in time in the TAI64 format.
#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct TAI64N {
    secs: U64,
    nanos: U32,
}

// The TAI64 seconds value that is supposed to represent the Unix
// epoch. The 0xa offset is incorrect and assumes that system
// clock timestamps are referenced to TAI rather than UTC, which
// is true for approximately no system clocks in the world.
//
// However, this error in implementing TAI64 is very widespread due
// to the reference implementation's unfortunate choices. In particular,
// other WireGuard implementations use this incorrect computation,
// and therefore so does this code.
//
// See https://blog.dave.tf/post/tai64-is-not-tai/ for more details
// if you care.
const TAI_BASE: u64 = 0x400000000000000a;

// We mask off the least significant bits of nanoseconds. TAI64N
// timestamps end up on the network, and we don't want to leak
// timestamps exact enough to be useful in timing attacks.
//
// This mask truncates the nanoseconds value to multiples of
// 16_777_215ns, or ~16.8ms.
const WHITEN_MASK: u32 = !0xFFFFFF;

// The smallest nanoseconds increment that results in a different
// TAI64N value after whitening.
const WHITEN_INCREMENT: u32 = !WHITEN_MASK + 1;

/// A TAI64N timestamp suitable for use in WireGuard handshakes.
///
/// This is not a general purpose TAI64N implementation. In particular,
/// the timestamps it generates are inaccurate by virtue of being
/// bug-for-bug compatible with other wireguard implementations
/// (see https://blog.dave.tf/post/tai64-is-not-tai/ for details); and
/// the generated timestamps have deliberately truncated accuracy so
/// that they cannot be used as a reliable reference for timing attacks.
///
/// This type also deliberately does not implement all general-purpose
/// operations, only those needed for wireguard's use of timestamps for
/// replay protection.
impl TAI64N {
    #[inline]
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    /// Return self if it's a later timestamp than min, or a
    /// timestamp very shortly after min otherwise.
    pub fn clamp_after(self, min: TAI64N) -> Self {
        if self > min {
            self
        } else {
            let (nanos, carry) = u32::from(min.nanos).overflowing_add(WHITEN_INCREMENT);
            let secs = if carry { min.secs + 1 } else { min.secs };
            TAI64N {
                secs,
                nanos: U32::from(nanos & WHITEN_MASK),
            }
        }
    }
}

impl Debug for TAI64N {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "TAI64N({}.{})", self.secs, self.nanos)
    }
}

impl Display for TAI64N {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}.{}", self.secs, self.nanos)
    }
}

// Note: there is deliberately no From<TAI64N> for SystemTime.
//
// This is because WireGuard uses TAI64N timestamps as a monotonic counter to
// prevent replay attacks, and we explicitly do _not_ want to assume that
// incoming TAI64N timestamps relate to local system time in any sensible way
// (e.g. the peer clock might be way off, but as long as it ticks monotonically,
// that's fine).
//
// To avoid us accidentally treating these timestamps as useful time references,
// we allow generation of timestamps from local system time, but not the reverse
// translation.

impl From<SystemTime> for TAI64N {
    fn from(v: SystemTime) -> Self {
        if v < UNIX_EPOCH {
            let now = UNIX_EPOCH.duration_since(v).unwrap();
            let (secs, nanos) = if now.subsec_nanos() == 0 {
                (now.as_secs(), 0)
            } else {
                (now.as_secs() + 1, 1_000_000_000 - now.subsec_nanos())
            };
            TAI64N {
                secs: U64::from(TAI_BASE - secs),
                nanos: U32::from(nanos & WHITEN_MASK),
            }
        } else {
            let now = v.duration_since(UNIX_EPOCH).unwrap();
            TAI64N {
                secs: U64::from(TAI_BASE + now.as_secs()),
                nanos: U32::from(now.subsec_nanos() & WHITEN_MASK),
            }
        }
    }
}

/// A clock that produces monotonic TAI64N timestamps.
///
/// Successive timestamps are guaranteed to advance relative to past timestamps.
/// When SystemTime is well-behaved, the clock produces timestamps that match the
/// system time. If matching SystemTime would violate monotonicity, TAI64NClock
/// instead produces a timestamp a few milliseconds in the future of the last
/// issued timestamp.
#[derive(Debug)]
pub struct TAI64NClock {
    last: TAI64N,
}

impl TAI64NClock {
    pub fn new() -> Self {
        Self {
            last: TAI64N::new_zeroed(),
        }
    }

    pub fn now(&mut self) -> TAI64N {
        self.last = TAI64N::now().clamp_after(self.last);
        self.last
    }

    #[cfg(test)]
    fn now_from_systemtime(&mut self, t: SystemTime) -> TAI64N {
        self.last = TAI64N::from(t).clamp_after(self.last);
        self.last
    }
}

impl Default for TAI64NClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use core::time::Duration;

    use super::*;

    #[test]
    fn tai64n() {
        let tai = TAI64N::from(UNIX_EPOCH);
        assert_eq!(tai.secs, TAI_BASE);
        assert_eq!(tai.nanos, 0);

        let delta = Duration::from_secs(2) + Duration::from_millis(200) + Duration::from_nanos(400);

        let stamp = UNIX_EPOCH + delta;
        let tai2 = TAI64N::from(stamp);
        assert_eq!(tai2.secs, TAI_BASE + 2);
        // 200_000_400, after whitening.
        assert_eq!(tai2.nanos, 184_549_376);
        assert!(tai < tai2);

        let stamp = UNIX_EPOCH - delta;
        let tai3 = TAI64N::from(stamp);
        assert_eq!(tai3.secs, TAI_BASE - 3);
        // 1_000_000_000 - 200_000_400, after whitening.
        assert_eq!(tai3.nanos, 788_529_152);
        assert!(tai3 < tai);
        assert!(tai3 < tai2);
    }

    #[test]
    fn tai64n_clamp() {
        let now = TAI64N::now();
        let later = now.clamp_after(now);
        assert!(later > now);

        let epoch = TAI64N::from(UNIX_EPOCH);
        let later = epoch.clamp_after(epoch);
        assert_eq!(epoch.secs, later.secs);
        assert_eq!(epoch.nanos, 0);
        assert_eq!(later.nanos, WHITEN_INCREMENT);

        assert_eq!(now.clamp_after(epoch), now);
    }

    #[test]
    fn tai64n_clock() {
        let mut clock = TAI64NClock::new();
        let t1 = clock.now();
        let t2 = clock.now();
        assert!(t1 < t2);
    }

    #[test]
    fn tai64n_clock_rollback() {
        let mut clock = TAI64NClock::new();
        // Simulate a backwards time jump in the system clock, followed
        // by a forward jump. By timestamp value, the timeline goes:
        // st2 < st3 < st1 < st4
        let st1 = SystemTime::now();
        let st2 = st1 - Duration::from_secs(3600);
        let st3 = st2 + Duration::from_secs(10);
        let st4 = st1 + Duration::from_secs(1);

        let t1 = clock.now_from_systemtime(st1);
        let t2 = clock.now_from_systemtime(st2);
        let t3 = clock.now_from_systemtime(st3);
        let t4 = clock.now_from_systemtime(st4);
        // TAI timestamps are in issuance order despite the wall clock chaos.
        assert!(t1 < t2);
        assert!(t2 < t3);
        assert!(t3 < t4);
    }
}
