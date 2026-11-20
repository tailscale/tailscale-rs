#![doc = include_str!("../README.md")]
#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};
use pastey::paste;

macro_rules! define_metrics {
    ($({ category: $categories:ident, counters: [ $($names:ident : $doc:literal),+ ]}),+) => {
        paste! {
            /// Holder for all of the per-Device counters. A single instance is shared by the entire
            /// Device. We may run in multicore environments, so we need to be concerned about false
            /// sharing with so many atomics packed together. This is addressed by organizing the
            /// metrics by category, and padding the struct for each category to cache line size.
            /// The intent is that only or at most a few threads will be updating counters
            /// in any given category.
            #[derive(Default)]
            pub struct Metrics {
                $(
                #[doc = concat!(stringify!($categories), " counters")]
                pub [<$categories>]: crossbeam_utils::CachePadded<[<$categories:camel Metrics>]>
                ),+
            }

            impl Metrics {
                /// Names for all of the counters. The format is "tsrs_<category>_<name>". This array
                /// is indexed by metric id, the same as `MetricsSnapshot`. If that ever fails to hold
                /// then we will report metrics with the wrong name.
                pub const NAMES: [&'static str; 0usize $( $( + __replace_expr!($names, 1usize))+ )+] = [
                    $($(concat!("tsrs_", stringify!($categories), "_", stringify!($names)),)+)+
                ];
            }

            $(
            /// [<categories:camel>]-related counters. Held by `Metrics`, not intended to be used on
            /// its own.
            #[derive(Default)]
            pub struct [<$categories:camel Metrics>] {
                $(
                #[doc = $doc]
                pub $names: Counter
                ),+
            }
            )+

            /// A packed snapshot of `Metrics` counter values
            #[derive(Copy, Clone)]
            pub struct MetricsSnapshot {
                /// This array is indexed by metric id, the same as `Metrics::NAMES`. If that ever
                /// fails to hold then we will report metrics with the wrong name.
                pub values: [usize; 0usize $( $( + __replace_expr!($names, 1usize))+ )+]
            }

            impl MetricsSnapshot {
                /// Take a snapshot. Counters are loaded individually so a completed snapshot
                /// doesn't reflect the instantaneous state of the system. However, even if this
                /// function is preempted a snapshot should take only a few ms to complete.
                pub fn new(metrics: &Metrics) -> Self {
                    let mut snapshot = MetricsSnapshot {
                        values: Default::default(),
                    };

                    let mut idx = 0;
                    $($(
                    snapshot.values[idx] = metrics.$categories.$names.get();
                    idx += 1;
                    )+)+

                    snapshot
                }
            }
        }
    }
}

macro_rules! __replace_expr {
    ($_arg:tt, $sub:expr) => { $sub };
}

define_metrics! {
    {
        category: control_plane,
        counters: [
            handled_state_update: "state updates successfully handled"
        ]
    },
    {
        category: network,
        counters: [
            rx_pkts_wg: "wireguard packets received",
            rx_pkts_disco: "disco packets received",
            rx_pkts_stun: "stun packets received"
        ]
    }
}

/// A thread-safe monotonic counter. Using `usize` enables us to scale down to 32-bit systems.
/// Wraps around on overflow.
pub struct Counter {
    #[cfg(feature = "metrics")]
    count: AtomicUsize,
}

impl Counter {
    /// Increment the counter
    pub fn inc(&self) {
        self.add(1);
    }

    /// Add `value` to the counter
    pub fn add(&self, value: usize) {
        #[cfg(feature = "metrics")]
        self.count.fetch_add(value, Ordering::Relaxed);
    }

    fn get(&self) -> usize {
        #[cfg(feature = "metrics")]
        return self.count.load(Ordering::Relaxed);
        #[cfg(not(feature = "metrics"))]
        return 0;
    }
}

impl Default for Counter {
    fn default() -> Self {
        Counter {
            #[cfg(feature = "metrics")]
            count: AtomicUsize::new(0)
        }
    }
}