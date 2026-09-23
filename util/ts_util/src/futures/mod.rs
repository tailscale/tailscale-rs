//! Futures and async related utilities.

mod debounce;

pub use debounce::{Debounce, DebounceExt, DefaultFold};
#[cfg(feature = "tokio")]
pub use debounce::{TokioDebounce, TokioSleepFn};
