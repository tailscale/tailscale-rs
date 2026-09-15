#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod debounce;

#[cfg(feature = "tokio")]
pub use debounce::TokioDebounce;
pub use debounce::{Debounce, DebounceExt};
