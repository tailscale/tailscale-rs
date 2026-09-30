#![doc = include_str!("../README.md")]

mod derp_latency;
pub mod https;
pub mod stun;

pub use derp_latency::{Config, RegionResult, measure_derp_map};
#[doc(inline)]
pub use https::measure_https_latency;
