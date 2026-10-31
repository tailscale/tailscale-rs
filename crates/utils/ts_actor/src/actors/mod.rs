//! Generic actors that ship with the system.

pub mod bus;
mod forward_stream;
pub mod registry;

pub use forward_stream::forward_stream;
