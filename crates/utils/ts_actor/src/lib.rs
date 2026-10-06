#![no_std]

//! Experimental actor system built as an adaptation of Erlang into Rust idioms.
//!
//! `ts_actor` intentionally diverges from existing Rust ecosystem actor systems by adopting highly
//! dynamic message processing capabilities, rather than traits enforcing static message and reply
//! typing.

extern crate alloc;
pub extern crate smallbox;

mod message;
pub mod oneshot;

pub use message::Message;
