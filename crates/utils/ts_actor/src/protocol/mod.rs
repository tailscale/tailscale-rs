//! Message protocols independent of gen_server or any other particular process shape.
//!
//! The idea is that any process can implement a protocol if it implements the semantics
//! correctly, e.g. any process can be a [`registry`] if it replies to [`registry::Lookup`]
//! with [`registry::Reply`].

pub mod registry;
