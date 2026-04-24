#![doc = include_str!("../README.md")]

mod cipher;
mod codec;
mod error;
mod framed_io;
mod handshake;
mod messages;

pub use cipher::ChaCha20Poly1305BigEndian;
pub use error::Error;
pub use handshake::Handshake;
