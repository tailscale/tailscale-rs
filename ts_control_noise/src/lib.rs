#![doc = include_str!("../README.md")]

mod cipher;
mod codec;
mod error;
mod framed_io;
mod handshake;
mod messages;

pub use cipher::ChaCha20Poly1305BigEndian;
pub use codec::{BiCodec, Codec, MAX_MESSAGE_SIZE};
pub use error::Error;
pub use handshake::Handshake;
pub use messages::{Header, Initiation, MessageType};
