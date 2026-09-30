#![doc = include_str!("../README.md")]

mod codec;
mod error;
mod framed_io;
mod handshake;
mod messages;

pub use codec::{BiCodec, Codec, MAX_MESSAGE_SIZE, Rx, Tx};
pub use error::Error;
pub use handshake::Handshake;
pub use messages::{Header, Initiation, MessageType};
