#![doc = include_str!("../README.md")]

mod config;
mod endpoint;
mod handshake;
mod macs;
mod messages;
mod session;
mod time;

pub use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};

pub use crate::{
    config::{PeerConfig, PeerId, Psk},
    endpoint::{Endpoint, Event, EventResult, RecvResult, SendResult},
};
