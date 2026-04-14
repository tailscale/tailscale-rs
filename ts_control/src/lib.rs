#![doc = include_str!("../README.md")]

extern crate alloc;

/// Package version of `ts_control` as reported by cargo.
// TODO(npry): this is used to populate Hostinfo.ipn_version, which requests "long format":
//  attach build info and whatever else that entails
const PKG_VERSION: &str = if let Some(version) = option_env!("CARGO_PKG_VERSION") {
    version
} else {
    ""
};

mod config;
mod control_dialer;
mod derp;
mod dial_plan;
#[cfg_attr(not(feature = "async_tokio"), expect(dead_code))]
mod map_request_builder;
mod node;
#[cfg(feature = "async_tokio")]
mod tokio;

#[doc(inline)]
pub use config::{Config, DEFAULT_CONTROL_SERVER};
pub use control_dialer::{ControlDialer, TcpDialer, complete_connection};
pub use derp::{Map as DerpMap, Region as DerpRegion, convert_derp_map};
pub use dial_plan::{DialCandidate, DialMode, DialPlan};
pub use node::{Id as NodeId, Node, StableId as StableNodeId, TailnetAddress};

#[cfg(feature = "async_tokio")]
pub use crate::tokio::{AsyncControlClient, AuthResult, FilterUpdate, PeerUpdate, StateUpdate};

/// Errors that may occur while communicating with control.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error connecting to control.
    #[error(transparent)]
    #[cfg(feature = "async_tokio")]
    Connect(#[from] tokio::ConnectionError),
    /// Error processing streaming netmap results.
    #[error(transparent)]
    #[cfg(feature = "async_tokio")]
    MapStream(#[from] tokio::MapStreamError),
    /// Error executing a ping.
    #[error(transparent)]
    #[cfg(feature = "async_tokio")]
    Ping(#[from] tokio::PingError),
    /// Error registering with control.
    #[error(transparent)]
    #[cfg(feature = "async_tokio")]
    Register(#[from] tokio::RegistrationError),
}
