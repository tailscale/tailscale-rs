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

use std::fmt;

#[doc(inline)]
pub use config::{Config, DEFAULT_CONTROL_SERVER};
pub use control_dialer::{ControlDialer, TcpDialer, complete_connection};
pub use derp::{Map as DerpMap, Region as DerpRegion, convert_derp_map};
pub use dial_plan::{DialCandidate, DialMode, DialPlan};
pub use node::{Id as NodeId, Node, StableId as StableNodeId, TailnetAddress};

#[cfg(feature = "async_tokio")]
pub use crate::tokio::{AsyncControlClient, FilterUpdate, PeerUpdate, StateUpdate};

/// An error which occured while connecting to the control server or control plane.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum Error {
    /// A machine was not authorized by control to join tailnet; authorize via the supplied URL.
    #[error("machine was not authorized by control to join tailnet")]
    MachineNotAuthorized(url::Url),

    /// Some kind of networking error, e.g., HTTP, TLS.
    ///
    /// These might be addressed by retrying, or might be an unresolvable error.
    ///
    /// [`Operation`] is intended to be informational, rather then inspected during handling.
    #[error("A networking error occurred in {0}")]
    NetworkError(Operation),

    /// An internal error that users of the library are not expected to handle.
    ///
    /// [`InternalErrorKind`] and [`Operation`] are intended to be informational, rather then
    /// inspected during handling.
    #[error("{0} error in {1}")]
    Internal(InternalErrorKind, Operation),
}

/// What kind of internal error has occured.
///
/// This is intended to be useful for reporting a crash to an end user, rather than being handled.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    /// An error in URL parsing.
    Url,
    /// An error in serialization or deserialization.
    SerDe,
    /// An error in I/O.
    Io,
    /// An invalid message format.
    MessageFormat,
    /// An error parsing a string as UTF8.
    Utf8,
    /// Noise framework handshake.
    NoiseHandshake,
    /// Tailscale challenge packet.
    Challenge,
    /// The user's machine was not authorized to register with a Tailnet and there is no URL for
    /// the user to authorize at.
    MachineAuthorization,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Io => write!(f, "I/O error"),
            InternalErrorKind::MessageFormat => write!(f, "message format error"),
            InternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            InternalErrorKind::NoiseHandshake => write!(f, "error in Noise handshake"),
            InternalErrorKind::Challenge => write!(f, "error with Tailscale challenge packet"),
            InternalErrorKind::MachineAuthorization => {
                write!(f, "Machine not authorized to register with Tailnet")
            }
        }
    }
}

/// The phase of connecting the control plane to a Tailnet in which an error occurs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Operation {
    /// Requesting a net map.
    MapRequest,
    /// Connecting to a control server.
    ConnectToControlServer,
    /// Registering the user's device with a Tailnet.
    Registration,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::MapRequest => write!(f, "net map request"),
            Operation::ConnectToControlServer => write!(f, "connection to control server"),
            Operation::Registration => write!(f, "registration"),
        }
    }
}

impl From<ts_http_util::Error> for Error {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error");
        Error::NetworkError(Operation::ConnectToControlServer)
    }
}
