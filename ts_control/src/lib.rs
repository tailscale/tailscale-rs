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

/// An error connecting to the control server or control plane.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A machine was not authorized by control to join tailnet, authorize via the supplied URL.
    #[error("machine was not authorized by control to join tailnet")]
    MachineNotAuthorized(url::Url),

    /// An internal error that users of the library are not expected to handle.
    #[error("{0} error in {1}")]
    Internal(ErrorKind, ConnectionPhase),
    /// An internal error with protocol implementation that users of the library are not expected to handle.
    #[error("{0}")]
    Protocol(ProtocolPhase),
}

/// What kind of internal error has occured.
///
/// This is intended to be useful for reporting a crash to an end user, rather than being handled.
#[derive(Debug)]
pub enum ErrorKind {
    /// An error in URL parsing.
    Url,
    /// An error in serialization/deserialization.
    SerDe,
    /// An error with an HTTP connection.
    Http,
    /// An error with a TLS connection.
    Tls,
    /// An error in I/O.
    Io,
    /// An invalid message format.
    MessageFormat,
    /// An error parsing a string as UTF8.
    Utf8,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Url => write!(f, "URL parsing"),
            ErrorKind::SerDe => write!(f, "serialization/deserialization"),
            ErrorKind::Http => write!(f, "HTTP error"),
            ErrorKind::Tls => write!(f, "TLS error"),
            ErrorKind::Io => write!(f, "I/O"),
            ErrorKind::MessageFormat => write!(f, "message format"),
            ErrorKind::Utf8 => write!(f, "UTF8"),
        }
    }
}

/// The phase of connecting the control plane to a Tailnet in which an internal error occurs.
#[derive(Debug)]
pub enum ConnectionPhase {
    /// Requesting a net map.
    MapRequest,
    /// Connecting to a control server.
    ConnectToControlServer,
    /// Registering the user's device with a Tailnet.
    Registration,
    /// Handling a ping.
    Ping,
}

impl fmt::Display for ConnectionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionPhase::MapRequest => write!(f, "net map request"),
            ConnectionPhase::ConnectToControlServer => write!(f, "connection to control server"),
            ConnectionPhase::Registration => write!(f, "registration"),
            ConnectionPhase::Ping => write!(f, "ping"),
        }
    }
}

/// The phase in which a protocol error occurs.
#[derive(Debug)]
pub enum ProtocolPhase {
    /// Noise framework handshake.
    NoiseHandshake,
    /// Tailscale challenge packet.
    Challenge,
    /// The user's machine was not authorized to register with a Tailnet and there is no URL for
    /// the user to authorize at.
    MachineAuthorization,
}

impl fmt::Display for ProtocolPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolPhase::NoiseHandshake => write!(f, "Noise handshakes"),
            ProtocolPhase::Challenge => write!(f, "Tailscale challenge packet"),
            ProtocolPhase::MachineAuthorization => {
                write!(f, "Machine not authorized to register with Tailnet")
            }
        }
    }
}

impl From<ts_http_util::Error> for Error {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error");
        Error::Internal(ErrorKind::Http, ConnectionPhase::ConnectToControlServer)
    }
}
