#![doc = include_str!("../README.md")]

extern crate alloc;

/// Package version of `ts_control` as reported by cargo.
// TODO(npry): this is used to populate Hostinfo.ipn_version, which requests "long format":
//  attach build info and whatever else that entails
pub const PKG_VERSION: &str = if let Some(version) = option_env!("CARGO_PKG_VERSION") {
    version
} else {
    ""
};

pub mod client;
mod config;
mod control_dialer;
mod derp;
mod dial_plan;
mod map_request_builder;
mod node;

use std::fmt;

pub use client::{FilterUpdate, PeerUpdate, RegistrationError, StateUpdate, connect, register};
#[doc(inline)]
pub use config::{Config, DEFAULT_CONTROL_SERVER};
pub use control_dialer::{ControlDialer, TcpDialer, complete_connection};
pub use derp::{Map as DerpMap, Region as DerpRegion, convert_derp_map};
pub use dial_plan::{DialCandidate, DialMode, DialPlan};
pub use map_request_builder::MapRequestBuilder;
pub use node::{
    Id as NodeId, Node, NodeLastSeen, NodeStatus, NodeUpdate, StableId as StableNodeId,
    TailnetAddress,
};
pub use ts_control_serde::{Endpoint, EndpointType};

/// An error which occurred while connecting to the control server or control plane.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum Error {
    /// A machine was not authorized by control to join tailnet; authorize via the supplied URL.
    #[error("machine was not authorized by control to join tailnet, authorize at {0}")]
    MachineNotAuthorized(url::Url),

    /// The user supplied an invalid URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(url::Url),

    /// Some kind of networking error.
    ///
    /// These might be addressed by retrying, or might be an unresolvable error.
    ///
    /// [`Operation`] is intended to be informational, rather then inspected during handling.
    #[error("a networking error occurred in {0}")]
    NetworkError(Operation),

    /// An internal error that users of the library are not expected to handle.
    ///
    /// [`InternalErrorKind`] and [`Operation`] are intended to be informational, rather then
    /// inspected during handling.
    #[error("{0} error in {1}")]
    Internal(InternalErrorKind, Operation),
}

impl Error {
    fn io_error(err: std::io::Error, op: Operation) -> Self {
        if crate::is_network_error(&err) {
            Error::NetworkError(op)
        } else {
            Error::Internal(InternalErrorKind::Io, op)
        }
    }
}

/// What kind of internal error has occurred.
///
/// This is intended to be useful for reporting a crash to an end user, rather than being handled.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    /// An error in URL parsing.
    Url,
    /// An unsuccessful HTTP request or upgrade.
    Http,
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
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Io => write!(f, "I/O error"),
            InternalErrorKind::MessageFormat => write!(f, "message format error"),
            InternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            InternalErrorKind::NoiseHandshake => write!(f, "error in Noise handshake"),
            InternalErrorKind::Challenge => write!(f, "error with Tailscale challenge packet"),
            InternalErrorKind::MachineAuthorization => {
                write!(f, "machine not authorized to register with Tailnet")
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

        if http_error_is_recoverable(error) {
            Error::NetworkError(Operation::ConnectToControlServer)
        } else {
            Error::Internal(InternalErrorKind::Http, Operation::ConnectToControlServer)
        }
    }
}

/// Returns true if the input io error should be classed as a network error.
fn is_network_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        err.kind(),
        ConnectionRefused
            | ConnectionReset
            | HostUnreachable
            | NetworkUnreachable
            | ConnectionAborted
            | NotConnected
            | TimedOut
            | AddrNotAvailable
            | Interrupted
            | NetworkDown
    )
}

/// Returns true if the error is likely to be a transient network error.
fn http_error_is_recoverable(error: ts_http_util::Error) -> bool {
    match error {
        ts_http_util::Error::Io => true,
        ts_http_util::Error::InvalidInput
        // A TCP timeout (recoverable) should get classed as an IO error, so any other kind of
        // timeout is probably not.
        | ts_http_util::Error::Timeout
        | ts_http_util::Error::InvalidResponse => false,
        // In the future, this might be recoverable with a reset.
        ts_http_util::Error::ConnectionClosed => false,
    }
}
