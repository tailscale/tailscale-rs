use std::fmt::Display;

use napi::{Error, Status};

/// The `code` of an error reported to JS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    /// An argument was invalid, e.g., an unparseable IP address.
    InvalidArg,
    /// The control server rejected the auth key.
    AuthKeyRejected,
    /// The key file could not be read or parsed.
    KeyFileRead,
    /// The key file could not be written.
    KeyFileWrite,
    /// An operation timed out.
    Timeout,
    /// A connection was reset (or could not be established).
    ConnectionReset,
    /// The netstack rejected a request, e.g., sending to an IPv6 address from an IPv4 socket.
    BadRequest,
    /// The socket or device was closed.
    SocketClosed,
    /// The operation was cancelled by an `AbortSignal`.
    Aborted,
    /// An internal error.
    Internal,
}

impl Code {
    fn as_str(self) -> &'static str {
        match self {
            Code::InvalidArg => "ERR_INVALID_ARG_VALUE",
            Code::AuthKeyRejected => "ERR_TAILSCALE_AUTH_KEY_REJECTED",
            Code::KeyFileRead => "ERR_TAILSCALE_KEY_FILE_READ",
            Code::KeyFileWrite => "ERR_TAILSCALE_KEY_FILE_WRITE",
            Code::Timeout => "ERR_TAILSCALE_TIMEOUT",
            Code::ConnectionReset => "ECONNRESET",
            Code::BadRequest => "ERR_TAILSCALE_BAD_REQUEST",
            Code::SocketClosed => "ERR_SOCKET_CLOSED",
            Code::Aborted => "ABORT_ERR",
            Code::Internal => "ERR_TAILSCALE_INTERNAL",
        }
    }
}

/// Create a JS error with the given code.
///
/// napi-rs can only set an error's `code` property to a napi [`Status`], so the code is instead
/// prefixed to the error message (`"CODE: message"`). The TypeScript wrapper (`lib/errors.ts`)
/// parses it back out and converts the error to the matching JS error type; keep the two in sync.
pub(crate) fn js_err(code: Code, msg: impl Display) -> Error {
    let status = match code {
        Code::InvalidArg => Status::InvalidArg,
        _ => Status::GenericFailure,
    };
    Error::new(status, format!("{}: {msg}", code.as_str()))
}

/// Create a JS error indicating an invalid argument.
pub(crate) fn js_arg_err(e: impl Display) -> Error {
    js_err(Code::InvalidArg, e)
}

/// Convert a device error into a JS error.
pub(crate) fn ts_err(e: tailscale::Error) -> Error {
    let code = match e {
        tailscale::Error::Timeout => Code::Timeout,
        tailscale::Error::ConnectionReset => Code::ConnectionReset,
        tailscale::Error::KeyFileRead => Code::KeyFileRead,
        tailscale::Error::KeyFileWrite => Code::KeyFileWrite,
        tailscale::Error::AuthKeyRejected => Code::AuthKeyRejected,
        tailscale::Error::Internal(tailscale::InternalErrorKind::BadRequest) => Code::BadRequest,
        tailscale::Error::Internal(_) => Code::Internal,
    };
    js_err(code, e)
}

/// Convert a netstack (socket) error into a JS error.
pub(crate) fn netstack_err(e: tailscale::netstack::Error) -> Error {
    let code = match e {
        tailscale::netstack::Error::BadRequest(_) => Code::BadRequest,
        tailscale::netstack::Error::ConnectionReset => Code::ConnectionReset,
        tailscale::netstack::Error::Internal(_) => Code::Internal,
    };
    js_err(code, e)
}
