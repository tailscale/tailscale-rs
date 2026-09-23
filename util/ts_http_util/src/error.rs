use std::error::Error as StdError;

/// General categories of error that can occur during any phase of an HTTP connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A function argument or field value wasn't populated, or contained an invalid value, or user-
    /// supplied code caused an error.
    #[error("invalid parameter or other input")]
    InvalidInput,

    /// An underlying I/O error occurred that prevented a connection from being established, a
    /// request from being sent, or a response from being read.
    #[error("i/o error encountered")]
    Io,

    /// A timeout expired while waiting for the server to respond, or the client (us) didn't send
    /// request headers within the timeframe the server expected.
    #[error("timed out")]
    Timeout,

    /// The connection is no longer usable for some (probably unexpected) reason.
    #[error("an error occurred and the connection must be re-established before retrying")]
    ConnectionClosed,

    /// An invalid status code or HTTP 2 message where HTTP 1 was expected.
    #[error("received a response which was invalid in some way")]
    InvalidResponse,
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        if io_error(&e) {
            Error::Io
        } else if e.is_timeout() {
            Error::Timeout
        } else if e.is_parse() || e.is_user() {
            Error::InvalidInput
        } else if e.is_parse_status() || e.is_parse_version_h2() {
            Error::InvalidResponse
        } else {
            // A problem with the connection, or something occurred where we should do some kind of
            // reset before retrying.
            // e.is_canceled() || e.is_shutdown() || e.is_body_write_aborted() || e.is_closed() || e.is_incomplete_message
            Error::ConnectionClosed
        }
    }
}

fn io_error(e: &hyper::Error) -> bool {
    let mut e = e as &dyn StdError;
    loop {
        match e.source() {
            None => return false,
            Some(source) => {
                let io = source.downcast_ref::<std::io::Error>();
                if io.is_some() {
                    return true;
                }
                e = source;
            }
        }
    }
}
