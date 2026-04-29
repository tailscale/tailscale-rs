//! Socket command handler implementations for [`Netstack`][crate::Netstack].

/// Unwrap an optional handle or log an error and return
/// [`Error::BadRequest`][crate::command::Error::BadRequest].
macro_rules! unwrap_handle {
    ($handle:expr) => {{
        let handle = $handle;

        match handle {
            Some(handle) => handle,
            None => {
                tracing::error!(?handle, "no socket handle");

                return $crate::command::Error::missing_socket().into();
            }
        }
    }};
}

pub mod raw;
pub mod tcp;
pub mod udp;
