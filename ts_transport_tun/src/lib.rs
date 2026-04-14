#![doc = include_str!("../README.md")]

mod async_tokio;
mod config;

pub use async_tokio::AsyncTunTransport;
pub use config::Config;

/// Errors that may be encountered during tun operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An IO error was encountered.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// Tried to create a tun device without sufficient permissions.
    #[error("only root user can create a TUN interface")]
    RootUserRequired,
}
