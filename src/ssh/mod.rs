//! Support for tailnet-native, in-process SSH servers.
//!
//! # Overview
//!
//! This module (`tailscale::ssh`) holds helpers for running SSH servers on the tailnet
//! using [`russh`]. They delegate their functionality to the [`Handler`] trait, which is
//! `russh`'s notion of a _connection_ handler, i.e. a single incoming TCP connection gets
//! a single instance of [`Handler`].
//!
//! ## Channels
//!
//! SSH has a nested notion of channels, which are multiplexed over a single connection.
//! The terminal session you open over a normal machine-to-machine ssh connection runs in a
//! channel, and in principle, you can have multiple channels open on the same connection.
//!
//! The `channel_server` module provides a [`ChannelServer`] type that separates out the
//! per-channel handler logic from `russh`'s monolithic [`Handler`]. Channel handler logic
//! is supported here by [`ChannelHandler`], which is passed into [`ChannelServer`] and
//! processes a [`ChannelEvent`] stream for each channel that's opened.
//!
//! ## Terminal applications
//!
//! Support for building per-channel terminal application is provided by [`RatatuiTerm`],
//! which implements [`ChannelHandler`] to drive a
//! [`ratatui::Terminal`][::ratatui::Terminal]. The user provides an implementation of
//! [`RatatuiApp`] that consumes input data and supports draws to the screen, and the
//! [`RatatuiTerm`] drives it automatically.

pub extern crate russh;

use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use russh::server::Handler;

mod channel_server;
mod channel_write;
mod ratatui;

pub use channel_server::{ChannelEvent, ChannelHandler, ChannelServer};
pub use ratatui::{RatatuiApp, RatatuiEnv, RatatuiTerm};

/// Trait to construct a new [`Handler`] from a Tailscale [`Device`][crate::Device] and
/// the address of a connecting client.
///
/// Rephrasing of [`russh::server::Server`] that includes the Tailscale device as an
/// argument and skips the support for off-tailnet IP and Unix sockets.
pub trait TailnetServer {
    /// Construct a new handler.
    fn new_client(dev: Arc<crate::Device>, addr: SocketAddr) -> Self;
}

impl crate::Device {
    /// Serve an ssh service on the given TCP address.
    ///
    /// This is a minimal helper that just wires up the relevant pieces. All the
    /// authentication and actual SSH server logic must be implemented by the caller in
    /// the `TailnetServer` (`H`) and configured by `config`.
    pub async fn serve_ssh<H>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        H: TailnetServer + Handler + Send + 'static,
        H::Error: Debug,
    {
        let config = Arc::new(config);
        let listener = self.tcp_listen(listen_addr).await?;

        tracing::info!(%listen_addr, "ssh server listening");

        loop {
            let conn = listener.accept().await?;

            let handler = H::new_client(self.clone(), conn.remote_addr());
            let config = config.clone();

            tokio::task::spawn(async move {
                let sess = match russh::server::run_stream(config, conn, handler).await {
                    Ok(sess) => sess,
                    Err(e) => {
                        tracing::error!(error = ?e, "establishing session");
                        return;
                    }
                };

                match sess.await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(error = ?e, "running ssh session");
                    }
                }
            });
        }
    }

    /// Serve an SSH TUI service on the given TCP address.
    ///
    /// Wrapper around [`serve_ssh`][crate::Device::serve_ssh] to specifically use
    /// [`ChannelServer`] around a [`RatatuiTerm`] using `App`.
    pub async fn serve_ssh_tui<App>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        App: RatatuiApp + Default + Send + 'static,
    {
        self.serve_ssh::<ChannelServer<RatatuiTerm<App>>>(config, listen_addr)
            .await
    }
}
