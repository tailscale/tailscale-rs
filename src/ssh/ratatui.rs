use std::sync::Arc;

use ratatui::{Terminal, TerminalOptions, Viewport, backend::CrosstermBackend, layout::Rect};
use russh::{ChannelId, Sig, server::Handle};

use crate::{
    Device,
    ssh::{ChannelEvent, ChannelHandler, channel_write::ChannelWrite},
};

type Backend = CrosstermBackend<ChannelWrite>;

/// Terminal environment for [`RatatuiApp`].
pub trait RatatuiEnv {
    /// Request that the terminal close.
    fn close(&self) -> impl Future<Output = ()> + Send;

    /// Get a reference to the Tailscale [`Device`] this is running in.
    fn tailscale(&self) -> &Device;
}

/// A [`ratatui`] application designed to be driven by a
/// [`ChannelServer`][crate::ssh::ChannelServer].
pub trait RatatuiApp {
    /// Process new input from the channel.
    fn input(
        &mut self,
        data: &[u8],
        env: impl RatatuiEnv + Send,
    ) -> impl Future<Output = ()> + Send;

    /// Render the app to the [`ratatui::Frame`].
    fn draw(&mut self, frame: &mut ratatui::Frame);
}

/// A [`ChannelHandler`] that runs a [`RatatuiApp`].
pub struct RatatuiTerm<Io> {
    channel_id: ChannelId,
    session: Handle,
    term: Terminal<Backend>,
    dev: Arc<Device>,
    io: Io,
}

struct Env<'a> {
    channel_id: ChannelId,
    session: &'a Handle,
    dev: &'a Device,
}

impl RatatuiEnv for Env<'_> {
    async fn close(&self) {
        if self.session.close(self.channel_id).await.is_err() {
            tracing::error!("channel closed while closing ratatui app");
        }
    }

    fn tailscale(&self) -> &Device {
        self.dev
    }
}

impl<Io> RatatuiTerm<Io>
where
    Io: RatatuiApp,
{
    fn refresh(&mut self) -> std::io::Result<()> {
        self.term.clear()?;
        self.draw()?;

        Ok(())
    }

    fn draw(&mut self) -> std::io::Result<()> {
        self.term.draw(|frame| self.io.draw(frame))?;

        Ok(())
    }
}

impl<Io> ChannelHandler for RatatuiTerm<Io>
where
    Io: RatatuiApp + Default + Send,
{
    type Error = std::io::Error;

    fn new(
        rt: tokio::runtime::Handle,
        channel_id: ChannelId,
        session: Handle,
        dev: Arc<Device>,
    ) -> Result<Self, Self::Error> {
        let mut term = Self {
            term: make_term(rt, session.clone(), channel_id)?,
            dev,
            channel_id,
            session,
            io: Default::default(),
        };
        term.refresh()?;

        Ok(term)
    }

    async fn handle_event(&mut self, event: &ChannelEvent) -> Result<(), Self::Error> {
        match event {
            ChannelEvent::Data(d) => {
                self.io
                    .input(
                        d,
                        Env {
                            dev: &self.dev,
                            channel_id: self.channel_id,
                            session: &self.session,
                        },
                    )
                    .await;

                self.draw()?;
            }
            ChannelEvent::Resize { width, height } => {
                self.term.resize(Rect::new(0, 0, *width, *height))?;
                self.draw()?;
            }
            ChannelEvent::Eof
            | ChannelEvent::Signal(Sig::ABRT | Sig::QUIT | Sig::TERM | Sig::KILL | Sig::INT) => {
                tracing::debug!(?event, channel_id = %self.channel_id, "close channel");

                if self.session.close(self.channel_id).await.is_err() {
                    tracing::error!("session already shut down");

                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
            }
            ChannelEvent::Signal(sig) => {
                tracing::debug!(?sig, "unhandled signal");
            }
            ChannelEvent::Close => {
                self.term.clear()?;
            }
        }

        Ok(())
    }
}

fn make_term(
    rt: tokio::runtime::Handle,
    session_handle: Handle,
    channel_id: ChannelId,
) -> Result<Terminal<Backend>, <Backend as ratatui::backend::Backend>::Error> {
    let terminal_handle = ChannelWrite::new(rt, session_handle, channel_id);
    let backend = CrosstermBackend::new(terminal_handle);

    let options = TerminalOptions {
        viewport: Viewport::Fixed(Rect::default()),
    };

    Terminal::with_options(backend, options)
}
