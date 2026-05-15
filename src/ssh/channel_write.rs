use std::io::{ErrorKind, Write};

use bytes::BytesMut;

/// Wrapper that implements [`Write`] for a [`russh`] channel.
///
/// Needed to support a `crossterm` terminal driver, which isn't async-aware.
///
/// This is basically `tokio_util::SyncIoBridge`, except that [`russh::server::Handle`]
/// doesn't natively support [`tokio::io::AsyncWrite`], so it's all just done here.
pub struct ChannelWrite {
    rt: tokio::runtime::Handle,
    buf: BytesMut,
    channel_id: russh::ChannelId,
    handle: russh::server::Handle,
}

impl ChannelWrite {
    pub fn new(
        runtime: tokio::runtime::Handle,
        handle: russh::server::Handle,
        channel_id: russh::ChannelId,
    ) -> Self {
        Self {
            rt: runtime,
            buf: BytesMut::new(),
            handle,
            channel_id,
        }
    }
}

impl Write for ChannelWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        tokio::task::block_in_place(|| {
            self.rt
                .block_on(self.handle.data(self.channel_id, self.buf.split()))
        })
        .map_err(|_| ErrorKind::BrokenPipe.into())
    }
}
