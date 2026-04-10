use alloc::vec;

use bytes::Bytes;
use smoltcp::{iface::SocketHandle, socket::raw};

use crate::{
    Netstack, Response,
    command::Error,
    raw::{Command as RawSocketCommand, Response as RawSocketResponse},
};

impl Netstack {
    /// Process a raw socket command.
    #[tracing::instrument(skip_all, fields(?raw, ?handle), level = "debug")]
    pub(crate) fn process_raw(
        &mut self,
        raw: RawSocketCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match raw {
            RawSocketCommand::Open {
                ip_version,
                protocol,
            } => {
                let sock = raw::Socket::new(
                    Some(ip_version),
                    Some(protocol),
                    self.raw_buffer(),
                    self.raw_buffer(),
                );
                let handle = self.socket_set.add(sock);

                RawSocketResponse::Opened { handle }.into()
            }
            RawSocketCommand::Send { buf } => {
                let sock = self
                    .socket_set
                    .get_mut::<raw::Socket>(unwrap_handle!(handle));

                if buf.len() > sock.payload_send_capacity() {
                    tracing::error!(
                        len = buf.len(),
                        capacity = sock.payload_send_capacity(),
                        "send can never succeed, packet size is greater than socket buffer cap"
                    );

                    return Response::Error(Error::BadRequest);
                }

                match sock.send_slice(&buf) {
                    Ok(()) => Response::Ok,
                    Err(raw::SendError::BufferFull) => Response::WouldBlock {
                        command: RawSocketCommand::Send { buf }.into(),
                        handle,
                    },
                }
            }
            RawSocketCommand::Recv { max_len } => {
                let sock = self
                    .socket_set
                    .get_mut::<raw::Socket>(unwrap_handle!(handle));

                match sock.recv() {
                    Ok(mut buf) => {
                        let mut trunc = None;

                        if let Some(max_len) = max_len {
                            let max_len = max_len.get();

                            if max_len < buf.len() {
                                tracing::warn!(max_len, pkt_len = buf.len(), "truncating packet");

                                trunc = Some(buf.len());
                                buf = &buf[..max_len];
                            }
                        }

                        RawSocketResponse::Recv {
                            buf: Bytes::copy_from_slice(buf),
                            truncated: trunc,
                        }
                        .into()
                    }
                    Err(raw::RecvError::Exhausted) => Response::WouldBlock {
                        command: RawSocketCommand::Recv { max_len }.into(),
                        handle,
                    },
                    Err(raw::RecvError::Truncated) => {
                        // this can't occur for recv()
                        unreachable!()
                    }
                }
            }
            RawSocketCommand::Close => {
                self.socket_set.remove(unwrap_handle!(handle));
                Response::Ok
            }
        }
    }

    fn raw_buffer(&self) -> raw::PacketBuffer<'static> {
        raw::PacketBuffer::new(
            vec![raw::PacketMetadata::EMPTY; self.config.raw_message_count],
            vec![0; self.config.raw_buffer_size],
        )
    }
}
