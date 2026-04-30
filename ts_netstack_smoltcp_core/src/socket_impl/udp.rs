use alloc::vec;
use core::net::SocketAddr;

use bytes::Bytes;
use smoltcp::{iface::SocketHandle, socket::udp};

use crate::command::{
    Error, Response,
    udp::{Command as UdpCommand, Response as UdpResponse},
};

impl crate::Netstack {
    /// Process a UDP socket command.
    #[tracing::instrument(skip_all, fields(?handle, ?cmd), level = "debug")]
    pub(crate) fn process_udp(
        &mut self,
        cmd: UdpCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match cmd {
            UdpCommand::Bind { endpoint } => {
                let mut sock = udp::Socket::new(self.udp_buffer(), self.udp_buffer());

                if endpoint.port() == 0 {
                    tracing::error!(?endpoint, "udp bind: zero port");
                    return Response::Error(Error::unaddressable());
                }

                // The two possible failure cases for `bind` are that the port is zero or the socket
                // was already open. Those are handled, so failure is impossible here.
                sock.bind(endpoint).unwrap();

                let handle = self.socket_set.add(sock);

                UdpResponse::Bound {
                    local: endpoint,
                    handle,
                }
                .into()
            }
            UdpCommand::Send { endpoint, buf } => {
                let handle = handle.unwrap();

                let sock = self.socket_set.get_mut::<udp::Socket>(handle);
                if buf.len() > sock.payload_send_capacity() {
                    tracing::error!(
                        len = buf.len(),
                        socket_capacity = sock.payload_send_capacity(),
                        "requested message size overflows socket capacity",
                    );

                    return Response::Error(Error::big_packet());
                }

                match sock.send_slice(&buf, endpoint) {
                    Ok(_n) => Response::Ok,
                    // This means that the _current_ buffer is too full, but since we checked if we
                    // had send capacity, it should be available in the future, so just punt and
                    // wouldblock until then.
                    Err(udp::SendError::BufferFull) => Response::WouldBlock {
                        command: UdpCommand::Send { buf, endpoint }.into(),
                        handle: Some(handle),
                    },
                    Err(udp::SendError::Unaddressable) => {
                        tracing::error!(?endpoint, "invalid endpoint");
                        Response::Error(Error::unaddressable())
                    }
                }
            }
            UdpCommand::Recv { max_len } => {
                let sock = self
                    .socket_set
                    .get_mut::<udp::Socket>(unwrap_handle!(handle));

                match sock.recv() {
                    Ok((b, meta)) => {
                        let mut len = b.len();
                        let mut truncated = None;

                        if let Some(max_len) = max_len {
                            let max_len = max_len.get();

                            if len > max_len {
                                truncated = Some(len);
                                tracing::warn!(len, max_len, "udp read truncated");
                            }

                            len = max_len.min(len);
                        }

                        UdpResponse::RecvFrom {
                            remote: SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port),
                            buf: Bytes::copy_from_slice(&b[..len]),
                            truncated,
                        }
                        .into()
                    }
                    Err(udp::RecvError::Exhausted) => Response::WouldBlock {
                        command: UdpCommand::Recv { max_len }.into(),
                        handle,
                    },
                    Err(udp::RecvError::Truncated) => {
                        // this can't occur for recv() as we have a view into the backing
                        // socketbuffer storage. truncated only occurs for recv_slice().
                        unreachable!()
                    }
                }
            }
            UdpCommand::Close => {
                // NOTE(npry): smoltcp supports socket reuse via `socket.close()`, which puts the
                // socket in a valid state to re-bound. We don't support that for API simplicity,
                // but we could in principle if there was a motivating reason.
                self.socket_set.remove(unwrap_handle!(handle));

                Response::Ok
            }
        }
    }

    fn udp_buffer(&self) -> udp::PacketBuffer<'static> {
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_message_count],
            vec![0; self.config.udp_buffer_size],
        )
    }
}
