use bytes::Bytes;
use smoltcp::{iface::SocketHandle, socket::tcp};

use crate::{
    Netstack,
    command::{
        Error, Response,
        tcp::stream::{Command as TcpStreamCommand, Response as TcpStreamResponse},
    },
};

impl Netstack {
    /// Process a TCP stream command.
    #[tracing::instrument(skip_all, fields(?cmd, ?handle), level = "debug")]
    pub(crate) fn process_tcp_stream(
        &mut self,
        cmd: TcpStreamCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match cmd {
            TcpStreamCommand::Connect {
                remote_endpoint,
                local_endpoint,
            } => {
                // Only occurs if we're polling a `WouldBlock`.
                if let Some(handle) = handle {
                    return self.check_conn(
                        handle,
                        TcpStreamCommand::Connect {
                            local_endpoint,
                            remote_endpoint,
                        },
                    );
                }

                let mut sock = tcp::Socket::new(self.tcp_buffer(), self.tcp_buffer());

                if let Err(e) = sock.connect(self.iface.context(), remote_endpoint, local_endpoint)
                {
                    tracing::error!(error = %e, "tcp connect");
                    return Response::Error(e.into());
                }

                let handle = self.socket_set.add(sock);

                Response::WouldBlock {
                    handle: Some(handle),
                    command: TcpStreamCommand::Connect {
                        local_endpoint,
                        remote_endpoint,
                    }
                    .into(),
                }
            }

            TcpStreamCommand::Send { buf } => {
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

                match sock.send_slice(&buf) {
                    Ok(0) => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Send { buf }.into(),
                    },
                    Ok(n) => TcpStreamResponse::Sent { n }.into(),
                    Err(tcp::SendError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for send");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Recv { max_len } => {
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

                match sock.recv(|buf| {
                    let mut len = buf.len();

                    if let Some(max_len) = max_len {
                        len = len.min(max_len);
                    }

                    (len, Bytes::copy_from_slice(&buf[..len]))
                }) {
                    Ok(buf) if buf.is_empty() => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Recv { max_len }.into(),
                    },
                    Ok(buf) => TcpStreamResponse::Recv { buf }.into(),
                    Err(tcp::RecvError::Finished) => TcpStreamResponse::Finished.into(),
                    Err(tcp::RecvError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for recv");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Close => {
                let handle = handle.unwrap();

                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);
                sock.close();

                self.pending_tcp_closes.push(handle);

                Response::Ok
            }
        }
    }

    /// Drop all TCP sockets that have finished closing.
    #[tracing::instrument(skip_all)]
    pub(crate) fn drain_tcp_closes(&mut self) {
        self.pending_tcp_closes.retain(|&handle| {
            let state = {
                let sock = self.socket_set.get::<tcp::Socket>(handle);
                sock.state()
            };

            let should_remove = state == tcp::State::Closed;
            if should_remove {
                self.socket_set.remove(handle);
            }

            !should_remove
        });
    }

    fn check_conn(&mut self, handle: SocketHandle, orig_cmd: TcpStreamCommand) -> Response {
        let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

        match sock.state() {
            tcp::State::Established => {
                tracing::trace!("connection succeeded");
                TcpStreamResponse::Connected { handle }.into()
            }

            tcp::State::SynReceived | tcp::State::SynSent => Response::WouldBlock {
                handle: Some(handle),
                command: orig_cmd.into(),
            },

            _ => {
                tracing::warn!("connecting socket was reset or closed");
                self.pending_tcp_closes.push(handle);
                Response::Error(Error::ConnectionReset)
            }
        }
    }
}
