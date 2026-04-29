use alloc::{collections::VecDeque, vec};
use core::net::SocketAddr;

use smoltcp::{iface::SocketHandle, socket::tcp};

use crate::{
    Netstack,
    command::{
        Error, Response,
        tcp::listen::{Command as TcpListenCommand, Response as TcpListenResponse},
    },
};

/// Opaque handle to a TCP listener.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerHandle(usize);

/// State for a particular TCP listener, supporting the abstraction of a single persistent
/// listener object that can spin off connections by calling `accept`.
///
/// `smoltcp` doesn't provide a TCP listener abstraction, just plain sockets. Each one has
/// its own state machine, which can be in the `LISTENING` state, i.e. waiting for a
/// connection. But once it's `ESTABLISHED`, you need to create a new `LISTENING` socket in
/// order to accept a new connection.
pub struct TcpListenerState {
    /// The local endpoint on which this listener is listening.
    local_endpoint: SocketAddr,

    /// Socket currently in listening state and waiting for a new connection.
    current_socket_handle: SocketHandle,

    /// Sockets which have transitioned from `LISTEN` to `SYN-RECEIVED` (half-open) and are waiting
    /// to become `ESTABLISHED`; in other words, the socket received a `SYN` and replied with a
    /// `SYN-ACK`, and is awaiting an `ACK` to complete the handshake.
    ///
    /// Note that sockets in this queue can [transition back to the `LISTEN` state if the remote
    /// replies with a `RST` rather than an `ACK`](https://www.rfc-editor.org/rfc/rfc793#page-70).
    /// Sockets that return to `LISTEN` should be removed from this queue/dropped (not `close()`d);
    /// the listener has already opened a new socket in the `LISTEN` state.
    half_open_queue: VecDeque<SocketHandle>,

    /// Sockets which have transitioned from `SYN-RECEIVED` (half-open) to `ESTABLISHED`
    /// (full-open); in other words, the socket has received an `ACK` from the remote completing the
    /// three-way handshake. Sockets in this queue are waiting for a call to
    /// [`Netstack::process_tcp_listen()`] with a [`TcpListenCommand::Accept`] command, which will
    /// dequeue a socket and return it to become a [`TcpStream`].
    ///
    /// [`TcpStream`]: [::ts_netstack_smoltcp_socket::tcp::stream::TcpStream]
    accept_queue: VecDeque<SocketHandle>,
}

impl Netstack {
    /// Process a TCP listener command.
    #[tracing::instrument(skip_all, fields(?cmd), level = "debug")]
    pub(crate) fn process_tcp_listen(
        &mut self,
        cmd: TcpListenCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        debug_assert!(handle.is_none());

        match cmd {
            TcpListenCommand::Listen { local_endpoint } => {
                let mut listener = tcp::Socket::new(self.tcp_buffer(), self.tcp_buffer());

                if let Err(e) = listener.listen(local_endpoint) {
                    return Response::Error(e.into());
                }

                let socket_handle = self.socket_set.add(listener);

                let listener_handle = ListenerHandle(self.next_tcp_listener_id);
                self.next_tcp_listener_id += 1;

                self.tcp_listeners.insert(
                    listener_handle,
                    TcpListenerState {
                        current_socket_handle: socket_handle,
                        local_endpoint,
                        half_open_queue: Default::default(),
                        accept_queue: Default::default(),
                    },
                );

                TcpListenResponse::Listening {
                    handle: listener_handle,
                }
                .into()
            }
            TcpListenCommand::Accept { handle } => {
                let Some(listener) = self.tcp_listeners.get_mut(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::missing_listener().into();
                };

                // Iterate the half-open queue, re-queueing any sockets that are still in
                // `SYN-RECEIVED`. Move any sockets in `ESTABLISHED` to the `accept_queue`, close
                // any sockets in `CLOSE-WAIT`, and drop any sockets that moved back to `LISTEN`.
                // All other states are unexpected.
                listener.half_open_queue.retain(|half_open| {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(*half_open);
                    let state = sock.state();
                    let _span = tracing::trace_span!(
                        "half_open_queue",
                        accept_queue_len = listener.accept_queue.len(),
                        pending_closes = self.pending_tcp_closes.len(),
                        ?half_open,
                        ?state
                    )
                    .entered();

                    match state {
                        tcp::State::SynReceived => {
                            tracing::trace!("half-open socket unchanged, re-queueing");
                            true
                        }
                        tcp::State::Established => {
                            tracing::trace!("half-open socket ready, moving to accept queue");
                            listener.accept_queue.push_back(*half_open);
                            false
                        }
                        tcp::State::CloseWait => {
                            tracing::trace!("half-open socket moved to CLOSE-WAIT, closing");
                            sock.close();
                            self.pending_tcp_closes.push(*half_open);
                            if self.pending_tcp_closes.len() > 10000 {
                                tracing::warn!("large number of pending closes");
                            }
                            false
                        }
                        tcp::State::Listen => {
                            tracing::trace!("half-open socket moved to LISTEN, dropping");
                            false
                        }
                        _ => {
                            tracing::warn!("half-open socket in unexpected state, dropping");
                            false
                        }
                    }
                });

                // De-queue a single socket in the `ESTABLISHED` state from the `accept_queue` and
                // return it to become a `TcpStream`.
                if let Some(accept) = listener.accept_queue.pop_front() {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(accept);
                    let state = sock.state();
                    let _span = tracing::trace_span!(
                        "accept_queue",
                        half_open_queue_len = listener.half_open_queue.len(),
                        accept_queue_len = listener.accept_queue.len(),
                        pending_closes = self.pending_tcp_closes.len(),
                        ?accept,
                        ?state
                    )
                    .entered();

                    debug_assert_eq!(sock.state(), tcp::State::Established);
                    tracing::trace!("accept socket accepted, returning");

                    let remote = sock.remote_endpoint().unwrap();
                    return TcpListenResponse::Accepted {
                        handle: accept,
                        remote: SocketAddr::new(remote.addr.into(), remote.port),
                    }
                    .into();
                }

                tracing::trace!("accept queue empty");

                Response::WouldBlock {
                    handle: None,
                    command: TcpListenCommand::Accept { handle }.into(),
                }
            }
            TcpListenCommand::Close { handle } => {
                let Some(listener) = self.tcp_listeners.remove(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::missing_listener().into();
                };

                let sock = self
                    .socket_set
                    .get_mut::<tcp::Socket>(listener.current_socket_handle);

                sock.close();

                self.pending_tcp_closes.push(listener.current_socket_handle);

                let accept_handles = listener
                    .half_open_queue
                    .iter()
                    .chain(listener.accept_queue.iter())
                    .copied();
                for pending_accept in accept_handles {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(pending_accept);
                    sock.close();

                    self.pending_tcp_closes.push(pending_accept);
                }

                Response::Ok
            }
        }
    }

    /// Attempt to accept a TCP connection for all TCP listeners.
    #[tracing::instrument(skip_all)]
    pub(crate) fn pump_tcp_accept(&mut self) {
        for listener in self.tcp_listeners.values_mut() {
            let sock = self
                .socket_set
                .get_mut::<tcp::Socket>(listener.current_socket_handle);

            let state = sock.state();
            let _span = tracing::trace_span!(
                "pump_one_tcp_listener",
                current_socket = ?listener.current_socket_handle,
                current_socket_state = %state,
                accept_queue_len = listener.accept_queue.len(),
                listening_on = %listener.local_endpoint,
            )
            .entered();

            match sock.state() {
                tcp::State::Listen => {
                    tracing::trace!("listening");
                    continue;
                }

                tcp::State::SynReceived => {
                    tracing::trace!("socket pending, not yet established");
                    listener
                        .half_open_queue
                        .push_back(listener.current_socket_handle);
                }

                tcp::State::Established => {
                    tracing::trace!("connection established");
                    listener
                        .accept_queue
                        .push_back(listener.current_socket_handle);
                }

                state => {
                    tracing::warn!(
                        current_socket = ?listener.current_socket_handle,
                        current_socket_state = %state,
                        half_open_queue_len = listener.half_open_queue.len(),
                        accept_queue_len = listener.accept_queue.len(),
                        listening_on = %listener.local_endpoint,
                        "partially-established listening socket reset or closed");
                    sock.close();
                    self.pending_tcp_closes.push(listener.current_socket_handle);
                }
            }

            // fallthrough: socket has either closed or been established -- create a new listen
            // socket

            let mut new_listener = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size]),
                tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size]),
            );

            if let Err(e) = new_listener.listen(listener.local_endpoint) {
                // invariant failure: the only variants for ListenError are
                // InvalidState and Unaddressable. InvalidState isn't possible here because we just
                // created the socket. Unaddressable only occurs if listener.local_endpoint has
                // an unspecified (zero) port and/or address. but we're currently replacing a socket
                // with the _same_ local_endpoint, and it clearly wasn't invalid before, so
                // Unaddressable shouldn't be possible either. this should always succeed.
                panic!("opening new listen socket for accept: {e}");
            }

            let socket_handle = self.socket_set.add(new_listener);
            listener.current_socket_handle = socket_handle;
            tracing::trace!(new_handle = ?socket_handle, "replaced active listen socket");
        }
    }
}
