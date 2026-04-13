//! Command-channel-driven userspace network stack.
//!
//! This is an opinionated wrapper around [`smoltcp`] that provides an easier-to-integrate,
//! more-portable API.
//!
//! ## Organization
//!
//! This is the `core` crate, which just provides a [`Netstack`] type that contains the
//! required state and logic to drive the contained [`smoltcp::iface::Interface`] to process
//! commands received over a [`Channel`]. The ergonomic sockets API around the
//! remote end of that channel is provided by `ts_netstack_smoltcp_socket`.
//!
//! The whole thing is integrated along with runtime functionality in `ts_netstack_smoltcp`.
//!
//! ## Motivation
//!
//! - Usage of `smoltcp` sockets requires access to their backing
//!   [`SocketSet`][smoltcp::iface::SocketSet] (buffer storage). This functionally attaches
//!   them to the lifetime of that storage, meaning that synchronous access across threads
//!   would require passing around `Arc<Mutex<SocketSet>>` and grabbing locks everywhere
//!   that's used. Instead, this crate uses a channel-oriented approach, converting the
//!   socket function call API into a set of RPC-style request/response messages.
//!
//! - Lack of direct integration with `async`: the command-channel paradigm means that this
//!   is straightforward in our implementation: a task or thread drives the netstack, and
//!   sockets enjoy asynchronous semantics by polling on channel sends and receives. Because
//!   the channel library we're using ([`flume`]) supports both sync and async operation,
//!   this means that sockets work naturally in sync contexts as well.
//!
//! - Lack of features: `smoltcp` is a minimal core crate -- it doesn't provide TCP accept
//!   logic, any commitments re: allocation, a complete polling loop, garbage collection of
//!   closed TCP connections, or a way to block until e.g. a TCP connection is established.
//!
//! ## Example
//!
//! ```rust
//! extern crate ts_netstack_smoltcp_core as netcore;
//! # use core::net::SocketAddr;
//! # use bytes::Bytes;
//! # use smoltcp::time::Instant;
//! # use smoltcp::phy::Medium;
//! # use netcore::{Response, udp, HasChannel};
//! # fn main() -> Result<(), netcore::Error> {
//! // Construct a new netstack:
//! let mut stack = netcore::Netstack::new(netcore::Config::default(), Instant::ZERO);
//!
//! // Grab a channel through which we can send commands:
//! let channel = stack.command_channel();
//!
//! // Process the upcoming bind and send commands in the background (request() blocks
//! // for a response, hence the thread)
//! let thread = std::thread::spawn(move || {
//!     for i in 0..2 {
//!         let cmd = stack.wait_for_cmd_blocking(None).unwrap();
//!         stack.process_one_cmd(cmd);
//!     }
//!
//!     stack
//! });
//!
//! // Send a command to bind a UDP socket:
//! let endpoint = SocketAddr::from(([127, 0, 0, 1], 1000));
//! let Response::Udp(udp::Response::Bound { handle, local }) = channel.request_blocking(None, udp::Command::Bind {
//!     endpoint
//! })? else {
//!     unreachable!();
//! };
//! println!("bound udp socket to {local}");
//!
//! // Issue a command to send a UDP packet over the channel:
//! channel.request_nonblocking(Some(handle), udp::Command::Send {
//!     endpoint: SocketAddr::from(([1, 2, 3, 4], 80)),
//!     buf: Bytes::copy_from_slice(b"hello"),
//! })?;
//! println!("sent udp packet");
//!
//! // Wait for the thread started above to finish processing the two UDP port commands:
//! let mut stack = thread.join().unwrap();
//!
//! // Pump the netstack to produce the IP packet that needs to be sent out on the network:
//! let (end1, end2) = netcore::Pipe::unbounded();
//! stack.poll_device_io(Instant::ZERO, &mut netcore::PipeDev {
//!     pipe: end1,
//!     medium: Medium::Ip,
//!     mtu: 1500,
//! });
//!
//! // Receive the packet from the pipe device:
//! let packet = end2.rx.recv().unwrap();
//! println!("packet: {packet:?}");
//!
//! // Sanity-check that the packet we got back is shaped correctly:
//! assert_eq!(packet.len(), smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + b"hello".len());
//! assert_eq!(packet[0] >> 4, 4); // ipv4 packet
//! assert!(packet.ends_with(b"hello"));
//! #     Ok(())
//! # }
//! ```
//!
//! Compare the examples in `ts_netstack_smoltcp_socket` and `ts_netstack_smoltcp` (which
//! do the same thing as this example) for an indication of the abstraction that crate
//! provides.

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub extern crate flume;
pub extern crate smoltcp;

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use core::{
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use smoltcp::{
    iface::{PollIngressSingleResult, PollResult, SocketHandle},
    wire::{HardwareAddress, IpAddress},
};

mod command;
mod config;
mod pipe;
mod socket_impl;
mod stack_control_impl;
mod util;
mod wake_device;

#[doc(inline)]
pub use command::{
    Channel, Command, Error, HasChannel, Request, Response, raw, request, request_blocking,
    request_nonblocking, stack_control, tcp, udp,
};
pub use config::Config;
pub use pipe::{Pipe, PipeDev};
pub use socket_impl::tcp::ListenerHandle as TcpListenerHandle;
pub use stack_control_impl::NetstackControl;
use util::NoopCapDev;
pub use util::{DisplayExt, DisplayToDebug, OptionExt, ResultExt};
pub use wake_device::AsyncWakeDevice;

/// Internally i/o free userspace network stack built around `smoltcp`.
pub struct Netstack {
    config: Config,

    iface: smoltcp::iface::Interface,
    socket_set: smoltcp::iface::SocketSet<'static>,

    command_rx: flume::Receiver<Request>,
    // Need to hold the sender to avoid closing the channel.
    command_tx: flume::Sender<Request>,

    /// Commands pending in a wouldblock state: to be processed again in the future for
    /// completion.
    blocked_commands: VecDeque<Request>,

    /// Set of TCP socket handles that are expected to close in the future, held onto for
    /// graceful shutdown.
    pending_tcp_closes: Vec<SocketHandle>,

    /// Active TCP listeners.
    ///
    /// These are registered here so that they can be polled to accept incoming connections
    /// without an explicit accept command: internally accepted connections are stored in
    /// a queue in the state, and the accept command just dequeues and returns the first
    /// ready one.
    tcp_listeners: BTreeMap<socket_impl::tcp::ListenerHandle, socket_impl::tcp::TcpListenerState>,
    next_tcp_listener_id: usize,
}

impl Netstack {
    /// Construct a netstack with the given config and starting instant.
    ///
    /// # Panics
    ///
    /// If `ns_config.loopback` is set and smoltcp's `iface-max-addr-count` (feature flag)
    /// is less than 2.
    pub fn new(ns_config: Config, now: smoltcp::time::Instant) -> Netstack {
        let config = smoltcp::iface::Config::new(HardwareAddress::Ip);

        let mut iface = smoltcp::iface::Interface::new(
            config,
            &mut NoopCapDev::with_caps(|caps| {
                caps.max_transmission_unit = ns_config.mtu;
            }),
            now,
        );

        if ns_config.loopback {
            iface.update_ip_addrs(|addrs| {
                if !set_loopback(addrs) {
                    panic!();
                }
            });
        }

        let (tx, rx) = match ns_config.command_channel_capacity {
            Some(cap) => flume::bounded(cap),
            None => flume::unbounded(),
        };

        Netstack {
            iface,
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            command_tx: tx,
            command_rx: rx,
            config: ns_config,
            blocked_commands: Default::default(),
            pending_tcp_closes: Default::default(),
            tcp_listeners: Default::default(),
            next_tcp_listener_id: 0,
        }
    }

    /// Report the next time the netstack should be polled.
    pub fn poll_at(&mut self, now: smoltcp::time::Instant) -> Option<smoltcp::time::Instant> {
        self.iface.poll_at(now, &self.socket_set)
    }

    /// Report the amount of time until the netstack should next be polled.
    pub fn poll_delay(&mut self, now: smoltcp::time::Instant) -> Option<core::time::Duration> {
        self.iface
            .poll_delay(now, &self.socket_set)
            .map(|x| x.into())
    }

    /// Process all commands available in the command queue.
    #[tracing::instrument(skip_all)]
    pub fn process_cmds(&mut self) {
        while let Ok(cmd) = self.command_rx.try_recv() {
            self.process_one_cmd(cmd);
        }
    }

    /// Synchronously block for a single command over the channel.
    #[tracing::instrument(skip_all, fields(?timeout))]
    pub fn wait_for_cmd_blocking(
        &mut self,
        timeout: Option<core::time::Duration>,
    ) -> Result<Request, flume::RecvTimeoutError> {
        if let Some(timeout) = timeout {
            self.command_rx.recv_timeout(timeout)
        } else {
            self.command_rx
                .recv()
                .map_err(|flume::RecvError::Disconnected| flume::RecvTimeoutError::Disconnected)
        }
    }

    /// Asynchronously wait for a single command over the channel.
    #[tracing::instrument(skip_all)]
    pub fn wait_for_cmd(&self) -> impl Future<Output = Option<Request>> + use<> {
        let rx = self.command_rx.clone();

        async move { rx.recv_async().await.ok() }
    }

    /// Set the IP addresses for this interface.
    ///
    /// Loopback addresses are automatically appended if indicated by [`Config::loopback`].
    ///
    /// The return value reports whether the operation was successful: if not, it was
    /// because there wasn't enough storage configured in smoltcp's feature flags for the
    /// number of submitted interface IPs.
    pub fn direct_set_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) -> bool {
        const fn full_prefix_len(is_ipv4: bool) -> u8 {
            if is_ipv4 { 32 } else { 128 }
        }

        let mut ok = true;

        self.iface.update_ip_addrs(|stored_ips| {
            stored_ips.clear();

            for ip in ips.into_iter() {
                let cidr = smoltcp::wire::IpCidr::new(ip.into(), full_prefix_len(ip.is_ipv4()));

                if stored_ips.push(cidr).is_err() {
                    ok = false;
                    break;
                }
            }

            if ok && self.config.loopback {
                ok = ok && set_loopback(stored_ips);
            }
        });

        ok
    }

    /// Process a single command.
    #[tracing::instrument(skip_all, fields(?command, ?handle))]
    pub fn process_one_cmd(
        &mut self,
        Request {
            command,
            handle,
            resp,
        }: Request,
    ) {
        let cmd_resp = match command {
            Command::StackControl(cmd) => self.process_stack_control(cmd),
            Command::Udp(udp) => self.process_udp(udp, handle),
            Command::TcpStream(tcp) => self.process_tcp_stream(tcp, handle),
            Command::TcpListen(listen) => self.process_tcp_listen(listen, handle),
            Command::Raw(raw) => self.process_raw(raw, handle),
        };
        tracing::trace!(?cmd_resp, "command processed");

        match cmd_resp {
            Response::WouldBlock { command, handle } => {
                self.blocked_commands.push_back(Request {
                    command,
                    handle,
                    resp,
                });
            }
            otherwise => {
                if let Response::Error(e) = &otherwise {
                    tracing::debug!(error = %e, "command error");
                }

                if let Err(resp) = resp.send(otherwise) {
                    tracing::debug!(resp = ?resp.0, "response channel closed");
                }
            }
        }
    }

    /// Poll the lower device to send and receive packets, and attempt to complete any
    /// blocked socket commands.
    ///
    /// Returns whether there were any updates to socket state.
    #[tracing::instrument(skip_all, fields(%now))]
    pub fn poll_device_io(
        &mut self,
        now: smoltcp::time::Instant,
        dev: &mut impl smoltcp::phy::Device,
    ) -> bool {
        use smoltcp::iface::{PollIngressSingleResult, PollResult};

        // Goal of this function: complete all _synchronously_ available work given what is queued
        // in the underlying device and the netstack state. It may be a long time until this
        // function is called again, so leaving any available work for the next iteration could
        // potentially stall out sockets with I/O in flight until the next poll.
        //
        // It requires a bit of care to determine when it's possible that the netstack made
        // progress and should try to communicate with the lower dev. Specifically, while (as of
        // smoltcp 0.12) packet egress does not itself perform loopback (outgoing packets are always
        // emitted to the underlying device, even if the address belongs to this node or a route
        // points back at us), it's possible that `dev` could synchronously perform loopback after
        // egressing packets, i.e. they would immediately (synchronously) become available for
        // ingress again. This means that after we perform egress and any sockets make progress, we
        // need to try ingress. And after any ingress, TCP state machines may have (synchronously)
        // made progress and want to emit packets -- hence, we need to poll egress again.
        //
        // This is why this function is structured as a loop: we need to keep polling until both
        // ingress and egress report that they are done and no sockets have changed state.
        // Unfortunately poll_egress is O(n) in the number of sockets, but that's an unavoidable
        // cost of correctness given the design of smoltcp.

        let mut changed = false;

        self.pump_waiters();

        'outer: loop {
            let mut changed_this_iter = false;

            let span_ingress = tracing::trace_span!("ingress");

            span_ingress.in_scope(|| {
                loop {
                    match self
                        .iface
                        .poll_ingress_single(now, dev, &mut self.socket_set)
                    {
                        PollIngressSingleResult::None => {
                            break;
                        }
                        PollIngressSingleResult::PacketProcessed => {}
                        PollIngressSingleResult::SocketStateChanged => {
                            changed = true;
                            changed_this_iter = true;

                            tracing::trace!("socket state changed");
                        }
                    }
                }
            });

            if changed_this_iter {
                // TODO(npry): need to validate through more thorough inspection of smoltcp
                //  source, but I don't _think_ the below comment is true: since receive()
                //  provides a TxToken, TCP devices should actually not need to be pumped. We
                //  may still want to call pump_blocked_commands to ready receives. Leaving
                //  this in for now as a conservative measure to ensure correctness, even if
                //  it costs a bit of performance.

                // Ingress can cause egress: TCP state machines may have advanced and want to send
                // packets now.
                //
                // Also unblocks any sockets that were waiting for a recv.
                self.pump_waiters();
            }

            let _span = tracing::trace_span!("egress").entered();

            match self.iface.poll_egress(now, dev, &mut self.socket_set) {
                PollResult::SocketStateChanged => {
                    changed = true;
                    tracing::trace!("socket state changed");

                    // Egress may have opened capacity in packet buffers for
                    // e.g. pending TCP or UDP sends, which we may be able to complete + send now.
                    //
                    // Need to fall through to the top of the loop in this case to ensure that
                    // if the underlying device synchronously looped back any packets, they're
                    // ingressed and processed by any waiting sockets.
                    self.pump_waiters();
                }
                PollResult::None => break 'outer,
            }
        }

        if changed {
            self.drain_tcp_closes();
        }

        changed
    }

    /// Poll the device for all synchronously-available packets and process them.
    ///
    /// The return value indicates whether packets were consumed and if sockets made
    /// progress:
    ///
    /// - `Poll::Pending`: no packets were processed because we were waiting for them to
    ///   arrive from `dev.
    /// - `Poll::Ready(false)`: we received packets but socket state did not make progress
    /// - `Poll::Ready(true)`: we received packets and socket state _did_ make progress
    ///
    /// When this function returns, it is guaranteed that all packets currently available to
    /// receive from `dev` have been processed.
    #[tracing::instrument(skip_all, fields(%now), ret, level = "trace")]
    pub fn poll_device_ingress_async(
        &mut self,
        cx: &mut core::task::Context<'_>,
        now: smoltcp::time::Instant,
        mut dev: Pin<&mut (impl AsyncWakeDevice + smoltcp::phy::Device + Unpin)>,
    ) -> Poll<bool> {
        let mut changed = false;
        let mut polled_successfully = false;

        loop {
            match dev.as_mut().poll_rx(cx) {
                Poll::Ready(()) => {
                    polled_successfully = true;
                }
                Poll::Pending => {
                    // If we get a pending now but we have already polled successfully, don't return
                    // pending (we need to report that we made progress).
                    return if polled_successfully {
                        Poll::Ready(changed)
                    } else {
                        Poll::Pending
                    };
                }
            }

            let _span = tracing::trace_span!("poll_ingress_single").entered();
            match self
                .iface
                .poll_ingress_single(now, dev.as_mut().get_mut(), &mut self.socket_set)
            {
                PollIngressSingleResult::None => {
                    break;
                }
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => {
                    changed = true;
                    tracing::trace!("socket state changed");
                }
            }
        }

        if changed {
            // TODO(npry): need to validate through more thorough inspection of smoltcp
            //  source, but I don't _think_ the below comment is true: since receive()
            //  provides a TxToken, TCP devices should actually not need to be pumped. We may
            //  still want to call pump_blocked_commands to ready receives. Leaving this in
            //  for now as a conservative measure to ensure correctness, even if it costs a
            //  bit of performance.

            // Ingress can cause egress: TCP state machines may have advanced and want to send
            // packets now.
            //
            // Also unblocks any sockets that were waiting for a recv.
            self.pump_waiters();
        }

        Poll::Ready(changed)
    }

    /// Send all packets the netstack wants to transmit on the network.
    ///
    /// Returns:
    ///
    /// - `Poll::Pending` if _no_ packets could be sent because `dev` wasn't ready (if
    ///   [`AsyncWakeDevice::poll_tx`] returns `Poll::Pending`)
    /// - `Poll::Ready(false)` if `dev` was ready but no packets needed to be sent
    /// - `Poll::Ready(true)` if `dev` was ready and packets were sent
    #[tracing::instrument(skip_all, fields(%now), ret, level = "trace")]
    pub fn poll_device_egress_async(
        &mut self,
        cx: &mut core::task::Context<'_>,
        now: smoltcp::time::Instant,
        mut dev: Pin<&mut (impl AsyncWakeDevice + smoltcp::phy::Device + Unpin)>,
    ) -> Poll<bool> {
        core::task::ready!(dev.as_mut().poll_tx(cx));

        match self
            .iface
            .poll_egress(now, dev.as_mut().get_mut(), &mut self.socket_set)
        {
            PollResult::SocketStateChanged => {
                tracing::trace!("socket state changed");

                // Egress may have opened capacity in packet buffers for
                // e.g. pending TCP or UDP sends, which we may be able to complete + send now.
                self.pump_waiters();

                Poll::Ready(true)
            }
            PollResult::None => Poll::Ready(false),
        }
    }

    /// Attempt to make progress on internal state that is blocking on I/O.
    ///
    /// Calls [`Netstack::pump_blocked_commands`] and [`Netstack::pump_tcp_accept`].
    #[tracing::instrument(skip_all, level = "trace")]
    fn pump_waiters(&mut self) {
        // Pump accept first, then commands: blocked commands will have tried to run once, so they
        // will have created any listeners already (i.e. they can't affect the TCP accept loop).
        // Accepts however can unblock waiting commands.
        self.pump_tcp_accept();
        self.pump_blocked_commands();
    }

    /// Reprocess all blocked socket commands.
    ///
    /// This is `O(n)` in the number of socket commands in the queue: it attempts to run
    /// all of them. Any that return [`Command::WouldBlock`] are requeued as normal.
    #[tracing::instrument(skip_all, level = "trace")]
    fn pump_blocked_commands(&mut self) {
        // NB: we pop_front here and push_back in process_one_cmd: since we're taking len()
        // elements, we see everything that is currently in the deque exactly once, no matter
        // how many of them end up still blocked and pushed onto the back.
        for _ in 0..self.blocked_commands.len() {
            let cmd = self.blocked_commands.pop_front().unwrap();
            self.process_one_cmd(cmd);
        }
    }

    /// Attempt to send and receive packets on `dev`.
    ///
    /// The future becomes ready when `dev` sends or receives packets on the network. All
    /// synchronously-available network I/O is always performed.
    ///
    /// Assumes that alarms are handled separately and that `now` does not advance
    /// over the course of the polled future.
    pub fn wait_io_async<'stack, 'dev, D>(
        &'stack mut self,
        now: smoltcp::time::Instant,
        dev: &'dev mut D,
    ) -> IoPoller<'stack, 'dev, D>
    where
        D: AsyncWakeDevice + smoltcp::phy::Device + Unpin,
    {
        IoPoller {
            stack: self,
            now,
            egress_done: false,
            dev: Pin::new(dev),
        }
    }
}

/// A future that becomes ready when the contained `smoltcp::phy::Device` sends or receives
/// packets on the network.
///
/// The future always completes _all_ synchronously-available network I/O, i.e. it polls
/// until `dev.poll_rx` and `dev.poll_tx` return `Poll::Pending`, and/or until the netstack
/// reports that there are no more packets to be sent.
///
/// # Cancel safety
///
/// This future is completely cancel-safe.
pub struct IoPoller<'stack, 'dev, D> {
    stack: &'stack mut Netstack,
    /// Whether egress has returned `Poll::Ready(false)`, indicating that it is not waiting
    /// for transmit capacity in `dev` but just has no more work to do with
    /// currently-available data.
    ///
    /// This state should not change with repeated calls to `poll` because socket commands
    /// are the only reason `smoltcp` calls `dev.transmit()`, and we don't expect any new
    /// commands to be processed while this future is being `poll`ed.
    ///
    /// We don't store a similar flag for ingress because ingress readiness is controlled
    /// by the network: if new packets arrive between calls to `poll`, `poll_ingress` may
    /// return `Poll::Ready(true)` where it had previously returned `Poll::Ready(false)`.
    ///
    /// By contrast, while send capacity may become available in the future
    /// (`Poll::Pending` -> `Poll::Ready(_)`), having _things to send_ (`Poll::Ready(true)`)
    /// will not arise from a `Poll::Ready(false)` state without commands being processed.
    egress_done: bool,

    /// The current instant to use while polling this future.
    ///
    /// Alarms (e.g. for TCP retransmit) must be set externally.
    now: smoltcp::time::Instant,

    dev: Pin<&'dev mut D>,
}

impl<D> Future for IoPoller<'_, '_, D>
where
    D: AsyncWakeDevice + smoltcp::phy::Device + Unpin,
{
    type Output = ();

    #[tracing::instrument(skip_all, fields(%self.now), ret, level = "trace")]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Logic here: future resolves when _either_ egress or ingress has made progress.
        // If neither makes forward progress (either because pending or nothing to do), return
        // pending.

        let Self {
            now,
            stack,
            dev,
            egress_done,
            ..
        } = self.get_mut();

        stack.pump_waiters();

        let now = *now;

        let mut ingress_pending = false;
        let mut egress_pending = false;
        let mut progress_made = false;

        while !(ingress_pending && (*egress_done || egress_pending)) {
            tracing::trace_span!("poll_loop", ingress_pending, egress_done, egress_pending);

            if !ingress_pending {
                match stack.poll_device_ingress_async(cx, now, dev.as_mut()) {
                    // `dev` doesn't have any packets to receive
                    Poll::Pending => ingress_pending = true,
                    // `dev` received packets but no sockets made progress. This means that
                    // `dev` is completely drained, so polling ingress again should return
                    // `Poll::Pending`.
                    Poll::Ready(false) => {
                        ingress_pending = true;
                        egress_pending = false;
                    }
                    // We received packets and socket state was updated as a result. Reset
                    // egress_pending as well to cover the possibility that successful receives
                    // made transmit capacity available (loopback case).
                    Poll::Ready(true) => {
                        ingress_pending = false;
                        egress_pending = false;
                        progress_made = true;
                    }
                }
            }

            if !(*egress_done || egress_pending) {
                match stack.poll_device_egress_async(cx, now, dev.as_mut()) {
                    // `dev` isn't ready to accept transmits, don't bother trying egress again this
                    // poll.
                    Poll::Pending => egress_pending = true,
                    // Not blocked, we just have no packets to send. Don't bother polling egress
                    // again, we should not be able to make progress.
                    Poll::Ready(false) => {
                        *egress_done = true;
                        egress_pending = false;
                    }
                    // We successfully sent packet(s). Reset ingress_pending as well to cover
                    // possibility of synchronous loopback.
                    Poll::Ready(true) => {
                        egress_pending = false;
                        ingress_pending = false;
                        progress_made = true;
                    }
                }
            }
        }

        if progress_made {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn set_loopback<const N: usize>(ips: &mut heapless::Vec<smoltcp::wire::IpCidr, N>) -> bool {
    if ips.capacity() < 2 {
        return false;
    }

    if ips
        .push(smoltcp::wire::IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .is_err()
    {
        return false;
    }

    if ips
        .push(smoltcp::wire::IpCidr::new(
            IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1),
            128,
        ))
        .is_err()
    {
        return false;
    }

    true
}
