//! The packet processing dataplane, as a tokio task.

use std::{collections::HashMap, convert::Infallible, ops::DerefMut, sync::atomic::AtomicU32};

use tokio::sync::{Mutex, mpsc};
use ts_keys::NodePublicKey;
use ts_packet::old::PacketMut;
use ts_transport::{OverlayTransportId, UnderlayTransportId};
use ts_tunnel::NodeKeyPair;

use crate::{EventResult, InboundResult, OutboundResult};

/// Queue for packets leaving the data plane "up" into an overlay transport.
pub type DataplaneToOverlay = mpsc::UnboundedSender<Vec<PacketMut>>;

/// Queue for packets entering the data plane "down" from an overlay transport.
pub type DataplaneFromOverlay = mpsc::UnboundedReceiver<Vec<PacketMut>>;

/// Queue for packets leaving the data plane "down" into an underlay transport.
pub type DataplaneToUnderlay = mpsc::UnboundedSender<(NodePublicKey, Vec<PacketMut>)>;

/// Queue for packets entering the data plane "up" from an underlay transport.
pub type DataplaneFromUnderlay = mpsc::UnboundedReceiver<(NodePublicKey, Vec<PacketMut>)>;

// TODO: wire in overlay/underlay transport traits

/// Transforms packets to make tailscale happen.
pub struct DataPlane {
    core_state: Mutex<CoreState>,
    poll_state: Mutex<PollState>,

    transports_changed: tokio::sync::Notify,

    underlay_down: DataplaneToUnderlay,
    overlay_up: DataplaneToOverlay,

    next_underlay_transport: AtomicU32,
    next_overlay_transport: AtomicU32,
}

struct CoreState {
    /// The synchronous core of the data plane.
    sync: crate::DataPlane,

    /// Queues to write packets to overlay transports.
    overlay_transports: HashMap<OverlayTransportId, DataplaneToOverlay>,
    /// Queues to write packets to underlay transports.
    underlay_transports: HashMap<UnderlayTransportId, DataplaneToUnderlay>,
}

/// State that must be held during async polling.
struct PollState {
    /// Queue for packets entering the data plane ("coming down") from overlay transports.
    from_overlay: DataplaneFromOverlay,
    /// Queue for packets entering the data plane ("coming up") from underlay transports.
    from_underlay: DataplaneFromUnderlay,
}

impl DataPlane {
    /// Create a new data plane for a wireguard node key.
    ///
    /// The caller must configure overlay/underlay output queues for the data plane to be useful,
    /// otherwise all it can do is drop packets.
    pub fn new(my_key: NodeKeyPair) -> Self {
        let (overlay_up, overlay_down) = mpsc::unbounded_channel();
        let (underlay_down, underlay_up) = mpsc::unbounded_channel();

        let sync = crate::DataPlane::new(my_key);

        Self {
            underlay_down,
            overlay_up,

            next_overlay_transport: Default::default(),
            next_underlay_transport: Default::default(),

            transports_changed: tokio::sync::Notify::new(),

            core_state: Mutex::new(CoreState {
                sync,
                overlay_transports: Default::default(),
                underlay_transports: Default::default(),
            }),

            poll_state: Mutex::new(PollState {
                from_overlay: overlay_down,
                from_underlay: underlay_up,
            }),
        }
    }

    /// Allocate a new underlay transport.
    pub async fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        DataplaneFromUnderlay,
        DataplaneToUnderlay,
    ) {
        let id = self
            .next_underlay_transport
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();

        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut rest = self.core_state.lock().await;
            rest.underlay_transports.insert(id, tx);
        }

        self.transports_changed.notify_waiters();

        (id, rx, self.underlay_down.clone())
    }

    /// Allocate a new overlay transport.
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, DataplaneToOverlay, DataplaneFromOverlay) {
        let id = self
            .next_overlay_transport
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();

        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut rest = self.core_state.lock().await;
            rest.overlay_transports.insert(id, tx);
        }

        self.transports_changed.notify_waiters();

        (id, self.overlay_up.clone(), rx)
    }

    /// Run the data plane forever, moving packets from the input queues to output queues.
    pub async fn run(&self) -> Infallible {
        loop {
            self.step().await;
        }
    }

    /// Run the data plane for a single step.
    #[tracing::instrument(skip_all)]
    pub async fn step(&self) {
        enum SelectResult {
            OverlayDown(Vec<PacketMut>),
            UnderlayUp(NodePublicKey, Vec<PacketMut>),
            TransportsChanged,
            Event,
        }

        // process in two phases:
        //
        // - SELECT: wait for underlying i/o or timer to make progress: don't lock the
        //      user-modifiable (core) state. self.transports_changed is used to break out of this
        //      state if the caller changes the underlying transports
        // - UPDATE: lock the user-modifiable state and actually write out the packets produced
        //      in the SELECT phase (if any)
        //
        // designed this way to ensure that users can add and remove transports at any time without
        // having to wait for the network or a timer to make progress (which may never happen)

        let select_result = {
            let next_event = {
                let state = self.core_state.lock().await;
                state.sync.next_event()
            };

            let mut poll_state = self.poll_state.lock().await;

            let PollState {
                from_overlay: overlay_down,
                from_underlay: underlay_up,
                ..
            } = &mut *poll_state;

            tokio::select! {
                overlay_pkts = overlay_down.recv() => {
                    let overlay_pkts = overlay_pkts.unwrap();
                    tracing::trace!(n_overlay_pkts = overlay_pkts.len());

                    SelectResult::OverlayDown(overlay_pkts)
                }

                underlay_pkts = underlay_up.recv() => {
                    let (node_key, underlay_pkts) = underlay_pkts.unwrap();
                    tracing::trace!(%node_key, n_underlay_pkts = underlay_pkts.len());

                    SelectResult::UnderlayUp(node_key, underlay_pkts)
                }

                _ = self.transports_changed.notified() => {
                    tracing::trace!("transports changed");

                    SelectResult::TransportsChanged
                }

                _ = option_sleep_until(next_event.map(Into::into)) => {
                    tracing::trace!("event");

                    SelectResult::Event
                }
            }
        };

        let mut core = self.core_state.lock().await;

        let (to_peers, to_local) = match select_result {
            SelectResult::OverlayDown(overlay_down) => {
                let OutboundResult { to_peers, loopback } =
                    core.sync.process_outbound(overlay_down);

                (Some(to_peers), Some(loopback))
            }
            SelectResult::UnderlayUp(node_key, underlay_up) => {
                if core.sync.wireguard.peer_id(node_key).is_none() {
                    core.sync.wireguard.add_peer(ts_tunnel::PeerConfig {
                        key: node_key,
                        psk: [0u8; 32].into(),
                    });
                }

                let InboundResult { to_local, to_peers } = core.sync.process_inbound(underlay_up);

                (Some(to_peers), Some(to_local))
            }
            SelectResult::Event => {
                let EventResult { to_peers } = core.sync.process_events();
                (Some(to_peers), None)
            }
            SelectResult::TransportsChanged => (None, None),
        };

        if let Some(to_peers) = to_peers {
            write_to_underlay(&core, to_peers).await;
        }

        if let Some(to_local) = to_local {
            write_to_overlay(&core, to_local).await;
        }
    }

    /// Get a mutable reference to the inner [`crate::DataPlane`].
    ///
    /// Primarily intended for mutating the routing tables.
    ///
    /// The returned value is a mutex guard, so limit how long it's held.
    pub async fn inner(&self) -> impl DerefMut<Target = crate::DataPlane> {
        let core = self.core_state.lock().await;
        tokio::sync::MutexGuard::map(core, |x| &mut x.sync)
    }
}

async fn write_to_overlay(slf: &CoreState, packets: HashMap<OverlayTransportId, Vec<PacketMut>>) {
    for (id, packets) in packets {
        if let Some(queue) = slf.overlay_transports.get(&id) {
            tracing::trace!(overlay_id = ?id, n_packets = packets.len());
            queue.send(packets).unwrap();
        }
    }
}

async fn write_to_underlay(
    slf: &CoreState,
    packets: impl IntoIterator<Item = ((UnderlayTransportId, NodePublicKey), Vec<PacketMut>)>,
) {
    for ((tid, node_key), packets) in packets {
        tracing::trace!(underlay_id = ?tid, %node_key, n_packets = packets.len());

        if let Some(queue) = slf.underlay_transports.get(&tid) {
            queue.send((node_key, packets)).unwrap();
        }
    }
}

async fn option_sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => core::future::pending().await,
    }
}
