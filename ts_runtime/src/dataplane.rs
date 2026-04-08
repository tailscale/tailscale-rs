use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::mpsc;
use ts_keys::NodePublicKey;
use ts_packet::old::PacketMut;
use ts_transport::{OverlayTransportId, UnderlayTransportId};

use crate::{
    Error,
    env::Env,
    packetfilter::PacketFilterState,
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

/// Queue for packets sent from the overlay to the dataplane.
pub type OverlayToDataplane = mpsc::UnboundedSender<Vec<PacketMut>>;

/// Queue for packets entering the overlay from the dataplane.
pub type OverlayFromDataplane = mpsc::UnboundedReceiver<Vec<PacketMut>>;

/// Queue for packets leaving the underlay to the dataplane.
pub type UnderlayToDataplane = mpsc::UnboundedSender<(NodePublicKey, Vec<PacketMut>)>;

/// Queue for packets entering an underlay from the dataplane.
pub type UnderlayFromDataplane = mpsc::UnboundedReceiver<(NodePublicKey, Vec<PacketMut>)>;

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DataplaneActor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, OverlayToDataplane, OverlayFromDataplane) {
        self.dataplane.new_overlay_transport().await
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        UnderlayFromDataplane,
        UnderlayToDataplane,
    ) {
        self.dataplane.new_underlay_transport().await
    }
}

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let dataplane = Arc::new(ts_dataplane::async_tokio::DataPlane::new(
            env.keys.node_keys,
        ));

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;

        let task_dataplane = dataplane.clone();

        let task = tokio::task::spawn(async move {
            task_dataplane.run().await;
        });

        tracing::trace!("dataplane running");

        Ok(Self { dataplane, task })
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!("applying peer route update");

        let dp = &mut *self.dataplane.inner().await;
        dp.or_out.swap(msg.inner.overlay_out_routes.clone());

        dp.ur_out.table = msg.inner.underlay_routes.clone();
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
        }

        tracing::trace!("applied self route update");
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.packet_filter = msg.0;
        }

        tracing::trace!("applied new packet filter");
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.src_filter_in = msg.0;
        }

        tracing::trace!("applied new source filter");
    }
}
