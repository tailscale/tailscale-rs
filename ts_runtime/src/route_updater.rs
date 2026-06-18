use std::{collections::HashMap, sync::Arc};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_bart::RoutingTable;
use ts_overlay_router::{
    inbound::RouteAction as InboundRouteAction, outbound::RouteAction as OutboundRouteAction,
};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{Error, env::Env, multiderp, multiderp::Multiderp, peer_tracker::PeerState};

pub struct RouteUpdater {
    multiderp: ActorRef<Multiderp>,
    default_overlay_transport: OverlayTransportId,
    env: Env,
}

impl kameo::Actor for RouteUpdater {
    type Args = (ActorRef<Multiderp>, Env, OverlayTransportId);
    type Error = Error;

    async fn on_start(
        (multiderp, env, default_transport): Self::Args,
        actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&actor_ref).await?;
        env.subscribe::<Arc<ts_control::StateUpdate>>(&actor_ref)
            .await?;

        env.register(None, &slf).await?;

        Ok(Self {
            multiderp,
            default_overlay_transport: default_transport,
            env,
        })
    }
}

#[derive(Clone)]
pub struct SelfRouteUpdate {
    pub overlay_in_routes: Arc<ts_bart::Table<InboundRouteAction>>,
}

#[derive(Clone)]
pub struct PeerRouteUpdate {
    pub inner: Arc<PeerRoutesInner>,
}

pub struct PeerRoutesInner {
    pub underlay_routes: HashMap<PeerId, UnderlayTransportId>,
    pub overlay_out_routes: ts_bart::Table<OutboundRouteAction>,
}

impl Message<Arc<PeerState>> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!(
            n_peers = msg.peers.peers().len(),
            "reconstructing routes for peer update"
        );

        let mut overlay_out = ts_bart::Table::default();
        let mut underlay_out = HashMap::default();

        for (id, peer) in msg.peers.peers() {
            let span = tracing::trace_span!(
                "peer_update",
                peer_key = %peer.node_key,
                region = ?peer.derp_region,
                underlay_transport = tracing::field::Empty,
                peer_id = ?id,
            );

            let Some(region) = peer.derp_region else {
                tracing::trace!(parent: &span, "peer has no derp region");
                continue;
            };

            tracing::trace!(parent: &span, "ask multiderp for transport id");

            match self
                .multiderp
                .ask(multiderp::TransportIdForRegion { id: region })
                .await
            {
                Ok(Some(transport_id)) => {
                    span.record("underlay_transport", tracing::field::debug(transport_id));
                    underlay_out.insert(*id, transport_id);
                    tracing::trace!(parent: &span, "set underlay route");
                }
                Ok(None) => {
                    tracing::error!(parent: &span, "no region stored in multiderp, no underlay route");
                }
                Err(e) => {
                    tracing::error!(error = %e, "multiderp unavailable");
                }
            }

            for route in &peer.accepted_routes {
                tracing::trace!(parent: &span, %route, "routes");

                overlay_out.insert(*route, OutboundRouteAction::Wireguard(*id));
            }
        }

        if let Err(e) = self
            .env
            .publish(PeerRouteUpdate {
                inner: Arc::new(PeerRoutesInner {
                    underlay_routes: underlay_out,
                    overlay_out_routes: overlay_out,
                }),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer route update");
        }
    }
}

impl Message<Arc<ts_control::StateUpdate>> for RouteUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(node) = msg.node.as_ref() else {
            return;
        };

        let mut out = ts_bart::Table::default();

        tracing::debug!(accepted_routes = ?node.accepted_routes, "populating accepted routes");

        for &accepted_route in &node.accepted_routes {
            out.insert(
                accepted_route,
                InboundRouteAction::ToOverlay(self.default_overlay_transport),
            );
        }

        if let Err(e) = self
            .env
            .publish(SelfRouteUpdate {
                overlay_in_routes: Arc::new(out),
            })
            .await
        {
            tracing::error!(error = %e, "publishing self route update");
        }
    }
}
