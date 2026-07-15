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

use crate::{Error, env::Env, multiderp::DerpTransportMap, peer_tracker::PeerState};

pub struct RouteUpdater {
    default_overlay_transport: OverlayTransportId,
    derp_transport_map: DerpTransportMap,
    peer_state: Arc<PeerState>,
    env: Env,
    /// Prevents building routes until the first `DerpTransportMap` has been processed.
    is_initialized: bool,
}

impl RouteUpdater {
    fn build_routes(&self) -> PeerRoutesInner {
        tracing::trace!(
            n_peers = self.peer_state.peers.peers().len(),
            "reconstructing routes for peer update"
        );

        let mut routes = PeerRoutesInner::default();
        if !self.is_initialized {
            tracing::debug!("not building routes, derp map unpopulated");
            return routes;
        }

        for (id, peer) in self.peer_state.peers.peers() {
            let span = tracing::trace_span!(
                "peer_update",
                peer_key = %peer.node_key,
                region = ?peer.derp_region,
                underlay_transport = tracing::field::Empty,
                peer_id = ?id,
            )
            .entered();

            let Some(region) = peer.derp_region else {
                continue;
            };

            match self.derp_transport_map.0.get(&region) {
                Some(&transport_id) => {
                    span.record("underlay_transport", tracing::field::debug(transport_id));
                    routes.underlay_routes.insert(*id, transport_id);
                }
                None => {
                    tracing::error!("no region stored in multiderp, no underlay route");
                }
            }

            tracing::trace!(routes = ?peer.accepted_routes);

            for route in &peer.accepted_routes {
                routes
                    .overlay_out_routes
                    .insert(*route, OutboundRouteAction::Wireguard(*id));
            }
        }

        routes
    }
}

impl kameo::Actor for RouteUpdater {
    type Args = (Env, OverlayTransportId);
    type Error = Error;

    async fn on_start(
        (env, default_transport): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<DerpTransportMap>(&slf).await?;

        env.register(None, &slf).await?;

        Ok(Self {
            default_overlay_transport: default_transport,
            derp_transport_map: DerpTransportMap::default(),
            peer_state: Default::default(),
            env,
            is_initialized: false,
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

#[derive(Default)]
pub struct PeerRoutesInner {
    pub underlay_routes: HashMap<PeerId, UnderlayTransportId>,
    pub overlay_out_routes: ts_bart::Table<OutboundRouteAction>,
}

impl Message<Arc<PeerState>> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        self.peer_state = msg;

        let new_routes = self.build_routes();

        if let Err(e) = self
            .env
            .publish(PeerRouteUpdate {
                inner: Arc::new(new_routes),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer route update");
        }
    }
}

impl Message<DerpTransportMap> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, msg: DerpTransportMap, _ctx: &mut Context<Self, Self::Reply>) {
        if msg.0 == self.derp_transport_map.0 {
            return;
        }

        tracing::debug!("derp transport map changed, building new routes");

        self.derp_transport_map = msg;
        self.is_initialized = true;

        let new_routes = self.build_routes();
        if let Err(e) = self
            .env
            .publish(PeerRouteUpdate {
                inner: Arc::new(new_routes),
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
