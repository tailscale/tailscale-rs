use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_bart::{RoutingTable, Table};
use ts_transport::PeerId;

use crate::{Error, env::Env, peer_tracker::PeerState};

pub struct SourceFilterUpdater {
    env: Env,
}

impl kameo::Actor for SourceFilterUpdater {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self { env })
    }
}

#[derive(Clone)]
pub struct SourceFilterState(pub Arc<Table<PeerId>>);

impl Message<Arc<PeerState>> for SourceFilterUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<PeerState>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let mut src_filter = Table::default();

        for (id, node) in state_update.peers.peers() {
            for route in node.accepted_routes.iter() {
                src_filter.insert(route.to_owned(), *id);
            }
        }

        tracing::trace!(updated_source_filter = ?src_filter);

        if let Err(e) = self
            .env
            .publish(SourceFilterState(Arc::new(src_filter)))
            .await
        {
            tracing::error!(error = %e, "publishing source filter state");
        }
    }
}
