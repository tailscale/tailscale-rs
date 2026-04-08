use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_bart::{RoutingTable, Table};
use ts_keys::NodePublicKey;

use crate::{Error, env::Env, peer_tracker::PeerState};

pub struct SourceFilterUpdater {
    env: Env,
}

impl kameo::Actor for SourceFilterUpdater {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<PeerState>(&slf).await?;

        Ok(Self { env })
    }
}

#[derive(Clone)]
pub struct SourceFilterState(pub Arc<Table<NodePublicKey>>);

impl Message<PeerState> for SourceFilterUpdater {
    type Reply = ();

    async fn handle(&mut self, state_update: PeerState, _ctx: &mut Context<Self, Self::Reply>) {
        let mut src_filter = Table::default();
        for (nodekey, node) in state_update.peers.iter() {
            for route in node.accepted_routes.iter() {
                src_filter.insert(route.to_owned(), *nodekey);
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
