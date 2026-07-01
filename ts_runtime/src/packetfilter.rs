use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};

use crate::{Error, env::Env};

pub struct PacketfilterUpdater {
    env: Env,
    pf_state: ts_packetfilter::CheckingFilter<
        ts_packetfilter::HashbrownFilter,
        ts_bart_packetfilter::BartFilter,
    >,
}

#[derive(Clone)]
pub struct PacketFilterState(pub Arc<dyn ts_packetfilter::Filter + Send + Sync>);

impl kameo::Actor for PacketfilterUpdater {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self {
            env,
            pf_state: Default::default(),
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for PacketfilterUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some((pf_ruleset, pf_map)) = &state_update.packetfilter else {
            return;
        };

        ts_packetfilter_state::apply_update(&mut self.pf_state, pf_ruleset.clone(), pf_map);

        tracing::trace!(updated_packet_filter = ?self.pf_state.0);

        if let Err(e) = self
            .env
            .publish(PacketFilterState(Arc::new(self.pf_state.clone())))
            .await
        {
            tracing::error!(error = %e, "publishing packet filter state");
        }
    }
}
