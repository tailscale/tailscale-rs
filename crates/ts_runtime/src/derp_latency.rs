use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_derp::RegionId;

use crate::{Error, env::Env, kv::KvStore, multiderp::DerpMapUpdate};

pub(crate) const KV_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("derp_latency");

/// The region with the lowest measured latency, if any.
pub(crate) fn preferred_region(store: &KvStore, owner: ts_kv_store::Owner) -> Option<RegionId> {
    store.DerpLatency.with_iter(owner, |it| {
        it.min_by(|(a_id, a), (b_id, b)| a.total_cmp(b).then(a_id.cmp(b_id)))
            .map(|(id, _)| *id)
    })
}

pub struct DerpLatencyMeasurer {
    env: Env,
}

impl kameo::Actor for DerpLatencyMeasurer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<DerpMapUpdate>(&slf).await?;
        env.register(None, &slf).await?;

        tracing::trace!("derp latency measurer running");

        Ok(Self { env })
    }
}

impl Message<DerpMapUpdate> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        _: DerpMapUpdate,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::trace!("new derp map: beginning measurement");

        let derp_map: ts_control::DerpMap = self.env.kv_store().DerpMap.with_iter(KV_OWNER, |it| {
            it.map(|(id, region)| (*id, region.clone())).collect()
        });
        // TODO(nrc): would be nice for this to use the kv store directly so we don't need to clone the derp map.
        let latencies = ts_netcheck::measure_derp_map(&derp_map, &Default::default()).await;

        tracing::trace!(?latencies, "measurement complete");

        let mut txn = self.env.kv_store().begin_transaction(KV_OWNER);
        txn.DerpLatency.clear();
        for result in latencies {
            txn.DerpLatency
                .insert(result.id, result.latency.as_secs_f64());
        }
        txn.commit().unwrap();
    }
}
