use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_netcheck::RegionResult;

use crate::{Error, env::Env, multiderp::DerpMapUpdate};

#[derive(Clone, PartialEq, Eq)]
pub struct DerpLatencyMeasurement {
    pub measurement: Arc<Vec<RegionResult>>,
}

const KV_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("derp_latency");

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

        if let Err(e) = self
            .env
            .publish(DerpLatencyMeasurement {
                measurement: Arc::new(latencies),
            })
            .await
        {
            tracing::error!(error = %e, "publishing");
        };
    }
}
