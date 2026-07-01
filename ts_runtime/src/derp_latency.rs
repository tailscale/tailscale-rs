use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_netcheck::RegionResult;

use crate::{Error, env::Env};

#[derive(Clone)]
pub struct DerpLatencyMeasurement {
    pub measurement: Arc<Vec<RegionResult>>,
}

pub struct DerpLatencyMeasurer {
    env: Env,
}

impl kameo::Actor for DerpLatencyMeasurer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        tracing::trace!("derp latency measurer running");

        Ok(Self { env })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(derp_map) = &state_update.derp else {
            return;
        };

        tracing::trace!("new derp map: beginning measurement");

        let latencies = ts_netcheck::measure_derp_map(derp_map, &Default::default()).await;

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
