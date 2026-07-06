#![doc = include_str!("../README.md")]

extern crate ts_netstack_smoltcp as netstack;

use std::sync::Arc;

use kameo::message::Context;
use tokio::sync::Mutex;

use crate::{
    control_runner::ControlRunner, dataplane::DataplaneActor, env::RegForwarded,
    multiderp::Multiderp, netstack_actor::NetstackActor, peer_tracker::PeerTracker,
};

/// Control runner.
pub mod control_runner;
mod dataplane;
mod derp_latency;
mod env;
mod error;
mod multiderp;
mod netmon;
mod netstack_actor;
mod packetfilter;
pub mod peer_tracker;
mod registry;
mod retained_bus;
mod route_updater;
mod src_filter;
mod stunner;
mod task;

pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use kameo::actor::{ActorRef, Spawn};
pub use registry::Registry;
pub use task::{ErasedTask, Task};

/// The runtime for a tailscale device.
pub struct Runtime {
    env: Env,
}

/// Configuration for starting a [`Runtime`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The control configuration to use.
    pub control_config: ts_control::Config,
    /// The auth key to use to connect to the control server.
    pub auth_key: Option<String>,
    /// The keys to use.
    pub keys: ts_keys::NodeState,
}

impl kameo::Actor for Runtime {
    type Error = Error;
    type Args = Config;

    async fn on_start(config: Config, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let env = Env::new(config.keys);

        env.bus.link(&slf).await;
        env.scheduler.link(&slf).await;
        env.registry.link(&slf).await;

        #[cfg(feature = "console")]
        {
            // Runs detached.
            if let Err(e) =
                kameo::console::serve((core::net::Ipv4Addr::new(127, 0, 0, 1), 9999)).await
            {
                tracing::error!(error = %e, "console died");
            };
        }

        DataplaneActor::supervise(&slf, env.clone()).spawn().await;

        let (netstack_id, netstack_up, netstack_down) = env
            .ask::<DataplaneActor, _>(None, dataplane::NewOverlayTransport, true)
            .await?;

        Multiderp::supervise(&slf, env.clone()).spawn().await;

        route_updater::RouteUpdater::supervise(&slf, (env.clone(), netstack_id))
            .spawn()
            .await;
        packetfilter::PacketfilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        src_filter::SourceFilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        stunner::Stunner::supervise(&slf, env.clone()).spawn().await;

        if let Some(mon) = ts_netmon::platform_mon() {
            netmon::NetmonActor::supervise(&slf, (env.clone(), Arc::new(mon)))
                .spawn()
                .await;
        }

        PeerTracker::supervise(&slf, env.clone()).spawn().await;

        NetstackActor::supervise(
            &slf,
            (
                env.clone(),
                Default::default(),
                netstack_up,
                Arc::new(Mutex::new(netstack_down)),
            ),
        )
        .spawn()
        .await;

        ControlRunner::supervise(
            &slf,
            control_runner::Params {
                config: config.control_config,
                auth_key: config.auth_key,
                env: env.clone(),
            },
        )
        .spawn()
        .await;

        // Actors we forward messages for:
        env.wait::<ControlRunner>(None).await?;
        env.wait::<NetstackActor>(None).await?;
        env.wait::<PeerTracker>(None).await?;

        Ok(Self { env })
    }
}

macro_rules! forward {
    ($actor:ty, $($msg:ty),* $(,)?) => {
        $(
            pub use $msg;

            impl kameo::message::Message<$msg> for Runtime {
                type Reply = RegForwarded<$actor, $msg>;

                async fn handle(
                    &mut self,
                    msg: $msg,
                    ctx: &mut Context<Self, Self::Reply>,
                ) -> RegForwarded<$actor, $msg> {
                    self.env.forward(ctx, None, msg).await
                }
            }
        )*
    };
}

forward!(NetstackActor, netstack_actor::GetChannel);
forward!(
    ControlRunner,
    control_runner::Ipv4,
    control_runner::Ipv6,
    control_runner::SelfNode,
    control_runner::AuthUrl,
);
forward!(
    PeerTracker,
    peer_tracker::PeerByName,
    peer_tracker::PeerByTailnetIp,
    peer_tracker::PeerByAcceptedRoute
);
