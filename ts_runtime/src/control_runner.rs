use core::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use std::sync::Arc;

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::Message,
    reply::DelegatedReply,
};
use tokio::sync::watch;
use ts_control::{AsyncControlClient, Error as ControlError, Node, StateUpdate};

use crate::derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer};

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    client: AsyncControlClient,
    params: Params,

    self_node: watch::Sender<Option<Node>>,
}

/// Control runner args.
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`crate::Env`] for this actor.
    pub(crate) env: crate::Env,
}

#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        loop {
            match AsyncControlClient::check_auth(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
            )
            .await
            {
                Ok(()) => break,
                Err(ControlError::MachineNotAuthorized(u)) => {
                    tracing::info!(auth_url = %u, "please authorize this machine or pass an auth key");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let (client, stream) = AsyncControlClient::connect(
            &params.config,
            &params.env.keys,
            params.auth_key.as_deref(),
        )
        .await?;

        DerpLatencyMeasurer::spawn_link(&slf, params.env.clone()).await;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        slf.attach_stream(stream.boxed(), (), ());

        Ok(Self {
            client,
            params,
            self_node: Default::default(),
        })
    }
}

impl ControlRunner {
    fn with_self_node<F, R>(&self, f: F) -> impl Future<Output = Option<R>> + use<F, R>
    where
        F: FnOnce(&Node) -> R,
    {
        let mut sub = self.self_node.subscribe();
        let mut shutdown = self.params.env.shutdown.clone();

        async move {
            tokio::select! {
                _ = shutdown.wait_for(|x| *x) => {
                    None
                },
                node = sub.wait_for(Option::is_some) => {
                    Some(f(node.ok()?.as_ref()?))
                },
            }
        }
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let fut = self.with_self_node(|node| node.tailnet_address.ipv4.addr());

            tokio::spawn(async move {
                let ip = fut.await;
                replier.send(ip);
            });
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let fut = self.with_self_node(|node| node.tailnet_address.ipv6.addr());

            tokio::spawn(async move {
                let ip = fut.await;
                replier.send(ip);
            });
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        let (deleg, replier) = ctx.reply_sender();

        if let Some(replier) = replier {
            let node = self.with_self_node(|node| node.clone());

            tokio::spawn(async move {
                let node = node.await;
                replier.send(node)
            });
        }

        deleg
    }
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
            }

            StreamMessage::Next(msg) => {
                if let Some(node) = msg.node.as_ref() {
                    self.self_node.send_replace(Some(node.clone()));
                }

                if let Err(e) = self.params.env.publish(msg).await {
                    tracing::error!(error = %e, "publishing netmap update");
                }
            }

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated")
            }
        }
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let measurements = msg.measurement.as_ref().clone();

        let Some(result) = measurements.first() else {
            tracing::debug!("derp latency measurements empty");
            return;
        };

        let iter = measurements.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        });

        tracing::debug!(selected_region_id = ?result.id, "updating home region");

        self.client.set_home_region(result.id, iter).await;
    }
}
