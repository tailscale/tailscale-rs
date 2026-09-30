use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message},
};
use netstack::{
    HasChannel,
    netcore::{Channel, NetstackControl},
};
use tokio::sync::Mutex;
use ts_dataplane::async_tokio::{FromOverlay, Rx, ToOverlay, Tx};
use ts_packet::PacketMut;
use ts_transport::OverlayTransportId;

use crate::{Error, env::Env, task::Task};

pub struct NetstackActor {
    channel: Channel,
}

impl kameo::Actor for NetstackActor {
    type Args = (
        Env,
        netstack::netcore::Config,
        OverlayTransportId,
        Tx<FromOverlay>,
        Arc<Mutex<Rx<ToOverlay>>>,
    );
    type Error = Error;

    async fn on_start(
        (env, config, id, netstack_up, netstack_down): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        let (
            mut netstack,
            netstack::WakingPipe {
                rx: mut netstack_down_rx,
                tx: netstack_down_tx,
            },
        ) = netstack::piped(config);
        let channel = netstack.command_channel();

        Task::spawn_link(&slf, async move {
            netstack.run_tokio().await;
        })
        .await;

        Task::spawn_link(&slf, async move {
            while let Some(buf) = netstack_down_rx.recv_async().await {
                if netstack_up.send((id, vec![buf.to_vec().into()])).is_err() {
                    break;
                }
            }

            tracing::warn!("netstack downlink shut down!");
        })
        .await;

        Task::spawn_link(&slf, async move {
            // NetstackActor is supervised, so the same netstack down channel may be handed to
            // another actor instance if this one panics. We hold this mutex open indefinitely,
            // relying on the Drop of this future to clean it up when the owning joinset drops.
            let mut netstack_down = netstack_down.lock().await;

            while let Some(bufs) = netstack_down.recv().await {
                for buf in bufs {
                    let buf: PacketMut = buf;
                    netstack_down_tx.send_async(buf.as_ref()).await;
                }
            }

            tracing::warn!("netstack uplink shut down!");
        })
        .await;

        env.register(None, &slf).await?;

        Ok(Self { channel })
    }
}

/// Get a netstack command channel.
#[derive(Debug, Copy, Clone)]
pub struct GetChannel;

impl Message<GetChannel> for NetstackActor {
    type Reply = (Channel,);

    async fn handle(
        &mut self,
        _: GetChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        (self.channel.clone(),)
    }
}

impl Message<Arc<ts_control::StateUpdate>> for NetstackActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(self_node) = &msg.node else {
            return;
        };

        tracing::debug!(new_tailnet_ips = ?self_node.tailnet_address);

        if let Err(e) = self
            .channel
            .set_ips([
                self_node.tailnet_address.ipv4.addr().into(),
                self_node.tailnet_address.ipv6.addr().into(),
            ])
            .await
        {
            tracing::error!(error = %e, "setting netstack ips");
        }
    }
}
