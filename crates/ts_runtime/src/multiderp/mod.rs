mod uniderp;

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message, StreamMessage},
};
use kameo_actors::scheduler::SetTimeout;
use ts_control::DerpRegion;
use ts_derp::RegionId;
use ts_packet::PacketMut;
use ts_transport::UnderlayTransportId;

use crate::{
    Env, Error,
    dataplane::{DataplaneActor, SendUnderlay},
    disco::SendDisco,
    kv,
    multiderp::uniderp::Uniderp,
};

/// Consumes derp map updates and spawns an actor per region that runs an underlay transport.
/// Also consumes home derp indications (for this node) to notify the relevant task that it
/// should keep the transport awake even if there is no traffic.
///
/// Other than the home task (which is always kept alive to receive packets), the transport
/// tasks keep the connection alive as long as there is traffic sent or received, and for a
/// short grace period afterward. Connections are otherwise closed not in use.
pub struct Multiderp {
    region_map: HashMap<RegionId, UnderlayTransportId>,
    env: Env,
    debounce_state: DebounceState,
}

impl kameo::Actor for Multiderp {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<SendDisco>(&slf).await?;

        env.register(None, &slf).await?;

        // Subscribe to changes in the derp map in the kv store and turn them into Kameo messages.
        // Note(nrc): it might be nice to have this functionality directly in something like
        // ts_kv_store_tokio.
        let subscriber = env.create_store_subscriber(KV_OWNER);
        env.kv_store()
            .DerpMap
            .subscribe_and_notify(&subscriber)
            .unwrap();
        let notifications = futures::stream::unfold(subscriber, async move |mut s| {
            s.recv().await.ok().map(|n| (n, s))
        });
        slf.attach_stream(notifications.boxed(), (), ());

        Ok(Self {
            env,
            region_map: Default::default(),
            debounce_state: Default::default(),
        })
    }

    async fn on_stop(
        &mut self,
        _: WeakActorRef<Self>,
        _: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.env.publish(DerpTransportMap::default()).await?;

        Ok(())
    }
}

/// Notify other actors that the derp map in the kv store has changed.
#[derive(Clone)]
pub struct DerpMapUpdate;

impl Multiderp {
    async fn ensure_all_regions(&self, slf: &ActorRef<Self>) {
        let regions: Vec<(RegionId, DerpRegion)> =
            self.env.kv_store().DerpMap.with_iter(KV_OWNER, |regions| {
                regions.map(|(id, region)| (*id, region.clone())).collect()
            });

        for (id, region) in regions {
            self.ensure_region(slf, id, region).await;
        }
    }

    #[tracing::instrument(skip_all, fields(region_id = %id))]
    async fn ensure_region(&self, slf: &ActorRef<Self>, id: RegionId, region: DerpRegion) {
        if self
            .env
            .lookup_opt::<Uniderp>(Some(Uniderp::name(id)))
            .await
            .unwrap()
            .is_some()
        {
            return;
        }

        tracing::trace!("spawn new uniderp");
        Uniderp::supervise(
            slf,
            uniderp::Args {
                env: self.env.clone(),
                region,
                region_id: id,
            },
        )
        .spawn()
        .await;
    }

    /// Trailing-edge debounce for region id -> transport id map updates.
    ///
    /// Delays these messages slightly in the interest of coalescing large quantities of updates
    /// from derp map updates and uniderp spawns to avoid repetitive, partial downstream route
    /// recomputations.
    async fn debounce_map_publish(&mut self, slf: &ActorRef<Self>) {
        const DEBOUNCE_DUR: Duration = Duration::from_millis(25);

        if self.debounce_state.publish_enqueued {
            return;
        }

        self.env
            .scheduler
            .ask(SetTimeout::new(
                slf.downgrade(),
                DEBOUNCE_DUR,
                DebouncedPublish,
            ))
            .await
            .unwrap();

        self.debounce_state.publish_enqueued = true;
    }

    async fn do_map_publish(&mut self) {
        self.env
            .publish(DerpTransportMap(Arc::new(self.region_map.clone())))
            .await
            .unwrap();

        self.debounce_state.last_publish = Some(Instant::now());
    }
}

const KV_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("multiderp");

impl Message<StreamMessage<Vec<kv::Notification>, (), ()>> for Multiderp {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Vec<kv::Notification>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        match msg {
            StreamMessage::Next(notifications) => {
                if notifications
                    .iter()
                    .any(|n| matches!(n, kv::Notification::DerpMap(_)))
                {
                    // Handle changes to the derp map and then notify other actors.
                    self.ensure_all_regions(ctx.actor_ref()).await;

                    if let Err(e) = self.env.publish(DerpMapUpdate).await {
                        tracing::error!(error = %e, "publishing derp map update");
                    }
                }
            }
            StreamMessage::Finished(()) => {
                tracing::error!("kv store subscription ended, restarting");
                ctx.stop();
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DerpTransportMap(pub Arc<HashMap<RegionId, UnderlayTransportId>>);

struct SetRegionTransportId(RegionId, Option<UnderlayTransportId>);

impl Message<SetRegionTransportId> for Multiderp {
    type Reply = ();

    async fn handle(
        &mut self,
        SetRegionTransportId(region, id): SetRegionTransportId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let pre = self.region_map.get(&region).copied();

        match id {
            Some(id) => {
                self.region_map.insert(region, id);
            }
            None => {
                self.region_map.remove(&region);
            }
        }

        let post = self.region_map.get(&region).copied();

        if pre != post {
            self.debounce_map_publish(_ctx.actor_ref()).await;
        }
    }
}

#[derive(Default)]
struct DebounceState {
    /// The last time a message was published.
    last_publish: Option<Instant>,

    /// Whether there is a publish timer currently enqueued.
    publish_enqueued: bool,
}

#[derive(Copy, Clone, Debug)]
struct DebouncedPublish;

impl Message<DebouncedPublish> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, _: DebouncedPublish, _: &mut Context<Self, Self::Reply>) {
        self.do_map_publish().await;
        self.debounce_state.publish_enqueued = false;
    }
}

impl Message<SendDisco> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, send: SendDisco, _: &mut Context<Self, Self::Reply>) {
        let Some(nodekey) = send.ep.as_derp() else {
            return;
        };

        let Some(derp_region) = self
            .env
            .kv_store()
            .Peers
            .indexes(KV_OWNER)
            .node_key
            .with(&nodekey, |_, peer| peer.derp_region)
        else {
            tracing::trace!(%nodekey, "no known peer");
            return;
        };

        let Some(derp_region) = derp_region else {
            tracing::trace!(%nodekey, "peer had no derp region");
            return;
        };

        let Some(transport_id) = self.region_map.get(&derp_region) else {
            tracing::trace!(%nodekey, ?derp_region, "derp region had no transport");
            return;
        };

        let sent = self
            .env
            .ask::<DataplaneActor, _>(
                None,
                SendUnderlay {
                    endpoint: send.ep,
                    bufs: vec![PacketMut::from(send.buf.to_vec())],
                    underlay_id: *transport_id,
                },
                true,
            )
            .await
            .unwrap();

        tracing::trace!(?sent, %nodekey, ?derp_region, "disco send result");
    }
}
