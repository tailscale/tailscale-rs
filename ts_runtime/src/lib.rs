#![doc = include_str!("../README.md")]

extern crate ts_netstack_smoltcp as netstack;

use core::time::Duration;
use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    mailbox::Signal,
};
use netstack::netcore::Channel;
use tokio::sync::watch;

use crate::{
    control_runner::ControlRunner, dataplane::DataplaneActor, multiderp::Multiderp,
    netstack_actor::NetstackActor,
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
mod route_updater;
mod src_filter;
mod stunner;

pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use registry::Registry;

use crate::peer_tracker::PeerTracker;

/// Wait for all of the listed [`ActorRef`]s to start, ensuring they haven't failed.
///
/// TODO(npry): we only do this this way because we don't currently have a supervision tree and any
/// of these actors failing to start means that the runtime is permanently compromised. In the
/// future, it should not be a fatal error to start up the runtime if your underlay network is
/// offline, where it currently is because e.g. control will fail its on_start if it can't connect,
/// so it will just be dead forever, making your runtime unusable.
///
/// So long as we're lacking the supervision functionality, it's better to fail early/fast like this
/// and have it take down the whole runtime before it starts rather than living with a
/// silently-degraded one; the actors being dead would only be surfaced later when something tried
/// to talk to them.
macro_rules! try_join_startup {
    ($([$($optaref:ident)*] $(,)?)? $($aref:ident),* $(,)?) => {
        {
            tokio::try_join![
                $(
                    $(
                        match $optaref.as_ref() {
                            Some(aref) => {
                                Box::pin(map_startup_result(aref)) as core::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>
                            },
                            None => {
                                Box::pin(core::future::ready(Ok(()))) as core::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>
                            }
                        },
                    )*
                )?
                $(
                    map_startup_result(&$aref),
                )*
            ]
        }
    }
}

async fn map_startup_result<A>(aref: &ActorRef<A>) -> Result<(), Error>
where
    A: kameo::Actor,
    A::Error: core::error::Error,
{
    aref.wait_for_startup_with_result(|r| {
        r.map_err(|e| {
            // TODO(npry): due to https://github.com/tqwewe/kameo/pull/340, we _must not_ access
            // `e`'s internals (via Debug, Display, or a field access) in this closure scope if it's
            // a panic error or it will deadlock this thread. `Error::from` upholds this invariant
            // (and drops the error, so it won't cause the issue later on), but we don't want to
            // print it as part of this trace for now.
            tracing::error!(actor = ?aref, "startup for actor failed");

            Error::from(e).with_actor_info(aref.clone())
        })
    })
    .await
}

/// The runtime for a tailscale device.
pub struct Runtime {
    /// Reference to the control actor.
    pub control: ActorRef<ControlRunner>,
    dataplane: ActorRef<DataplaneActor>,
    netstack: WeakActorRef<NetstackActor>,
    /// Reference to the peer tracker for peer lookups.
    pub peer_tracker: WeakActorRef<PeerTracker>,
    env: Env,
    shutdown: watch::Sender<bool>,
}

impl Runtime {
    /// Spawn a new runtime with the given parameters for connecting to a tailnet.
    pub async fn spawn(
        config: ts_control::Config,
        auth_key: Option<String>,
        keys: ts_keys::NodeState,
    ) -> Result<Self, Error> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let env = Env::new(keys, shutdown_rx);

        let dataplane = DataplaneActor::spawn(env.clone());

        let (netstack_id, netstack_up, netstack_down) =
            dataplane.ask(dataplane::NewOverlayTransport).await?;

        let multiderp = Multiderp::spawn((env.clone(), dataplane.clone()));

        let rt_upd =
            route_updater::RouteUpdater::spawn((multiderp.clone(), env.clone(), netstack_id));
        let pf_upd = packetfilter::PacketfilterUpdater::spawn(env.clone());
        let src_upd = src_filter::SourceFilterUpdater::spawn(env.clone());
        let stunner = stunner::Stunner::spawn(env.clone());

        let netmon = ts_netmon::platform_mon()
            .map(|mon| netmon::NetmonActor::spawn((env.clone(), Arc::new(mon))));

        let peer_tracker = PeerTracker::spawn(env.clone());

        let netstack =
            NetstackActor::spawn((env.clone(), Default::default(), netstack_up, netstack_down));

        let control = ControlRunner::spawn(control_runner::Params {
            config,
            auth_key,
            env: env.clone(),
        });

        // Construct the Runtime _before_ awaiting all actor startups so we get the cleanup in its
        // Drop for free.
        let rt = Self {
            control: control.clone(),
            dataplane: dataplane.clone(),
            peer_tracker: peer_tracker.downgrade(),
            netstack: netstack.downgrade(),
            env,
            shutdown: shutdown_tx,
        };

        tracing::trace!("waiting for actors to finish starting");
        try_join_startup![
            [netmon],
            dataplane,
            rt_upd,
            pf_upd,
            src_upd,
            stunner,
            peer_tracker,
            netstack,
            control,
        ]?;
        tracing::trace!("all root actors started ok");

        Ok(rt)
    }

    /// Get a channel to send commands to the netstack.
    pub async fn channel(&self) -> Result<Channel, Error> {
        let (channel,) = self
            .netstack
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(netstack_actor::GetChannel)
            .await?;

        Ok(channel)
    }

    /// Attempt to shut down the runtime gracefully.
    ///
    /// Returns false if the shutdown timed out. It is still shut down if it timed out, just
    /// more violently and with possible resource leaks.
    pub async fn graceful_shutdown(self, timeout: Option<Duration>) -> bool {
        self.shutdown.send_replace(true);

        async fn _shutdown_all(runtime: Runtime) {
            // See the note in `Drop` for why we only need to stop these actors to bring down the
            // whole runtime.

            let _ignore = runtime.control.stop_gracefully().await;
            let _ignore = runtime.dataplane.stop_gracefully().await;
            let _ignore = runtime.env.bus.stop_gracefully().await;
            let _ignore = runtime.env.scheduler.stop_gracefully().await;

            tokio::join![
                runtime.control.wait_for_shutdown(),
                runtime.dataplane.wait_for_shutdown(),
                runtime.env.bus.wait_for_shutdown(),
                runtime.env.scheduler.wait_for_shutdown(),
            ];
        }

        let fut = _shutdown_all(self);

        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, fut).await.is_ok(),
            None => {
                fut.await;
                true
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // We must have already run `graceful_shutdown`: on the happy path, this does nothing, but
        // if it timed out, we need to make sure the actors are dead so we don't leak them and their
        // dependents.
        if *self.shutdown.borrow() {
            self.control.kill();
            self.dataplane.kill();
            self.env.bus.kill();
            self.env.scheduler.kill();
            return;
        }

        self.shutdown.send_replace(true);

        // Actors shut down when the last ActorRef to them is dropped (as nothing can send them
        // messages anymore). If we don't hold an ActorRef in Runtime, in general the only thing
        // that has one is the MessageBus, which each actor subscribes to for a subset of messages.
        // Hence, if we shut down the bus, most actors die as well.

        // First shut down the actors we have an ActorRef to:
        try_shutdown(&self.control);
        try_shutdown(&self.dataplane);

        // Then shutdown the message bus, stopping the rest of the actors:
        try_shutdown(&self.env.bus);
        try_shutdown(&self.env.scheduler);
    }
}

fn try_shutdown(a: &ActorRef<impl kameo::Actor>) {
    if let Err(e) = a.mailbox_sender().try_send(Signal::Stop) {
        tracing::error!(error = %e, "graceful shutdown failed, killing actor");
        a.kill();
    }
}
