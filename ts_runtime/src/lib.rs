//! Tailscale runtime.

extern crate ts_netstack_smoltcp as netstack;

use core::time::Duration;

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
mod netstack_actor;
mod packetfilter;
mod peer_tracker;
mod route_updater;
mod src_filter;

pub(crate) use env::Env;
pub use error::Error;

/// The runtime for a tailscale device.
pub struct Runtime {
    /// Reference to the control actor.
    pub control: ActorRef<ControlRunner>,
    dataplane: ActorRef<DataplaneActor>,
    netstack: WeakActorRef<NetstackActor>,
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

        route_updater::RouteUpdater::spawn((multiderp.clone(), env.clone(), netstack_id));
        packetfilter::PacketfilterUpdater::spawn(env.clone());
        src_filter::SourceFilterUpdater::spawn(env.clone());
        peer_tracker::PeerTracker::spawn(env.clone());

        let netstack =
            NetstackActor::spawn((env.clone(), Default::default(), netstack_up, netstack_down));

        let control = ControlRunner::spawn(control_runner::Params {
            config,
            auth_key: auth_key.map(|x| x.to_owned()),
            env: env.clone(),
        });

        Ok(Self {
            control,
            dataplane,
            netstack: netstack.downgrade(),
            env,
            shutdown: shutdown_tx,
        })
    }

    /// Get a channel to send commands to the netstack.
    pub async fn channel(&self) -> Result<Channel, Error> {
        let (channel,) = self
            .netstack
            .upgrade()
            .ok_or(Error::RuntimeState)?
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

            tokio::join![
                runtime.control.wait_for_shutdown(),
                runtime.dataplane.wait_for_shutdown(),
                runtime.env.bus.wait_for_shutdown(),
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
    }
}

fn try_shutdown(a: &ActorRef<impl kameo::Actor>) {
    if let Err(e) = a.mailbox_sender().try_send(Signal::Stop) {
        tracing::error!(error = %e, "graceful shutdown failed, killing actor");
        a.kill();
    }
}
