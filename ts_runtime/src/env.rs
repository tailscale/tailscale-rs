use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn},
    message::Message,
};
use kameo_actors::scheduler::Scheduler;
use tokio::sync::watch;

use crate::{Error, error::ResultExt, retained_bus::RetainedBus};

#[derive(Clone)]
pub struct Env {
    pub bus: ActorRef<RetainedBus>,
    pub scheduler: ActorRef<Scheduler>,

    pub keys: Arc<ts_keys::NodeState>,

    /// Whether the runtime is shutdown.
    ///
    /// This is provided so that actors can check whether a message send has failed because
    /// the runtime is closing, or if it's because the peer has panicked.
    ///
    /// It's not a bus message because we need a value that is guaranteed to be delivered
    /// to anyone who's interested. The bus is by definition unreliable during shutdown, so
    /// we need this independent mechanism.
    pub shutdown: watch::Receiver<bool>,
}

impl Env {
    pub fn new(keys: ts_keys::NodeState, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            bus: RetainedBus::spawn_default(),
            scheduler: Scheduler::spawn_default(),
            keys: Arc::new(keys),
            shutdown,
        }
    }

    pub async fn subscribe<M>(&self, slf: &ActorRef<impl Message<M>>) -> Result<(), Error>
    where
        M: Clone + Send + 'static,
    {
        self.bus
            .tell(crate::retained_bus::Register(slf.clone().recipient::<M>()))
            .await
            .with_actor_info(&self.bus)?;

        Ok(())
    }

    pub async fn publish<M>(&self, msg: M) -> Result<(), Error>
    where
        M: Clone + Send + 'static,
    {
        self.bus
            .tell(crate::retained_bus::Publish::retained(msg))
            .await
            .with_actor_info(&self.bus)?;

        Ok(())
    }

    pub async fn publish_noretain<M>(&self, msg: M) -> Result<(), Error>
    where
        M: Clone + Send + 'static,
    {
        self.bus
            .tell(crate::retained_bus::Publish::unretained(msg))
            .await
            .with_actor_info(&self.bus)?;

        Ok(())
    }
}
