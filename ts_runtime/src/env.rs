use core::any::Any;
use std::sync::Arc;

use kameo::{
    Reply,
    actor::{ActorRef, Spawn, WeakActorRef},
    error::SendError,
    message::{Context, Message},
    reply::ForwardedReply,
};
use kameo_actors::scheduler::Scheduler;
use smol_str::SmolStr;

use crate::{
    Error, ErrorKind,
    error::ResultExt,
    registry,
    registry::{Forward, Registry},
    retained_bus::RetainedBus,
};

#[derive(Clone)]
pub struct Env {
    pub bus: ActorRef<RetainedBus>,
    pub scheduler: ActorRef<Scheduler>,
    pub registry: ActorRef<Registry>,

    pub keys: Arc<ts_keys::NodeState>,
}

impl Env {
    pub fn new(keys: ts_keys::NodeState) -> Self {
        Self {
            bus: RetainedBus::spawn_default(),
            scheduler: Scheduler::spawn_default(),
            registry: Registry::spawn_default(),
            keys: Arc::new(keys),
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

    /// Register an actor in the registry under the specified `name`. If `None`, the actor is
    /// registered as the canonical actor of type `A`.
    ///
    /// If the return value is `Ok(Some(_))`, this registration replaced an existing registration
    /// for the same name.
    pub async fn register<A>(
        &self,
        name: Option<SmolStr>,
        slf: &ActorRef<A>,
    ) -> Result<Option<WeakActorRef<A>>, Error>
    where
        A: kameo::Actor,
    {
        self.registry
            .ask(registry::Register::new(name, slf))
            .await
            .with_actor_info(&self.registry)
    }

    /// Look up an actor in the registry.
    pub async fn lookup_opt<A>(
        &self,
        name: Option<SmolStr>,
    ) -> Result<Option<WeakActorRef<A>>, Error>
    where
        A: kameo::Actor + Any,
    {
        let aref = self
            .registry
            .ask(registry::Lookup::<A>::new(name))
            .await
            .with_actor_info(&self.registry)?;

        Ok(aref)
    }

    /// Look up an actor in the registry.
    ///
    /// Reports an error if the actor is in the registry but dead.
    pub async fn lookup<A>(&self, name: Option<SmolStr>) -> Result<ActorRef<A>, Error>
    where
        A: kameo::Actor + Any,
    {
        let aref = self.lookup_opt::<A>(name).await?;
        self.resolve_aref(aref)
    }

    /// Ensure the given actor exists in the registry.
    ///
    /// If it doesn't, create the actor using the given function to populate its args.
    pub async fn ensure<A, F, Fut>(
        &self,
        name: Option<SmolStr>,
        args_builder: F,
    ) -> Result<(bool, ActorRef<A>), Error>
    where
        A: kameo::Actor,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = A::Args> + Send + 'static,
    {
        let (created, aref) = self
            .registry
            .ask(registry::Ensure::new(name, args_builder))
            .await?;

        Ok((created, aref))
    }

    /// Send an ask to an actor in the registry.
    ///
    /// # Parameters
    ///
    /// - `name`: the name of the actor to send the message to. If `None`, uses the canonical actor.
    /// - `msg`: the message to send.
    /// - `wait`: whether to wait for the actor to be registered if it's not present in the
    ///   registry.
    pub async fn ask<A, M>(
        &self,
        name: Option<SmolStr>,
        mut msg: M,
        wait: bool,
    ) -> Result<<A::Reply as kameo::Reply>::Ok, Error>
    where
        A: Message<M> + Any,
        M: Send + 'static,
    {
        let mk_forward = |msg| Forward::<A, _>::new(name.clone(), msg);

        // If we aren't waiting, this just looks like `return self.registry.ask(forward).await?`
        //
        // If we are, the idea is to prefer to use `registry::Forward` to do both the lookup and
        // forward steps inside the registry (atomically from the rest of the system's perspective).
        // We could do them here, but there could be a race in between (we wouldn't know if the
        // ActorRef for a given name is still alive and owning the name by the time we call it). If
        // the forward fails, we use a lookup to determine if there has been activity on the name,
        // but we throw away the result and just retry the forward for the previously discussed
        // reasons.
        loop {
            let result = self.registry.ask(mk_forward(msg)).await;

            match result {
                Ok(x) => return Ok(x),
                Err(e) => match e.unwrap_err() {
                    SendError::ActorNotRunning(m) if wait => {
                        msg = m;
                    }
                    e => {
                        return Err(e).with_actor_info(&self.registry);
                    }
                },
            }

            tracing::trace!("in ask: actor not available, wait until register");
            self.registry
                .ask(registry::Lookup::<A>::new(name.clone()).wait(true))
                .await
                .with_actor_info(&self.registry)?;
        }
    }

    /// Send a tell to an actor in the registry.
    ///
    /// The result provides no feedback about whether the actor was running or not.
    pub async fn tell<A, M>(&self, name: Option<SmolStr>, msg: M) -> Result<(), Error>
    where
        A: Message<M> + Any,
        M: Send + 'static,
    {
        self.registry
            .tell(Forward::<A, _>::new(name, msg))
            .await
            .with_actor_info(&self.registry)
    }

    /// Forward a message to an actor through the registry.
    pub async fn forward<A, M>(
        &self,
        ctx: &mut Context<impl kameo::Actor, impl Reply>,
        name: Option<SmolStr>,
        msg: M,
    ) -> RegForwarded<A, M>
    where
        A: Message<M> + Any,
        M: Send + 'static,
    {
        ctx.forward(&self.registry, Forward::<A, M>::new(name, msg))
            .await
    }

    /// Wait for a specific actor of type `A` to appear in the registry.
    pub async fn wait<A>(&self, name: Option<SmolStr>) -> Result<(), Error>
    where
        A: kameo::Actor,
    {
        self.registry
            .ask(registry::Lookup::<A>::new(name).wait(true))
            .await?;

        Ok(())
    }

    fn resolve_aref<A>(&self, aref: Option<WeakActorRef<A>>) -> Result<ActorRef<A>, Error>
    where
        A: kameo::Actor,
    {
        let aref = aref.ok_or_else(|| Error {
            kind: ErrorKind::ActorGone,
            message_ty: Some("Lookup"),
            target_actor: Some((&self.registry).into()),
        })?;

        let aref = aref.upgrade().ok_or_else(|| Error {
            kind: ErrorKind::ActorGone,
            message_ty: None,
            target_actor: Some((&aref).into()),
        })?;

        Ok(aref)
    }
}

pub type RegForwarded<A, M> =
    ForwardedReply<Forward<A, M>, registry::RegistryForward<M, <A as Message<M>>::Reply>>;
