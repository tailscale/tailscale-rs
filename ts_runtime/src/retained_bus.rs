use core::{
    any::{Any, TypeId},
    marker::PhantomData,
};
use std::collections::HashMap;

use kameo::{
    actor::{ActorId, Recipient},
    message::{Context, Message},
};
pub use kameo_actors::message_bus::Register;

/// A version of [`MessageBus`][kameo_actor::message_bus::MessageBus] optionally tracking retained
/// state.
///
/// [`Publish`] messages may optionally set the `retained` flag to indicate that the message should
/// be retained on the bus. When present, new [`Register`]ed actors receive the current retained
/// message immediately.
#[derive(Default, kameo::Actor)]
pub struct RetainedBus {
    subscriptions: HashMap<TypeId, SubState>,
}

#[derive(Default)]
struct SubState {
    retained: Option<Box<dyn Any + Send>>,
    recipients: HashMap<ActorId, Box<dyn Any + Send>>,
}

#[derive(Debug, Copy, Clone, Default)]
pub struct Publish<M> {
    pub message: M,
    pub retained: bool,
}

impl<M> Publish<M> {
    pub const fn new(m: M) -> Self {
        Self {
            message: m,
            retained: false,
        }
    }

    pub const fn retained(mut self, retained: bool) -> Self {
        self.retained = retained;
        self
    }
}

impl<M> Message<Publish<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = ();

    async fn handle(
        &mut self,
        Publish { message, retained }: Publish<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let state = self.subscriptions.entry(message.type_id()).or_default();

        if retained {
            state.retained = Some(Box::new(message.clone()));
        }

        for recip in state.recipients.values_mut() {
            let recip = recip.downcast_mut::<Recipient<M>>().unwrap();

            if let Err(e) = recip.tell(message.clone()).await {
                tracing::error!(error = %e, "");
            }
        }
    }
}

impl<M> Message<Register<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = Option<Recipient<M>>;

    async fn handle(
        &mut self,
        Register(recip): Register<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let state = self.subscriptions.entry(TypeId::of::<M>()).or_default();

        if let Some(retained) = &state.retained
            && !state.recipients.contains_key(&recip.id())
            && let Err(e) = recip
                .tell(retained.downcast_ref::<M>().unwrap().clone())
                .await
        {
            tracing::error!(error = %e);
        }

        state
            .recipients
            .insert(recip.id(), Box::new(recip))
            .map(|old| *old.downcast().unwrap())
    }
}

/// Get the current retained value for type `M` (if any).
#[derive(Debug, Copy, Clone, Default)]
pub struct Get<M>(PhantomData<M>);

impl<M> Message<Get<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = Option<M>;

    async fn handle(&mut self, _: Get<M>, _: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let state = self.subscriptions.get(&TypeId::of::<M>())?;
        let ret = state.retained.as_ref()?;
        let ret = ret.downcast_ref::<M>().unwrap().clone();

        Some(ret)
    }
}

pub struct Unregister<M> {
    actor_id: ActorId,
    _phantom: PhantomData<M>,
}

impl<M> Unregister<M> {
    pub const fn new(id: ActorId) -> Self {
        Self {
            actor_id: id,
            _phantom: PhantomData,
        }
    }
}

impl<M> Message<Unregister<M>> for RetainedBus
where
    M: Send + 'static,
{
    type Reply = (Option<Recipient<M>>, Option<M>);

    async fn handle(
        &mut self,
        Unregister { actor_id, .. }: Unregister<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let type_id = TypeId::of::<M>();

        let Some(state) = self.subscriptions.get_mut(&type_id) else {
            return (None, None);
        };

        let ret = state
            .recipients
            .remove(&actor_id)
            .map(|x| *x.downcast().unwrap());

        let state = if state.recipients.is_empty() {
            self.subscriptions
                .remove(&type_id)
                .and_then(|state| state.retained)
                .map(|x| *x.downcast().unwrap())
        } else {
            None
        };

        (ret, state)
    }
}
