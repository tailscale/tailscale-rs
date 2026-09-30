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

/// Type-erased [`SubState<M>`].
type ErasedSubState = Box<dyn Any + Send>;

/// A version of [`MessageBus`][kameo_actor::message_bus::MessageBus] optionally tracking retained
/// state.
///
/// [`Publish`] messages may optionally set the `retained` flag to indicate that the message should
/// be retained on the bus. When present, new [`Register`]ed actors receive the current retained
/// message immediately.
#[derive(Default, kameo::Actor)]
pub struct RetainedBus {
    /// Essentially: `Map<M, SubState<M>>`.
    subscriptions: HashMap<TypeId, ErasedSubState>,
}

// The unwraps in this impl block are safe because they are only present on downcasts, which are
// protected by the invariant that the value type for `TypeId::of::<M>()` is `SubState<M>`.
impl RetainedBus {
    fn get<M>(&self) -> Option<&SubState<M>>
    where
        M: Send + 'static,
    {
        let state = self.subscriptions.get(&TypeId::of::<M>())?;
        Some(state.downcast_ref().unwrap())
    }

    fn get_mut<M>(&mut self) -> Option<&mut SubState<M>>
    where
        M: Send + 'static,
    {
        let state = self.subscriptions.get_mut(&TypeId::of::<M>())?;
        Some(state.downcast_mut().unwrap())
    }

    fn entry_or_default<M>(&mut self) -> &mut SubState<M>
    where
        M: Send + 'static,
    {
        let state = self
            .subscriptions
            .entry(TypeId::of::<M>())
            .or_insert_with(|| Box::new(SubState::<M>::default()));

        state.downcast_mut().unwrap()
    }

    fn remove<M>(&mut self) -> Option<SubState<M>>
    where
        M: Send + 'static,
    {
        let ret = *self
            .subscriptions
            .remove(&TypeId::of::<M>())?
            .downcast::<SubState<M>>()
            .unwrap();

        Some(ret)
    }
}

struct SubState<M>
where
    M: Send + 'static,
{
    retained: Option<M>,
    recipients: HashMap<ActorId, Recipient<M>>,
}

impl<M> Default for SubState<M>
where
    M: Send + 'static,
{
    fn default() -> Self {
        Self {
            retained: None,
            recipients: Default::default(),
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct Publish<M> {
    pub message: M,
    pub retained: bool,
}

impl<M> Publish<M> {
    /// Construct a new unretained publish.
    ///
    /// If there exists a retained message stored in the [`RetainedBus`] for this message type, it
    /// is neither updated nor cleared by this message.
    pub const fn unretained(m: M) -> Self {
        Self {
            message: m,
            retained: false,
        }
    }

    /// Construct a new retained publish.
    ///
    /// It will update the retained message in the [`RetainedBus`].
    pub const fn retained(m: M) -> Self {
        Self {
            message: m,
            retained: true,
        }
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
        let state = self.entry_or_default::<M>();

        if retained {
            state.retained = Some(message.clone());
        }

        let mut any_missing = false;

        for recip in state.recipients.values_mut() {
            // actor is dead (this is an expected case)
            if recip.tell(message.clone()).await.is_err() {
                any_missing = true;
            }
        }

        if any_missing {
            state.recipients.retain(|id, recip| {
                let retain = recip.is_alive();
                if !retain {
                    tracing::trace!(
                        ?id,
                        msgty = core::any::type_name::<M>(),
                        "actor gone, remove subscription"
                    );
                }

                retain
            });
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
        let state = self.entry_or_default::<M>();

        if let Some(retained) = &state.retained
            && !state.recipients.contains_key(&recip.id())
            && let Err(e) = recip.tell(retained.clone()).await
        {
            tracing::error!(error = %e);
        }

        state.recipients.insert(recip.id(), recip)
    }
}

/// Get the current retained value for type `M` (if any).
#[derive(Debug, Copy, Clone, Default)]
pub struct GetRetained<M>(PhantomData<M>);

impl<M> Message<GetRetained<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = Option<M>;

    async fn handle(
        &mut self,
        _: GetRetained<M>,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let state = self.get::<M>()?;
        let ret = state.retained.as_ref()?;

        Some(ret.clone())
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
        let Some(state) = self.get_mut::<M>() else {
            return (None, None);
        };

        let ret = state.recipients.remove(&actor_id);

        let state = if state.recipients.is_empty() {
            self.remove::<M>().and_then(|state| state.retained)
        } else {
            None
        };

        (ret, state)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use kameo::actor::{ActorRef, Spawn};
    use tokio::sync::oneshot;

    use super::*;

    /// Ensure that the downcasts are of the correct types.
    #[test]
    fn basic() {
        type T = ();

        let mut bus = RetainedBus::default();

        let ent = bus.entry_or_default::<T>();
        assert!(ent.retained.is_none());
        assert!(ent.recipients.is_empty());

        assert!(bus.get::<T>().is_some());
        assert!(bus.get_mut::<T>().is_some());

        let ent = bus.remove::<T>().unwrap();
        assert!(ent.retained.is_none());
        assert!(ent.recipients.is_empty());
    }

    #[tokio::test]
    async fn bus_basic() {
        let bus = RetainedBus::spawn_default();
        bus.wait_for_startup_result().await.unwrap();

        #[derive(kameo::Actor)]
        struct Dummy(Option<oneshot::Sender<()>>);

        #[kameo::messages]
        impl Dummy {
            #[message(ctx)]
            async fn test(&self, bus: ActorRef<RetainedBus>, ctx: &mut Context<Self, ()>) {
                bus.ask(Register(ctx.actor_ref().clone().recipient::<Test2>()))
                    .await
                    .unwrap();

                bus.tell(Publish::unretained(Test2)).try_send().unwrap();
            }

            #[message]
            fn test2(&mut self) {
                self.0.take().unwrap().send(()).unwrap();
            }
        }

        impl Clone for Test2 {
            fn clone(&self) -> Self {
                Self
            }
        }

        let (tx, rx) = oneshot::channel();
        let dummy = Dummy::spawn(Dummy(Some(tx)));
        dummy.ask(Test { bus: bus.clone() }).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap()
            .unwrap()
    }
}
