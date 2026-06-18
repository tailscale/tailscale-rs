use core::{
    any::{Any, TypeId, type_name},
    marker::PhantomData,
};
use std::collections::HashMap;

use kameo::{
    Reply,
    actor::{ActorRef, WeakActorRef},
    error::{BoxSendError, Infallible, SendError},
    message::{Context, Message},
    reply::{BoxReplySender, DelegatedReply, ForwardedReply, ReplyError},
};
use smol_str::{SmolStr, ToSmolStr};

/// Name for a canonical actor instance.
const CANONICAL: SmolStr = SmolStr::new_static("__canonical__");

/// Complete identifier for an actor registration: the actor type and the user-provided name string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Id {
    actor_ty: TypeId,
    name: SmolStr,
}

impl Id {
    const fn canonical<A>() -> Self
    where
        A: Any,
    {
        Self {
            actor_ty: TypeId::of::<A>(),
            name: CANONICAL,
        }
    }

    fn new<A>(name: Option<SmolStr>) -> Self
    where
        A: Any,
    {
        match name {
            Some(name) => Self::named::<A>(name),
            None => Self::canonical::<A>(),
        }
    }

    fn named<A>(name: SmolStr) -> Self
    where
        A: Any,
    {
        Self {
            actor_ty: TypeId::of::<A>(),
            name,
        }
    }
}

/// [`WeakActorRef`] with erased actor type.
pub type ErasedWeakRef = Box<dyn Any + Send>;

/// An actor registry which itself runs as an actor and provides naming service for the tuple
/// `(actor_type, name)`.
///
/// # Names
///
/// When you communicate with this registry, you always explicitly name the type of actor you're
/// talking about as well as the user-provided string name. This is an affordance for type-safety;
/// kameo doesn't support fully type-erased actor references or message handlers. As a consequence,
/// names are permitted to overlap between actors of different types, as there can't be a collision
/// between them.
///
/// The conventional structure of names in this registry includes the idea of a "canonical" actor
/// which is unique. For actors expected to run as singletons or to have a single special instance,
/// the `new` function on any of the message types addresses this canonical instance. The canonical
/// name isn't privileged in any other way (e.g. the registry doesn't prevent you from spawning
/// named actors if there's a canonical one), it's just a conventional, easily-addressed name for a
/// special actor if you have one.
///
/// # Liveness
///
/// This registry does not keep actors alive; all refs are held weakly.
///
/// # Comparison to [`kameo::registry`]
///
/// We're not using the singleton [`kameo::registry::ACTOR_REGISTRY`] because it's at global scope,
/// but we need naming services to be scoped to each instance of a tailscale runtime. Rather than
/// dealing with prefixes, we just run a per-runtime registry.
///
/// We don't use [`kameo::registry::ActorRegistry`] for the per-runtime registry because it doesn't
/// have any built-in synchronization, is hard to customize, and requires manual downcasting on the
/// part of the user, despite the fact that the contained actor refs are only usable if you know
/// what kind of messages they can handle (i.e. you essentially must know the actor type a priori).
#[derive(Default)]
pub struct Registry {
    actors: HashMap<Id, ErasedWeakRef>,
    pending_lookups: HashMap<Id, Vec<BoxReplySender>>,
}

impl kameo::Actor for Registry {
    type Args = ();
    type Error = Infallible;

    async fn on_start(_args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

/// Request to register an actor with a given name.
///
/// The registry replies with the [`WeakActorRef`] of an actor that was already registered in this
/// name if there was one.
pub struct Register<A>
where
    A: kameo::Actor,
{
    id: Id,
    aref: WeakActorRef<A>,
}

impl<A> Register<A>
where
    A: kameo::Actor + Any,
{
    /// Construct a register request for the canonical actor of type `A`.
    pub fn new(name: Option<SmolStr>, aref: &ActorRef<A>) -> Self {
        Self {
            id: Id::new::<A>(name),
            aref: aref.downgrade(),
        }
    }

    /// Construct a register request for an actor with the specified `name`.
    pub fn named(name: SmolStr, aref: &ActorRef<A>) -> Self {
        Self {
            id: Id::named::<A>(name),
            aref: aref.downgrade(),
        }
    }

    /// Construct a register request for the canonical actor of type `A`.
    pub fn canonical(aref: &ActorRef<A>) -> Self {
        Self {
            id: Id::canonical::<A>(),
            aref: aref.downgrade(),
        }
    }
}

impl<A> Message<Register<A>> for Registry
where
    A: kameo::Actor + Any,
{
    type Reply = Option<WeakActorRef<A>>;

    async fn handle(
        &mut self,
        msg: Register<A>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Option<WeakActorRef<A>> {
        if let Some(pending) = self.pending_lookups.remove(&msg.id) {
            for sender in pending {
                drop(sender.send(Ok(Box::new(Some(msg.aref.clone())))));
            }
        }

        let previous = self.actors.insert(msg.id, Box::new(msg.aref))?;

        *previous.downcast().unwrap()
    }
}

/// Request to unregister an actor for a given name.
///
/// The registry replies with the [`WeakActorRef`] of the unregistered actor if there was one.
pub struct Unregister<A>(Id, PhantomData<A>);

impl<A> Unregister<A>
where
    A: Any,
{
    /// Unregister an actor of type `A` with the given `name` if it exists in the registry.
    pub fn named(name: SmolStr) -> Self {
        Self(Id::named::<A>(name), PhantomData)
    }

    /// Unregister the canonical actor of type `A` if it exists in the registry.
    pub const fn new() -> Self {
        Self(Id::canonical::<A>(), PhantomData)
    }
}

impl<A> Message<Unregister<A>> for Registry
where
    A: kameo::Actor,
{
    type Reply = Option<WeakActorRef<A>>;

    async fn handle(
        &mut self,
        msg: Unregister<A>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Option<WeakActorRef<A>> {
        let previous = self.actors.remove(&msg.0)?;
        *previous.downcast().unwrap()
    }
}

pub struct Lookup<A> {
    id: Id,
    wait: bool,
    _phantom: PhantomData<A>,
}

impl<A> Lookup<A>
where
    A: Any,
{
    pub fn new(name: Option<SmolStr>) -> Self {
        Self {
            id: if let Some(name) = name {
                Id::named::<A>(name)
            } else {
                Id::canonical::<A>()
            },
            wait: false,
            _phantom: PhantomData,
        }
    }

    /// Look up the canonical actor of type `A`.
    pub const fn canonical() -> Self {
        Self {
            id: Id::canonical::<A>(),
            wait: false,
            _phantom: PhantomData,
        }
    }

    /// Look up an actor of type `A` with name `name`.
    pub fn named(name: impl ToSmolStr) -> Self {
        Self::new(Some(name.to_smolstr()))
    }

    /// Wait until an actor is registered with the given name.
    pub const fn wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }
}

impl<A> Message<Lookup<A>> for Registry
where
    A: kameo::Actor,
{
    type Reply = DelegatedReply<Option<WeakActorRef<A>>>;

    async fn handle(
        &mut self,
        msg: Lookup<A>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (deleg, sender) = ctx.reply_sender();

        if let Some(sender) = sender {
            let aref = self
                .actors
                .get(&msg.id)
                .map(|x| x.downcast_ref::<WeakActorRef<A>>().unwrap())
                .cloned();

            match (&aref, msg.wait) {
                (Some(_), _) | (_, false) => {
                    sender.send(aref);
                }
                (None, true) => {
                    self.pending_lookups
                        .entry(msg.id)
                        .or_default()
                        .push(sender.boxed());
                }
            }
        };

        deleg
    }
}

/// Request to forward a message of type `M` to an actor of type `A` under a particular registered
/// name.
pub struct Forward<A, M> {
    id: Id,
    message: M,
    _phantom: PhantomData<A>,
}

impl<A, M> Forward<A, M>
where
    A: Any,
{
    pub fn new(name: Option<SmolStr>, m: M) -> Self {
        Self {
            id: Id::new::<A>(name),
            message: m,
            _phantom: PhantomData,
        }
    }

    /// Construct a new [`Forward`] for the message `M`.
    pub fn named(name: impl ToSmolStr, m: M) -> Self {
        Self {
            id: Id {
                name: name.to_smolstr(),
                actor_ty: TypeId::of::<A>(),
            },
            message: m,
            _phantom: PhantomData,
        }
    }

    pub const fn canonical(m: M) -> Self {
        Self {
            id: Id::canonical::<A>(),
            message: m,
            _phantom: PhantomData,
        }
    }
}

/// Wrapper around [`ForwardedReply`] that handles forwards into the registry.
///
/// This is needed because [`ForwardedReply`] doesn't let you construct a [`SendError`] variant
/// directly.
pub enum RegistryForward<M, R>
where
    M: Send + 'static,
    R: Reply,
{
    /// The message was successfully forwarded or failed to be forwarded
    Forwarded(ForwardedReply<M, R>),
    ActorDead(M),
    NotFound(M),
}

impl<M, R> Reply for RegistryForward<M, R>
where
    M: Send + 'static,
    R: Reply,
{
    type Ok = R::Ok;
    type Error = SendError<M, R::Error>;
    type Value = Result<Self::Ok, Self::Error>;

    fn to_result(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Self::Forwarded(res) => res.to_result(),
            Self::NotFound(m) => Err(SendError::ActorNotRunning(m)),
            Self::ActorDead(m) => Err(SendError::ActorNotRunning(m)),
        }
        .inspect_err(|e| {
            tracing::trace!(error = ?e, "forward error");
        })
    }

    fn into_any_err(self) -> Option<Box<dyn ReplyError>> {
        match self {
            Self::Forwarded(res) => res.into_any_err(),
            Self::ActorDead(m) => {
                Some(Box::new(SendError::<M, R::Error>::ActorNotRunning(m)) as Box<dyn ReplyError>)
            }
            Self::NotFound(m) => {
                Some(Box::new(SendError::<M, R::Error>::ActorNotRunning(m)) as Box<dyn ReplyError>)
            }
        }
    }

    fn into_value(self) -> Self::Value {
        self.to_result()
    }

    /// If the forwarded reply succeeded, then we can safely assume
    /// the `Box<dyn Any>` we have here is the ok value of the inner `R`.
    fn downcast_ok(ok: Box<dyn Any>) -> Self::Ok {
        *ok.downcast().unwrap()
    }

    /// The error is either from the inner `R`, or our outer `SendError`.
    /// We'll try both.
    fn downcast_err<N: 'static>(err: BoxSendError) -> SendError<N, Self::Error> {
        err.try_downcast::<N, R::Error>()
            .map(|err| err.map_err(SendError::HandlerError))
            .unwrap_or_else(|err| {
                err.downcast::<M, SendError<M, R::Error>>().map_msg(|_| {
                    unreachable!(
                        "forwarded reply is only an error if it failed to forward the message"
                    )
                })
            })
    }
}

impl<A, M> Message<Forward<A, M>> for Registry
where
    A: Message<M>,
    M: Send + 'static,
{
    type Reply = RegistryForward<M, A::Reply>;

    #[tracing::instrument(skip_all, fields(msgty = type_name::<M>(), actor = type_name::<A>(), name = %msg.id.name))]
    async fn handle(
        &mut self,
        msg: Forward<A, M>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(aref) = self.actors.get(&msg.id) else {
            tracing::trace!("actor not found");
            return RegistryForward::NotFound(msg.message);
        };

        let Some(aref) = aref.downcast_ref::<WeakActorRef<A>>().unwrap().upgrade() else {
            tracing::trace!("actor dead");
            return RegistryForward::ActorDead(msg.message);
        };

        let result = ctx.try_forward(&aref, msg.message);

        RegistryForward::Forwarded(result)
    }
}
