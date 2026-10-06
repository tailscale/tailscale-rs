//! Type-keyed message bus supporting retained messages.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
};
use core::{
    any::{Any, TypeId},
    marker::PhantomData,
};

use futures_util::{Stream, StreamExt};
use smol_str::SmolStr;

type Map<K, V> = BTreeMap<K, V>;

use crate::{
    Error, Message, ProcContext, ProcFut, StaticStorage, ToProcName, actors::forward_stream,
    gen_server, gen_server::GenServer, message, pid::Pid,
};

/// Default name for the bus actor.
const DEFAULT_NAME: SmolStr = SmolStr::new_static("bus");

/// Convenience macro to subscribe to many message types on the bus in a single call.
///
/// # Examples
///
/// ```rust
/// # #[tokio::main] async fn main() {
/// # let rt = ts_actor::runtime::new(ts_actor::runtime::Tokio::current());
/// # let bus_pid = rt.spawn(ts_actor::actors::bus::start_default).unwrap();
/// # rt.run(async move |ctx| {
/// # ctx.wait_proc("bus").await?;
/// ts_actor::bus_sub_all!(&ctx, u8).await?;
/// ts_actor::bus_sub_all!([&bus_pid], &ctx, u16, u32).await?;
/// # Ok(())
/// # }).await.unwrap();
/// # }
/// ```
#[macro_export]
macro_rules! bus_sub_all {
    ([$name:expr], $ctx:expr, $($t:ty),* $(,)?) => {
        async {
            let mut out = ::core::result::Result::<(), $crate::Error>::Ok(());

            $(
                if out.is_ok() {
                    out = $crate::actors::bus::subscribe_named::<$t>($ctx, $name).await;
                }
            )*

            out
        }
    };
    ($ctx:expr, $($t:ty),* $(,)?) => {
        async {
            let mut out = ::core::result::Result::<(), $crate::Error>::Ok(());

            $(
                if out.is_ok() {
                    out = $crate::actors::bus::subscribe::<$t>($ctx).await;
                }
            )*

            out
        }
    };
}

/// A type-keyed message bus which tracks retained message state.
///
/// [`Publish`] messages may optionally set the `retained` flag to indicate that the
/// message should be retained on the bus. When present, new [`Register`]ed processes
/// receive the current retained message immediately.
struct TypedBus;

/// Start a bus registered with the default name.
pub async fn start_default(ctx: ProcContext) -> Result<(), Error> {
    ctx.register(DEFAULT_NAME).await?;
    gen_server::start(TypedBus, ())(ctx).await
}

/// Start a bus registered with the given `name`.
pub fn start_named(name: SmolStr) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> {
    move |ctx| {
        StaticStorage::Box(Box::new(async move {
            ctx.register(name).await?;
            gen_server::start(TypedBus, ())(ctx).await
        }))
    }
}

/// Subscribe to bus messages of type `M` (using the default bus name).
pub async fn subscribe<M>(ctx: &ProcContext) -> Result<(), Error>
where
    M: Any,
{
    subscribe_named::<M>(ctx, &DEFAULT_NAME).await
}

/// Subscribe to bus messages of type `M` (using the specified bus name).
pub async fn subscribe_named<M>(ctx: &ProcContext, bus: &dyn ToProcName) -> Result<(), Error>
where
    M: Any,
{
    gen_server::cast_typed::<_, TypedBus>(ctx, bus, Register::new::<M>(ctx.pid())).await
}

/// Unsubscribe from bus messages of type `M` (using the default bus name).
pub async fn unsubscribe<M>(ctx: &ProcContext) -> Result<(), Error>
where
    M: Any,
{
    unsubscribe_named::<M>(ctx, &DEFAULT_NAME).await
}

/// Unsubscribe from bus messages of type `M` (using the specified bus name).
pub async fn unsubscribe_named<M>(ctx: &ProcContext, bus: &dyn ToProcName) -> Result<(), Error>
where
    M: Any,
{
    gen_server::cast_typed::<_, TypedBus>(ctx, bus, Unregister::new::<M>(ctx.pid())).await
}

/// Get the bus's current retained value for type `M` (using the default bus name).
pub async fn get<M>(ctx: &ProcContext) -> Result<Option<M>, Error>
where
    M: Any,
{
    get_named::<M>(ctx, &DEFAULT_NAME).await
}

/// Get the bus's current retained value for type `M` (using the specified bus name).
pub async fn get_named<M>(ctx: &ProcContext, bus: &dyn ToProcName) -> Result<Option<M>, Error>
where
    M: Any,
{
    let resp = gen_server::call_typed::<_, TypedBus>(ctx, bus, GetRetained::new::<M>()).await?;
    Ok(resp.map(|x| x.downcast().unwrap()))
}

/// Publish an optionally-retained message to the bus.
pub async fn publish(
    ctx: &ProcContext,
    msg: impl Clone + Send + Any,
    retain: bool,
) -> Result<(), Error> {
    publish_named(ctx, &DEFAULT_NAME, msg, retain).await
}

/// Publish an optionally-retained message to the bus identified by name `bus`.
pub async fn publish_named(
    ctx: &ProcContext,
    bus: &dyn ToProcName,
    msg: impl Clone + Send + Any,
    retain: bool,
) -> Result<(), Error> {
    let publ = if retain {
        Publish::retained(msg)
    } else {
        Publish::unretained(msg)
    };

    gen_server::cast_typed::<_, TypedBus>(ctx, bus, publ).await
}

/// Publish a stream of messages to the bus.
///
/// The return value is intended to be used to spawn a process.
pub fn publish_stream<S>(
    stream: S,
    retained: bool,
) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> + use<S>
where
    S: Stream + Send + 'static,
    S::Item: Send + Any + Clone,
{
    publish_stream_named(&DEFAULT_NAME, stream, retained)
}

/// Publish a stream of messages to the bus identified by `name`.
///
/// The return value is intended to be used to spawn a process.
pub fn publish_stream_named<S>(
    name: &dyn ToProcName,
    stream: S,
    retained: bool,
) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> + use<S>
where
    S: Stream + Send + 'static,
    S::Item: Send + Any + Clone,
{
    let name = name.to_proc_name();
    let stream = stream.map(move |x| Publish {
        tid: TypeId::of::<S::Item>(),
        message: Box::new(CloneMsg(x)),
        retained,
    });

    move |ctx| forward_stream(&name, stream)(ctx)
}

/// Build a process function that maps bus messages from type `T` to type `U`, using state
/// `S` and a mapper function `F`.
///
/// This is not async because the types become drastically more complicated if you need to
/// do anything involved inside the mapper. Prefer to write your own process function in
/// that case instead.
pub fn filter_map<T, U, S, F>(
    state: S,
    retain: bool,
    f: F,
) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> + use<T, S, U, F>
where
    T: Send + 'static,
    U: Any + Send + Clone + 'static,
    S: Send + 'static,
    F: FnMut(&mut S, T) -> Option<U> + Send + 'static,
{
    filter_map_named(&DEFAULT_NAME, state, retain, f)
}

/// Build a process function that maps a bus from type `T` to type `U`, using state `S` and
/// a mapper function `F`.
///
/// This is relatively simple and not async because the types become drastically more
/// complicated if you need to do anything involved inside the mapper. Prefer to write
/// your own process function in that case instead.
pub fn filter_map_named<T, U, S, F>(
    name: &dyn ToProcName,
    mut state: S,
    retain: bool,
    mut f: F,
) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> + use<T, S, U, F>
where
    T: Send + 'static,
    U: Any + Send + Clone + 'static,
    S: Send + 'static,
    F: FnMut(&mut S, T) -> Option<U> + Send + 'static,
{
    let name = name.to_proc_name();

    move |ctx| {
        StaticStorage::Box(Box::new(async move {
            subscribe_named::<T>(&ctx, &name).await?;

            loop {
                crate::msg_match! {
                    ctx.recv().await?,
                    T: msg => {
                        if let Some(ret) = f(&mut state, msg) {
                            publish_named(&ctx, &name, ret, retain).await?;
                        }
                    },
                }
            }
        }))
    }
}

/// Subscription state for the bus.
#[derive(Default)]
pub struct SubState {
    retained: Option<Box<dyn PubMsg>>,
    recipients: BTreeSet<Pid>,
}

/// Minor abstraction for published messages to support cloning even if the underlying value
/// doesn't natively.
///
/// Lets you either provide a value which is [`Clone`] (wrapped in [`CloneMsg`]), or a
/// factory closure to produce the value ([`FnMsg`]).
trait PubMsg: Send {
    fn clone_to_msg(&self) -> Message;
}

struct CloneMsg<T>(T);
struct FnMsg<F, T>(F, PhantomData<T>);

impl<T> PubMsg for CloneMsg<T>
where
    T: Clone + Any + Send,
{
    fn clone_to_msg(&self) -> Message {
        message![self.0.clone()]
    }
}

impl<F, T> PubMsg for FnMsg<F, T>
where
    F: Fn() -> T + Send + 'static,
    T: Any + Send,
{
    fn clone_to_msg(&self) -> Message {
        message![self.0()]
    }
}

crate::impl_cast!(TypedBus, Register, ctx, state, Register { pid, tid }, {
    let sub_state = state.entry(tid).or_default();

    if let Some(retained) = &sub_state.retained
        && !sub_state.recipients.contains(&pid)
        && let Err(e) = ctx.try_send(&pid, retained.clone_to_msg()).await
    {
        tracing::error!(error = %e);
    }

    sub_state.recipients.insert(pid);

    None
});

crate::impl_cast!(
    TypedBus,
    Unregister,
    _ctx,
    state,
    Unregister { pid, tid },
    {
        #[allow(clippy::question_mark)] // not semantically appropriate
        let Some(sub_state) = state.get_mut(&tid) else {
            return None;
        };

        sub_state.recipients.remove(&pid);

        if sub_state.recipients.is_empty() && sub_state.retained.is_none() {
            state.remove(&tid);
        }

        None
    }
);

crate::impl_cast!(
    TypedBus,
    Publish,
    ctx,
    state,
    Publish {
        tid,
        message,
        retained
    },
    {
        let sub_state = state.entry(tid).or_default();

        let mut any_missing = false;

        for recip in sub_state.recipients.iter() {
            // actor is dead (this is an expected case)
            if ctx.try_send(recip, message.clone_to_msg()).await.is_err() {
                any_missing = true;
            }
        }

        if retained {
            sub_state.retained = Some(message);
        }

        if any_missing {
            sub_state.recipients.retain(|&pid| {
                let retain = ctx.check_proc(pid).is_ok();

                if !retain {
                    tracing::trace!(
                        %pid,
                        "actor gone, remove subscription"
                    );
                }

                retain
            });
        }

        None
    }
);

crate::impl_call!(
    TypedBus,
    GetRetained,
    Option<Message>,
    _ctx,
    state,
    GetRetained(tid),
    handle,
    {
        let Some(sub_state) = state.get(&tid) else {
            return handle.commit(None).into();
        };

        let ret = sub_state.retained.as_ref().map(|x| x.clone_to_msg());
        handle.commit(ret).into()
    }
);

impl GenServer for TypedBus {
    type Args = ();
    type State = Map<TypeId, SubState>;

    async fn init(
        &self,
        _ctx: &ProcContext,
        _args: Self::Args,
    ) -> Result<(Self::State, Option<gen_server::Action>), Error> {
        Ok(Default::default())
    }

    crate::typed_call!(GetRetained);
    crate::typed_cast!(Register, Unregister, Publish);
}

/// Publish a message.
pub struct Publish {
    tid: TypeId,
    message: Box<dyn PubMsg>,
    retained: bool,
}

impl Publish {
    /// Construct a new unretained publish.
    ///
    /// If there exists a retained message stored in the bus for this message type, it
    /// is neither updated nor cleared by this message.
    fn unretained<M>(m: M) -> Self
    where
        M: Clone + Any + Send,
    {
        Self {
            tid: TypeId::of::<M>(),
            message: Box::new(CloneMsg(m)),
            retained: false,
        }
    }

    /// Construct a new retained publish.
    ///
    /// It will update the retained message in the bus.
    fn retained<M>(m: M) -> Self
    where
        M: Clone + Any + Send,
    {
        Self {
            tid: TypeId::of::<M>(),
            message: Box::new(CloneMsg(m)),
            retained: true,
        }
    }

    /// Construct a new publish with the given cloner function.
    #[allow(unused)]
    fn from_fn<M>(clone_msg: impl Fn() -> M + Send + 'static, retained: bool) -> Self
    where
        M: Any + Send,
    {
        Self {
            tid: TypeId::of::<M>(),
            message: Box::new(FnMsg(clone_msg, PhantomData)),
            retained,
        }
    }
}

/// Register the given process for the given message type.
pub struct Register {
    pid: Pid,
    tid: TypeId,
}

impl Register {
    const fn new<M>(pid: Pid) -> Self
    where
        M: Any,
    {
        Self {
            pid,
            tid: TypeId::of::<M>(),
        }
    }
}

/// Get the current retained value for type `M` (if any).
#[derive(Debug, Copy, Clone)]
pub struct GetRetained(TypeId);

impl GetRetained {
    const fn new<M>() -> Self
    where
        M: Any,
    {
        GetRetained(TypeId::of::<M>())
    }
}

/// Unregister the given process from the given message type.
pub struct Unregister {
    pid: Pid,
    tid: TypeId,
}

impl Unregister {
    const fn new<M>(pid: Pid) -> Self
    where
        M: Any,
    {
        Self {
            pid,
            tid: TypeId::of::<M>(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{runtime, runtime::Tokio};

    #[tokio::test]
    async fn bus_basic() {
        let rt = runtime::new(Tokio::current());

        rt.spawn(start_default).unwrap();

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct MyStruct {
            value: usize,
        }

        let (val, val_get) = rt
            .run(async move |ctx| {
                subscribe::<MyStruct>(&ctx).await?;
                assert!(matches!(ctx.try_recv(), Ok(None)));

                publish(&ctx, MyStruct { value: 4 }, true).await?;
                let val = ctx.recv_downcast::<MyStruct>().await?;

                let val_get = get::<MyStruct>(&ctx).await?.unwrap();
                Ok((val, val_get))
            })
            .await
            .unwrap();

        assert_eq!(val, val_get);
        assert_eq!(val.value, 4);
    }
}
