//! Provisions for statically typed [`GenServer`] message handlers.
//!
//! The traits defined here ([`TypedCall`], [`TypedCast`], [`TypedInfo`]) can be used to
//! assemble a [`GenServer`] instance which demonstrates its ability to handle certain
//! messages at the type level. This enables us to provide [`call_typed`], [`cast_typed`],
//! and [`try_cast_typed`], which automatically handle [`Message`][crate::Message]-wrapping
//! (and reply-unwrapping for `call`) with the correct types.
//!
//! Presently, the traits in this module can be used to assemble a [`GenServer`]  by
//! invoking the [`typed_call!`], [`typed_cast!`], and [`typed_info!`] handlers with the
//! message types which should be handled. This expands out into a `msg_match!` with a case
//! for each message type.
//!
//! Note that this can be somewhat misleading: a typed handler trait isn't evidence that a
//! particular [`GenServer`] _actually_ invokes the trait at runtime; if you forget to add
//! the message type to your `typed_call!` e.g., the process won't handle it and the caller
//! will get badarg back. This shouldn't be seen as a degradation of any guarantees; as soon
//! as you send a message you technically don't know a) that the process you're talking to
//! is even alive, or b) that there's any guarantee that it knows how to handle your
//! message -- there's no way to prove that a given process implements [`GenServer`] in the
//! first place, let alone a specific typed handler.

use core::{any::Any, marker::PhantomData};

use crate::{
    Error, ProcContext, Ref, ToProcName,
    gen_server::{Action, CallReply, GenServer, ReplyHandle},
    pid::Pid,
};

/// Convenience alias for the return type of [`TypedCall::handle_call`].
pub type TypedCallResult<Reply> = (Option<TypedReply<Reply>>, Option<Action>);

/// Send a request to the [`GenServer`] identified by `server`, waiting for its reply.
pub async fn call_typed<M, GS>(
    ctx: &ProcContext,
    server: &dyn ToProcName,
    msg: M,
) -> Result<GS::Reply, Error>
where
    M: Any + Send,
    GS: TypedCall<M>,
{
    let result = crate::gen_server::call(ctx, server, crate::message![msg]).await?;
    result.downcast().map_err(|_| Error::BadArg)
}

/// Send a cast to the [`GenServer`] identified by `server`.
#[allow(clippy::extra_unused_type_parameters)]
pub async fn cast_typed<M, GS>(
    ctx: &ProcContext,
    server: &dyn ToProcName,
    msg: M,
) -> Result<(), Error>
where
    M: Any + Send,
    GS: TypedCast<M>,
{
    crate::gen_server::cast(ctx, server, crate::message![msg]).await
}

/// Try to send a cast to the [`GenServer`] identified by `server` without waiting for space
/// in its mailbox.
#[allow(clippy::extra_unused_type_parameters)]
pub async fn try_cast_typed<M, GS>(
    ctx: &ProcContext,
    server: &dyn ToProcName,
    msg: M,
) -> Result<(), Error>
where
    M: Any + Send,
    GS: TypedCast<M>,
{
    crate::gen_server::try_cast(ctx, server, crate::message![msg]).await
}

/// Lightweight handle to a caller which the implementer of [`GenServer::handle_call`] can
/// hold in order to reply later.
///
/// The intended semantics of [`TypedCall::handle_call`] are that each call gets exactly
/// one reply; hence, you may either [`TypedReplyHandle::commit`] a response message and
/// return the [`TypedReply`] or store the [`TypedReplyHandle`] to return a deferred reply
/// later via [`TypedReplyHandle::reply`].
#[must_use = "not consuming a TypedReplyHandle will cause the call to hang"]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypedReplyHandle<Reply> {
    pid: Pid,
    rf: Ref,
    reply: PhantomData<Reply>,
}

impl<Reply> TypedReplyHandle<Reply> {
    #[doc(hidden)]
    pub fn from_untyped(handle: ReplyHandle) -> Self {
        Self {
            pid: handle.pid,
            rf: handle.rf,
            reply: PhantomData,
        }
    }

    /// Send a reply to the caller.
    pub async fn reply(self, ctx: &ProcContext, reply: Reply)
    where
        Reply: Send + Any,
    {
        if let Err(e) = ctx
            .try_send(
                &self.pid,
                crate::message![CallReply {
                    rf: self.rf,
                    msg: crate::message![reply]
                }],
            )
            .await
        {
            tracing::error!(error = %e, "replying to call");
        }
    }

    /// Commit this handle into a [`TypedReply`].
    pub fn commit(self, reply: Reply) -> TypedReply<Reply> {
        TypedReply::new(self, reply)
    }

    fn into_untyped(self) -> ReplyHandle {
        ReplyHandle {
            pid: self.pid,
            rf: self.rf,
        }
    }
}

/// Typed analogue of [`Reply`][super::Reply].
pub struct TypedReply<Reply>(TypedReplyHandle<Reply>, Reply);

impl<Reply> TypedReply<Reply> {
    /// Construct a new [`TypedReply`] from a handle and a message.
    pub const fn new(handle: TypedReplyHandle<Reply>, message: Reply) -> Self {
        Self(handle, message)
    }

    /// Attempt to send this [`TypedReply`].
    ///
    /// The message is just dropped if the reply doesn't go through because of a full mailbox.
    pub async fn send(self, ctx: &ProcContext)
    where
        Reply: Send + Any,
    {
        self.into_untyped().send(ctx).await
    }

    #[doc(hidden)]
    pub fn into_untyped(self) -> super::Reply
    where
        Reply: Send + Any,
    {
        let TypedReply(handle, reply) = self;

        super::Reply::new(handle.into_untyped(), crate::message![reply])
    }
}

impl<Reply> From<TypedReply<Reply>> for TypedCallResult<Reply> {
    fn from(value: TypedReply<Reply>) -> Self {
        (Some(value), None)
    }
}

/// Handler for a specific call message of type `M`.
///
/// Install this in a [`GenServer`] impl block with the [`typed_call!`][crate::typed_call]
/// macro. This generates a full `handle_call` implementation, so can only be used if all
/// call messages have `TypedCall` handlers.
///
/// # Examples
///
/// ```rust
/// # use ts_actor::gen_server::{TypedCall, GenServer, TypedCallResult, Action, TypedReplyHandle, self};
/// # use ts_actor::{Error, ProcContext};
/// struct SquareServer;
///
/// impl GenServer for SquareServer {
///     // ...
/// #    type State = ();
/// #    type Args = ();
/// #    async fn init(&self, ctx: &ProcContext, args: Self::Args) -> Result<(Self::State, Option<Action>), Error> {
/// #         Ok(((), None))
/// #    }
///     ts_actor::typed_call!(u8);
/// }
///
/// impl TypedCall<u8> for SquareServer {
///     type Reply = u16;
///
///     async fn handle_call(
///         &self,
///         ctx: &ProcContext,
///         state: &mut Self::State,
///         message: u8,
///         handle: TypedReplyHandle<Self::Reply>,
///     ) -> TypedCallResult<Self::Reply> {
///         handle.commit((message as u16).pow(2)).into()
///     }
/// }
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), ts_actor::Error> {
/// #   let rt = ts_actor::runtime::new(ts_actor::runtime::Tokio::current());
/// #   let sqr_pid = rt.spawn(gen_server::start(SquareServer, ()))?;
/// #
/// #   rt.run(async move |ctx| {
/// let result = gen_server::call_typed::<_, SquareServer>(&ctx, &sqr_pid, 3u8).await?;
/// assert_eq!(result, 9);
/// #       Ok(())
/// #   }).await?;
/// #   Ok(())
/// # }
/// ```
pub trait TypedCall<M>: GenServer {
    /// The reply for message type `M`.
    type Reply: Send + Any;

    /// Handle a call message of type `M` and replying with `Reply`.
    fn handle_call(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        message: M,
        handle: TypedReplyHandle<Self::Reply>,
    ) -> impl Future<Output = (Option<TypedReply<Self::Reply>>, Option<Action>)> + Send;
}

/// Handler for a specific cast message of type `M`.
///
/// Install this in a [`GenServer`] impl block with the [`typed_cast!`][crate::typed_cast]
/// macro. This generates a full `handle_cast` implementation, so can only be used if all
/// cast messages have `TypedCast` handlers.
///
/// # Examples
///
/// ```rust
/// # use ts_actor::gen_server::{TypedCast, GenServer, TypedCallResult, Action, TypedReplyHandle, self};
/// # use ts_actor::{Error, ProcContext};
/// struct PrintServer;
///
/// impl GenServer for PrintServer {
///     // ...
/// #    type State = ();
/// #    type Args = ();
/// #    async fn init(&self, ctx: &ProcContext, args: Self::Args) -> Result<(Self::State, Option<Action>), Error> {
/// #         Ok(((), None))
/// #    }
///     ts_actor::typed_cast!(String);
/// }
///
/// impl TypedCast<String> for PrintServer {
///     async fn handle_cast(
///         &self,
///         ctx: &ProcContext,
///         state: &mut Self::State,
///         message: String,
///     ) -> Option<gen_server::Action> {
///         println!("{message}");
///         None
///     }
/// }
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), ts_actor::Error> {
/// #   let rt = ts_actor::runtime::new(ts_actor::runtime::Tokio::current());
/// #   let print_pid = rt.spawn(gen_server::start(PrintServer, ()))?;
/// #
/// #   rt.run(async move |ctx| {
/// gen_server::cast_typed::<_, PrintServer>(&ctx, &print_pid, "hi".to_string()).await?;
/// // "hi" is printed
/// #       Ok(())
/// #   }).await?;
/// #   Ok(())
/// # }
/// ```
pub trait TypedCast<M>: GenServer {
    /// Handle a cast message of type `M`.
    ///
    /// The return value is an [`Action`] to take after this handler.
    fn handle_cast(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        message: M,
    ) -> impl Future<Output = Option<Action>> + Send;
}

/// Handler for a specific info message of type `M`.
///
/// Install this in a [`GenServer`] impl block with the [`typed_info!`][crate::typed_info]
/// macro. This generates a full `handle_info` implementation, so can only be used if all
/// info messages have `TypedInfo` handlers.
///
/// # Examples
///
/// ```rust
/// # use ts_actor::gen_server::{TypedInfo, GenServer, TypedCallResult, Action, TypedReplyHandle, self};
/// # use ts_actor::{Error, ProcContext};
/// struct CountServer;
///
/// struct Inc;
///
/// impl GenServer for CountServer {
///     // ...
/// #    type State = usize;
/// #    type Args = ();
/// #    async fn init(&self, ctx: &ProcContext, args: Self::Args) -> Result<(Self::State, Option<Action>), Error> {
/// #         Ok((0, None))
/// #    }
///     ts_actor::typed_info!(Inc);
/// }
///
/// impl TypedInfo<Inc> for CountServer {
///     async fn handle_info(
///         &self,
///         ctx: &ProcContext,
///         state: &mut Self::State,
///         _message: Inc,
///     ) -> Option<gen_server::Action> {
///         *state += 1;
///         None
///     }
/// }
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), ts_actor::Error> {
/// #   let rt = ts_actor::runtime::new(ts_actor::runtime::Tokio::current());
/// #   let count_pid = rt.spawn(gen_server::start(CountServer, ()))?;
/// #
/// #   rt.run(async move |ctx| {
/// ctx.send(&count_pid, ts_actor::message![Inc]).await;
/// #       Ok(())
/// #   }).await?;
/// #   Ok(())
/// # }
/// ```
pub trait TypedInfo<M>: GenServer {
    /// Handle an info message of type `M`.
    ///
    /// The return value is an [`Action`] the server should take in response to the message.
    fn handle_info(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        message: M,
    ) -> impl Future<Output = Option<Action>> + Send;
}

/// Generate a [`GenServer::handle_call`] implementation on the basis of a number of
/// [`TypedCall`] handlers. Invoke this macro inside a [`GenServer`] impl block.
///
/// # Example
///
/// ```rust
/// # use ts_actor::gen_server::{self, GenServer};
/// struct MyGenServer;
///
/// impl GenServer for MyGenServer {
///     // ...
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
///
///     ts_actor::typed_call!(u8);
/// }
///
/// ts_actor::impl_call!(MyGenServer, u8, u16, ctx, state, msg, handler, {
///     println!("got u8: {msg}");
///
///     handler.commit((msg as u16).pow(2)).into()
/// });
/// ```
#[macro_export]
macro_rules! typed_call {
    ($($msgty:ty),* $(,)?) => {
        async fn handle_call(
            &self,
            ctx: &$crate::ProcContext,
            state: &mut Self::State,
            message: $crate::Message,
            handle: $crate::gen_server::ReplyHandle,
        ) -> (Option<$crate::gen_server::Reply>, Option<$crate::gen_server::Action>) {
            $crate::msg_match! {
                message,
                $(
                    $msgty: msg => {
                        let handle = $crate::gen_server::TypedReplyHandle::from_untyped(handle);

                        let (result, action)
                            = <Self as $crate::gen_server::TypedCall::<$msgty>>::handle_call(self, ctx, state, msg, handle).await;

                        (result.map($crate::gen_server::TypedReply::into_untyped), action)
                    },
                )*
                else _msg => {
                    (Some(handle.commit(
                        $crate::message![$crate::Error::BadArg]
                    )), None)
                }
            }
        }
    };
}

/// Generate a [`GenServer::handle_cast`] implementation on the basis of a number of
/// [`TypedCast`] handlers. Invoke this macro inside a [`GenServer`] impl block.
///
/// # Example
///
/// ```rust
/// # use ts_actor::gen_server::{self, GenServer};
/// struct MyGenServer;
///
/// impl GenServer for MyGenServer {
///     // ...
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
///
///     ts_actor::typed_cast!(u8);
/// }
///
/// ts_actor::impl_cast!(MyGenServer, u8, ctx, state, msg, {
///     println!("got u8: {msg}");
///     None
/// });
/// ```
#[macro_export]
macro_rules! typed_cast {
    ($($msgty:ty),* $(,)?) => {
        async fn handle_cast(
            &self,
            ctx: &$crate::ProcContext,
            state: &mut Self::State,
            message: $crate::Message,
        ) -> Option<$crate::gen_server::Action> {
            let result: Option<$crate::gen_server::Action> = $crate::msg_match! {
                message,
                $(
                    $msgty: msg => {
                        <Self as $crate::gen_server::TypedCast<$msgty>>::handle_cast(self, ctx, state, msg).await
                    },
                )*
                else _msg => {
                    None
                }
            };

            result
        }
    };
}

/// Generate a [`GenServer::handle_info`] implementation on the basis of a number of
/// [`TypedInfo`] handlers. Invoke this macro inside a [`GenServer`] impl block.
///
/// # Example
///
/// ```rust
/// # use ts_actor::gen_server::{self, GenServer};
/// struct MyGenServer;
///
/// impl GenServer for MyGenServer {
///     // ...
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
///
///     ts_actor::typed_info!(u8);
/// }
///
/// ts_actor::impl_info!(MyGenServer, u8, ctx, state, msg, {
///     println!("got u8: {msg}");
///     None
/// });
/// ```
#[macro_export]
macro_rules! typed_info {
    ($($msgty:ty),* $(,)?) => {
        async fn handle_info(
            &self,
            ctx: &$crate::ProcContext,
            state: &mut Self::State,
            message: $crate::Message,
        ) -> Option<$crate::gen_server::Action> {
            let result: Option<$crate::gen_server::Action> = $crate::msg_match! {
                message,
                $(
                    $msgty: msg => {
                        <Self as $crate::gen_server::TypedInfo<$msgty>>::handle_info(self, ctx, state, msg).await
                    },
                )*
                else _msg => {
                    None
                }
            };

            result
        }
    };
}

/// Boilerplate reduction for implementing [`TypedCall`].
///
/// # Example
///
/// ```rust
/// # use ts_actor::{impl_call, gen_server};
/// struct MyGenServer;
/// struct MyMessage(String);
/// struct MyReply(&'static str);
///
/// # impl ts_actor::gen_server::GenServer for MyGenServer {
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
/// # }
/// #
/// impl_call!(MyGenServer, MyMessage, MyReply, ctx, state, MyMessage(msg), handle, {
///     println!("got call: {msg}");
///     handle.commit(MyReply("hi")).into()
/// });
/// ```
#[macro_export]
macro_rules! impl_call {
    ($gs:ty, $msg:ty, $rep:ty, $ctx:pat, $state:pat, $t:pat, $handle:pat, $body:expr) => {
        impl $crate::gen_server::TypedCall<$msg> for $gs {
            type Reply = $rep;

            async fn handle_call(
                &self,
                $ctx: &$crate::ProcContext,
                $state: &mut Self::State,
                $t: $msg,
                $handle: $crate::gen_server::TypedReplyHandle<$rep>,
            ) -> $crate::gen_server::TypedCallResult<$rep> {
                $body
            }
        }
    };
}

/// Boilerplate reduction for implementing [`TypedCast`].
///
/// # Example
///
/// ```rust
/// # use ts_actor::{impl_cast, gen_server};
/// struct MyGenServer;
/// struct MyMessage(String);
///
/// # impl ts_actor::gen_server::GenServer for MyGenServer {
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
/// # }
/// #
/// impl_cast!(MyGenServer, MyMessage, ctx, state, MyMessage(msg), {
///     println!("got cast message: {msg}");
///     None
/// });
/// ```
#[macro_export]
macro_rules! impl_cast {
    ($gs:ty, $msg:ty, $ctx:pat, $state:pat, $t:pat, $body:expr) => {
        impl $crate::gen_server::TypedCast<$msg> for $gs {
            async fn handle_cast(
                &self,
                $ctx: &$crate::ProcContext,
                $state: &mut Self::State,
                $t: $msg,
            ) -> Option<$crate::gen_server::Action> {
                $body
            }
        }
    };
}

/// Boilerplate reduction for implementing [`TypedInfo`].
///
/// # Example
///
/// ```rust
/// # use ts_actor::{impl_info, gen_server};
/// struct MyGenServer;
/// struct MyMessage(String);
///
/// # impl ts_actor::gen_server::GenServer for MyGenServer {
/// #   type State = ();
/// #   type Args = ();
/// #
/// #   async fn init(&self, ctx: &ts_actor::ProcContext, args: Self::Args) -> Result<(Self::State, Option<gen_server::Action>), ts_actor::Error> {
/// #       Ok(((), None))
/// #   }
/// # }
/// #
/// impl_info!(MyGenServer, MyMessage, ctx, state, MyMessage(msg), {
///     println!("got info message: {msg}");
///     None
/// });
/// ```
#[macro_export]
macro_rules! impl_info {
    ($gs:ty, $msg:ty, $ctx:pat, $state:pat, $t:pat, $body:expr) => {
        impl $crate::gen_server::TypedInfo<$msg> for $gs {
            async fn handle_info(
                &self,
                $ctx: &$crate::ProcContext,
                $state: &mut Self::State,
                $t: $msg,
            ) -> Option<$crate::gen_server::Action> {
                $body
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Error, gen_server, runtime, runtime::Tokio};

    #[tokio::test]
    async fn typed() {
        struct Dummy;

        impl TypedCall<u8> for Dummy {
            type Reply = u16;

            async fn handle_call(
                &self,
                _ctx: &ProcContext,
                _state: &mut Self::State,
                message: u8,
                caller_handle: TypedReplyHandle<Self::Reply>,
            ) -> (Option<TypedReply<Self::Reply>>, Option<Action>) {
                (Some(caller_handle.commit((message as u16).pow(2))), None)
            }
        }

        impl TypedCall<u16> for Dummy {
            type Reply = u32;

            async fn handle_call(
                &self,
                _ctx: &ProcContext,
                _state: &mut Self::State,
                message: u16,
                caller_handle: TypedReplyHandle<Self::Reply>,
            ) -> (Option<TypedReply<Self::Reply>>, Option<Action>) {
                (Some(caller_handle.commit((message as u32).pow(2))), None)
            }
        }

        impl GenServer for Dummy {
            type Args = ();
            type State = ();

            async fn init(
                &self,
                _ctx: &ProcContext,
                _args: Self::Args,
            ) -> Result<(Self::State, Option<Action>), Error> {
                Ok(core::default::Default::default())
            }

            typed_call! {
                u8,
            }
        }

        let rt = runtime::new(Tokio::current());

        let pid = rt.spawn(gen_server::start(Dummy, ())).unwrap();

        let ret = rt
            .run(async move |ctx| {
                let result = call_typed::<_, Dummy>(&ctx, &pid, 2u8).await?;

                Ok(result)
            })
            .await
            .unwrap();

        assert_eq!(ret, 4);
    }
}
