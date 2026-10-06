use core::marker::PhantomData;

use crate::{
    Error, Message, ProcContext, ProcName, ToProcName, gen_server,
    gen_server::{GenServer, TypedCall, TypedCast},
};

/// Convenience handle to a genserver of a known, particular type.
///
/// Used primarily to avoid having to turbofish the genserver type in typed calls and casts.
pub struct GenServerHandle<'ctx, GS> {
    name: ProcName,
    ctx: &'ctx ProcContext,
    gs: PhantomData<GS>,
}

impl<'ctx, GS> GenServerHandle<'ctx, GS>
where
    GS: GenServer,
{
    /// Construct a new [`GenServerHandle`] for a genserver of name `name`.
    pub fn new(ctx: &'ctx ProcContext, name: &dyn ToProcName) -> Self {
        Self {
            ctx,
            name: name.to_proc_name(),
            gs: PhantomData,
        }
    }

    /// Send a `call` to the server with message `msg`.
    pub async fn call(&self, msg: Message) -> Result<Message, Error> {
        gen_server::call(self.ctx, &self.name, msg).await
    }

    /// Send a `cast` to the server with message `msg`.
    pub async fn cast(&self, msg: Message) -> Result<(), Error> {
        gen_server::cast(self.ctx, &self.name, msg).await
    }

    /// Send a typed call with a message of type `M`.
    pub async fn call_typed<M>(&self, msg: M) -> Result<GS::Reply, Error>
    where
        GS: TypedCall<M>,
        M: Send + 'static,
    {
        gen_server::call_typed::<M, GS>(self.ctx, &self.name, msg).await
    }

    /// Send a typed cast with a message of type `M`.
    ///
    /// See [`gen_server::cast_typed`].
    pub async fn cast_typed<M>(&self, msg: M) -> Result<(), Error>
    where
        GS: TypedCast<M>,
        M: Send + 'static,
    {
        gen_server::cast_typed::<M, GS>(self.ctx, &self.name, msg).await
    }

    /// Try to send a typed cast with a message of type `M`. Doesn't wait for capacity in
    /// the receiver's mailbox.
    ///
    /// See [`gen_server::try_cast_typed`].
    pub async fn try_cast_typed<M>(&self, msg: M) -> Result<(), Error>
    where
        GS: TypedCast<M>,
        M: Send + 'static,
    {
        gen_server::try_cast_typed::<M, GS>(self.ctx, &self.name, msg).await
    }
}
