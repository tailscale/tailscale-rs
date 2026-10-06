//! Implementation of a process registry.

use alloc::collections::{BTreeMap, BTreeSet};

use smol_str::SmolStr;

use crate::{
    Error, Message, ProcContext, ToProcName, gen_server,
    gen_server::{GenServer, TypedCallResult, TypedReplyHandle},
    pid::Pid,
    protocol, typed_call, typed_cast, typed_info,
};

/// Register `pid` as `name` in `registry`.
pub async fn register(
    ctx: &ProcContext,
    registry: &dyn ToProcName,
    pid: Pid,
    name: SmolStr,
) -> Result<(), Error> {
    gen_server::cast_typed::<_, Registry>(ctx, registry, Register { id: pid, name }).await
}

/// Remove the registration for `name` from `registry`.
pub async fn unregister(
    ctx: &ProcContext,
    registry: &dyn ToProcName,
    name: SmolStr,
) -> Result<(), Error> {
    gen_server::cast_typed::<_, Registry>(ctx, registry, Unregister { name }).await
}

/// Lookup the given process `name` in `registry`.
pub async fn lookup(
    ctx: &ProcContext,
    registry: &dyn ToProcName,
    name: SmolStr,
) -> Result<Option<Pid>, Error> {
    gen_server::call_typed::<_, Registry>(ctx, registry, Lookup { name }).await
}

/// Wait (indefinitely) for the given process name to appear in `registry`.
pub async fn wait_for(
    ctx: &ProcContext,
    registry: &dyn ToProcName,
    name: SmolStr,
) -> Result<Pid, Error> {
    gen_server::call_typed::<_, Registry>(ctx, registry, WaitFor { name }).await
}

/// A process registry, mapping string names onto pids.
pub struct Registry;

/// State of a [`Registry`].
#[derive(Default)]
pub struct State {
    registrations: BTreeMap<SmolStr, Pid>,
    waiters: BTreeMap<SmolStr, BTreeSet<TypedReplyHandle<Pid>>>,
}

impl gen_server::TypedCast<Register> for Registry {
    async fn handle_cast(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        Register { id, name }: Register,
    ) -> Option<gen_server::Action> {
        let waiters = state.waiters.remove(&name);
        state.registrations.insert(name, id);

        for waiter in waiters.into_iter().flatten() {
            waiter.reply(ctx, id).await;
        }

        None
    }
}

impl gen_server::TypedCast<Unregister> for Registry {
    async fn handle_cast(
        &self,
        _ctx: &ProcContext,
        state: &mut Self::State,
        Unregister { name }: Unregister,
    ) -> Option<gen_server::Action> {
        state.registrations.remove(&name);
        None
    }
}

impl gen_server::TypedCall<Lookup> for Registry {
    type Reply = Option<Pid>;

    async fn handle_call(
        &self,
        _ctx: &ProcContext,
        state: &mut Self::State,
        Lookup { name }: Lookup,
        handle: TypedReplyHandle<Self::Reply>,
    ) -> TypedCallResult<Self::Reply> {
        let resp = state.registrations.get(&name).copied();

        handle.commit(resp).into()
    }
}

impl gen_server::TypedCall<WaitFor> for Registry {
    type Reply = Pid;

    async fn handle_call(
        &self,
        _ctx: &ProcContext,
        state: &mut Self::State,
        WaitFor { name }: WaitFor,
        caller_handle: TypedReplyHandle<Self::Reply>,
    ) -> TypedCallResult<Self::Reply> {
        if let Some(&id) = state.registrations.get(&name) {
            caller_handle.commit(id).into()
        } else {
            state.waiters.entry(name).or_default().insert(caller_handle);

            (None, None)
        }
    }
}

impl gen_server::TypedCall<Forward> for Registry {
    type Reply = Result<(), Error>;

    async fn handle_call(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        Forward { name, message }: Forward,
        caller_handle: TypedReplyHandle<Self::Reply>,
    ) -> TypedCallResult<Self::Reply> {
        let Some(&id) = state.registrations.get(&name) else {
            return caller_handle.commit(Err(Error::NoProc)).into();
        };

        let result = ctx.try_send(&id, message).await;
        if let Err(Error::NoProc) = &result {
            state.registrations.remove(&name);
        }

        if let Err(e) = result {
            tracing::warn!(error = %e, %name, "registry forward failed");
        }

        caller_handle.commit(result.map(|_| ())).into()
    }
}

// Handle the generic registry lookup protocol
impl gen_server::TypedInfo<protocol::registry::Lookup> for Registry {
    async fn handle_info(
        &self,
        ctx: &ProcContext,
        state: &mut Self::State,
        protocol::registry::Lookup { reply, name, rf }: protocol::registry::Lookup,
    ) -> Option<gen_server::Action> {
        let resp = protocol::registry::Reply {
            rf,
            pid: state.registrations.get(&name).copied(),
        };

        if let Err(e) = ctx.try_send(&reply, crate::message![resp]).await {
            tracing::warn!(err = %e, "failed to reply to reg lookup");
        }

        None
    }
}

impl GenServer for Registry {
    type Args = ();
    type State = State;

    async fn init(
        &self,
        _: &ProcContext,
        _: Self::Args,
    ) -> Result<(Self::State, Option<gen_server::Action>), Error> {
        Ok(Default::default())
    }

    typed_call!(Lookup, WaitFor, Forward);
    typed_cast!(Register, Unregister);
    typed_info!(protocol::registry::Lookup);
}

/// Register the given pid under the given name.
struct Register {
    id: Pid,
    name: SmolStr,
}

struct Unregister {
    name: SmolStr,
}

struct Lookup {
    name: SmolStr,
}

struct Forward {
    name: SmolStr,
    message: Message,
}

struct WaitFor {
    name: SmolStr,
}

#[cfg(test)]
mod test {
    use crate::{gen_server, runtime, runtime::Tokio};

    #[tokio::test]
    async fn reg_unreg() {
        let rt = runtime::new(Tokio::current());

        let reg_pid = rt.spawn(gen_server::start(super::Registry, ())).unwrap();

        rt.run(async move |ctx| {
            let resp = super::lookup(&ctx, &reg_pid, "abc".into()).await?;
            assert_eq!(resp, None);

            super::register(&ctx, &reg_pid, ctx.pid(), "abc".into()).await?;
            let resp = super::lookup(&ctx, &reg_pid, "abc".into()).await?;
            assert_eq!(resp, Some(ctx.pid()));

            super::unregister(&ctx, &reg_pid, "abc".into()).await?;
            let resp = super::lookup(&ctx, &reg_pid, "abc".into()).await?;
            assert_eq!(resp, None);

            Ok(())
        })
        .await
        .unwrap();
    }
}
