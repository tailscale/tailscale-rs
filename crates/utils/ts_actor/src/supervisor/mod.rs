//! Supervisor implementation modeling Erlang's `supervisor`.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::time::Duration;

use smol_str::SmolStr;

use crate::{
    Error, LinkExitReason, ProcContext, ProcFut, StaticProcFut, StaticStorage, SystemMessage,
    ToProcName, gen_server, gen_server::GenServer, pid::Pid,
};

struct State {
    child_ids: BTreeMap<Pid, SmolStr>,
    pid_lookup: BTreeMap<SmolStr, Pid>,
    specs: BTreeMap<SmolStr, ChildSpec>,
    config: Config,
}

/// Supervisor config.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// What to do with other children when a child dies and should be restarted.
    pub strategy: Strategy,
    /// How frequently to restart a failing child.
    pub restart_behavior: RestartBehavior,
}

/// Errors that may occur while starting a child.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartChildError {
    /// The requested child spec already exists in supervisor.
    #[error("child already exists with that id")]
    Exists,
    /// Another [`Error`] occurred while starting the child.
    #[error(transparent)]
    Other(#[from] Error),
}

struct StartChild(ChildSpec);

/// Dynamically add a child with the given `child_spec` to the supervisor process `sup`.
///
/// Returns [`StartChildError::Exists`] if there is already a child with the id in the
/// child spec.
pub async fn start_child(
    ctx: &ProcContext,
    sup: &dyn ToProcName,
    child_spec: ChildSpec,
) -> Result<Pid, StartChildError> {
    gen_server::call_typed::<_, Supervisor>(ctx, sup, StartChild(child_spec)).await?
}

struct Supervisor;

crate::impl_call!(Supervisor, StartChild, Result<Pid, StartChildError>, ctx, state, StartChild(child), caller_handle, {
    if state.specs.contains_key(&child.id) {
        tracing::error!(id = %child.id, "child with duplicate id");
        return caller_handle.commit(
            Err(StartChildError::Exists)
        ).into();
    }

    let id = child.id.clone();
    state.specs.insert(id.clone(), child);

    match spawn_child(ctx, state, &id) {
        Ok(pid) => caller_handle.commit(Ok(pid)).into(),

        Err(e) => {
            caller_handle.commit(Err(e.into())).into()
        }
    }
});

crate::impl_info!(Supervisor, SystemMessage, ctx, state, msg, {
    match msg {
        SystemMessage::LinkExit {
            reason,
            linked_process,
        } => {
            let Some(proc_name) = state.child_ids.remove(&linked_process) else {
                // TODO(npry): this means _we_ should die, since the process that died wasn't our
                //  child
                tracing::warn!(?linked_process, ?reason, "link exit for unknown process");
                return None;
            };

            let Some(child) = state.specs.get_mut(&proc_name) else {
                debug_assert!(false, "supervisor invariant violated: child spec missing");
                tracing::error!(?proc_name, "supervisor invariant error: child spec missing");
                return None;
            };

            let Some(pid) = state.pid_lookup.remove(&proc_name) else {
                debug_assert!(false, "supervisor invariant violated: child pid missing");
                tracing::error!(?proc_name, "supervisor invariant error: child pid missing");
                return None;
            };

            let should_restart = match child.restart {
                Restart::Permanent => true,
                Restart::Temporary => false,
                Restart::Transient => !matches!(reason, LinkExitReason::Normal),
            };

            let _span = tracing::debug_span!(
                "child_died",
                %pid,
                %proc_name,
                should_restart,
            )
            .entered();

            // TODO(npry): restart policy, supervision strategy
            let _config = &state.config;

            tracing::trace!("child died");

            if should_restart {
                if let Err(e) = spawn_child(ctx, state, &proc_name) {
                    tracing::error!(error = %e, %proc_name, "restarting child");
                } else {
                    tracing::trace!(%proc_name, "child restarted");
                }
            } else {
                let id = child.id.clone();
                state.specs.remove(&id);
            }
        }
        unknown => {
            tracing::debug!(?unknown, "unknown system message")
        }
    }

    None
});

impl GenServer for Supervisor {
    type Args = State;
    type State = State;

    async fn init(
        &self,
        ctx: &ProcContext,
        mut state: State,
    ) -> Result<(Self::State, Option<gen_server::Action>), Error> {
        ctx.trap_exit(true)?;

        let child_keys = state.specs.keys().cloned().collect::<Vec<_>>();
        for child_id in child_keys {
            // TODO(npry): gracefully handle child spawn failure
            spawn_child(ctx, &mut state, &child_id)?;
        }

        Ok((state, None))
    }

    crate::typed_call!(StartChild);
    crate::typed_info!(SystemMessage);
}

/// Start a supervisor with the given `config` and `children`.
///
/// Returns [`Error::BadArg`] if there is more than one child with the same id.
pub fn start(
    config: Config,
    children: impl IntoIterator<Item = ChildSpec>,
) -> Result<impl FnOnce(ProcContext) -> StaticStorage<ProcFut>, Error> {
    let mut state = State {
        config,
        child_ids: Default::default(),
        pid_lookup: Default::default(),
        specs: Default::default(),
    };

    for spec in children {
        let id = spec.id.clone();

        if let Some(_exists) = state.specs.insert(id.clone(), spec) {
            tracing::error!(%id, "duplicate child id");
            return Err(Error::BadArg);
        }
    }

    Ok(gen_server::start(Supervisor, state))
}

fn spawn_child(ctx: &ProcContext, state: &mut State, id: &SmolStr) -> Result<Pid, Error> {
    let Some(spec) = state.specs.get(id) else {
        return Err(Error::Other);
    };

    let start = spec.start.clone();
    let pid = ctx.spawn_link(move |ctx| start(ctx))?;

    state.child_ids.insert(pid, spec.id.clone());
    state.pid_lookup.insert(spec.id.clone(), pid);

    Ok(pid)
}

/// Behavior a supervisor adopts to handle child death.
#[derive(Debug, Clone)]
pub enum RestartBehavior {
    /// The supervisor limits start events to a maximum of once per the specified duration.
    /// It keeps trying to restart the child forever.
    RateLimit(Duration),

    /// A hard limit on child restart intensity over a given duration.
    ///
    /// If a child is restarted `intensity` times over `duration`, the supervisor gives up
    /// and terminates itself.
    HardLimit {
        /// The maximum number of restarts over `duration` before the supervisor gives up
        /// and shuts itself down.
        intensity: usize,
        /// The duration over which the intensity limit is counted.
        duration: Duration,
        /// If specified, limits the rate at which the supervisor attempts to restart the
        /// child.
        ///
        /// Can be provided as a baseline rate-limit to prevent spinning during an external
        /// error condition.
        min_period: Option<Duration>,
    },

    /// Linear backoff for child restarts.
    ///
    /// When a child dies and should be restarted, the supervisor waits for the current
    /// backoff value and attempts to start it again. If it fails, the backoff value is
    /// increased by `increase` (up to `max_duration`) before waiting again.
    ///
    /// Whenever the child starts up successfully, the backoff value is reset to
    /// `init_duration`.
    LinearBackoff {
        /// The initial duration of the backoff.
        init_duration: Duration,
        /// The amount the backoff is increased per child failure.
        increase: Duration,
        /// The maximum duration of the backoff.
        max_duration: Duration,
    },

    /// Exponential backoff for child restarts.
    ///
    /// When a child dies and should be restarted, the supervisor waits for the current
    /// backoff value and attempts to start it again. If it fails, the backoff value is
    /// multiplied by `backoff_factor` (up to `max_duration`) before waiting again.
    ///
    /// Whenever the child starts up successfully, the backoff value is reset back to
    /// `init_duration`.
    ExpBackoff {
        /// The initial backoff duration.
        init_duration: Duration,
        /// The maximum backoff duration.
        max_duration: Duration,
        /// The factor by which to multiply the current duration on each restart failure.
        backoff_factor: f32,
    },

    /// Token bucket restart limiting.
    ///
    /// When a child dies and should be restarted, a token bucket is consulted. If it has
    /// at least one token available, the child is restarted and a token is removed from the
    /// bucket. If no tokens are available, the supervisor waits until there is a token in
    /// the bucket before attempting to restart the child.
    TokenBucket {
        /// Maximum number of tokens in the bucket (per child).
        ///
        /// This is also used as the starting token count.
        max_tokens: usize,

        /// Period after which one token is added back to the bucket.
        refill_period: Duration,

        /// Minimum period at which the child is restarted.
        ///
        /// Can be provided as a baseline rate-limit on top of the token bucket behavior to
        /// prevent spinning during an error condition.
        ///
        /// Note: if this is greater than the refill period, the token bucket will do
        /// nothing.
        min_restart_period: Option<Duration>,
    },
}

impl Default for RestartBehavior {
    fn default() -> Self {
        Self::ExpBackoff {
            backoff_factor: 2.0,
            init_duration: Duration::from_millis(10),
            max_duration: Duration::from_secs(10),
        }
    }
}

/// What to do with other children when one child dies.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Strategy {
    /// When a child dies, it is the only process that is restarted.
    #[default]
    OneForOne,
    /// If any child dies, all of the supervisor's children are terminated and then all are
    /// restarted.
    OneForAll,
    /// If a child dies, all children spawned after it are terminated, and then they are all
    /// restarted.
    ///
    /// This enables the expression of a primitive linear dependency relationship between
    /// children without the need to write custom supervision logic.
    RestForOne,
}

/// Helper alias for a function which runs a child.
pub type MkChildProc<Fut> = dyn Fn(ProcContext) -> StaticStorage<Fut> + Send + Sync;

/// A supervisor child specification.
#[derive(Clone)]
pub struct ChildSpec {
    /// The id of this child.
    ///
    /// Must be unique within child specs for a given supervisor.
    pub id: SmolStr,
    /// Function to start the child process.
    pub start: Arc<MkChildProc<StaticProcFut>>,
    /// Restart behavior.
    pub restart: Restart,
    /// Shutdown behavior.
    pub shutdown: Shutdown,
    /// Type of this child.
    pub ty: ChildType,
}

/// Convenience helper to build a new child process function.
pub fn child_proc<Fut>(
    start: impl Fn(ProcContext) -> Fut + Send + Sync + 'static,
) -> impl Fn(ProcContext) -> StaticStorage<StaticProcFut> + Send + Sync
where
    Fut: Future<Output = Result<(), Error>> + Send + 'static,
{
    move |ctx| StaticStorage::Box(Box::new(start(ctx)))
}

impl ChildSpec {
    /// Construct a new [`ChildSpec`] from the given id and child proc.
    pub fn new<Fut>(id: SmolStr, start: impl Fn(ProcContext) -> Fut + Send + Sync + 'static) -> Self
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        ChildSpec {
            id,
            start: Arc::new(child_proc(start)),
            restart: Default::default(),
            shutdown: Default::default(),
            ty: ChildType::Worker,
        }
    }
}

/// Restart behavior for a supervisor child.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Restart {
    /// When this child dies, it is always restarted, even if it exited normally.
    #[default]
    Permanent,
    /// This child is restarted only if its exit condition was abnormal.
    Transient,
    /// This child is never restarted, even for an abnormal exit.
    ///
    /// This includes conditions where the child is terminated due to
    /// [`Strategy::OneForAll`] or [`Strategy::RestForOne`].
    Temporary,
}

/// Shutdown behavior for a supervisor child.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Shutdown {
    /// The child is killed immediately.
    Kill,

    /// The child's mailbox is closed, and it is given the specified amount of time to
    /// finish processing the remaining messages. If it doesn't complete processing before
    /// the timeout, it's killed.
    Timeout(Duration),

    /// The child's mailbox is closed, and it is given an unbounded amount of time to finish
    /// processing messages in its mailbox. It will never be killed.
    Polite,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::Timeout(Duration::from_millis(100))
    }
}

/// Type of child.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ChildType {
    /// Child is a normal process.
    #[default]
    Worker,
    /// Child is itself a supervisor.
    Supervisor,
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use core::time::Duration;

    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::util::SubscriberInitExt;

    use crate::{
        Error, LinkExitReason, ProcContext, SystemMessage, gen_server,
        gen_server::{Action, GenServer},
        msg_match,
        pid::Pid,
        runtime,
        runtime::{Rt, Tokio},
        supervisor,
        supervisor::{ChildSpec, Config, RestartBehavior, Strategy},
    };

    fn trace_init() {
        static ONCE: std::sync::Once = std::sync::Once::new();

        ONCE.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(LevelFilter::TRACE)
                .finish()
                .init();
        });
    }

    async fn assert_running(rt: &Arc<dyn Rt>, pid: Pid) {
        let result = rt
            .run(async move |ctx| ctx.whereis(&pid).await)
            .await
            .unwrap();

        assert_eq!(pid, result);
    }

    async fn assert_not_running(rt: &Arc<dyn Rt>, pid: Pid) {
        let result = rt.run(async move |ctx| ctx.whereis(&pid).await).await;

        assert_eq!(result, Err(Error::NoProc));
    }

    #[tokio::test]
    async fn no_children() {
        trace_init();

        let rt = runtime::new(Tokio::current());

        let pid = rt
            .spawn(
                supervisor::start(
                    Config {
                        strategy: Strategy::OneForOne,
                        restart_behavior: RestartBehavior::RateLimit(Duration::from_millis(5)),
                    },
                    [],
                )
                .unwrap(),
            )
            .unwrap();

        assert_running(&rt, pid).await;
    }

    #[tokio::test]
    async fn one_child() {
        trace_init();

        let rt = runtime::new(Tokio::current());

        struct Die;

        let pid = rt
            .spawn(
                supervisor::start(
                    Config {
                        strategy: Strategy::OneForOne,
                        restart_behavior: RestartBehavior::RateLimit(Duration::from_millis(5)),
                    },
                    [ChildSpec::new(
                        "foo".into(),
                        async move |ctx: ProcContext| {
                            ctx.register("foo").await?;

                            loop {
                                msg_match! {
                                    ctx.recv().await?,
                                    Die: _ => return Ok(()),
                                }
                            }
                        },
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert_running(&rt, pid).await;

        for _ in 0..32 {
            let child_pid = rt
                .run(async move |ctx| ctx.wait_proc("foo").await)
                .await
                .unwrap();

            assert_running(&rt, child_pid).await;
            tracing::trace!(%child_pid, "running");

            rt.run(async move |ctx| {
                ctx.trap_exit(true)?;
                ctx.link(&"foo").await?;

                ctx.send(&child_pid, crate::message![Die]).await?;

                tracing::trace!("notified child");

                loop {
                    msg_match! {
                        ctx.recv().await?,
                        SystemMessage: smsg => {
                            if let SystemMessage::LinkExit { linked_process, reason } = smsg {
                                assert_eq!(linked_process, child_pid);
                                assert_eq!(reason, LinkExitReason::Normal);
                                return Ok(())
                            }
                        },
                    }
                }
            })
            .await
            .unwrap();

            assert_not_running(&rt, child_pid).await;
        }
    }

    /// Ensure that the `genserver::start` types are compatible with `ChildSpec`.
    #[tokio::test]
    async fn spawn_genserver() {
        trace_init();

        let rt = runtime::new(Tokio::current());

        struct DummyGenserver;

        impl GenServer for DummyGenserver {
            type State = ();
            type Args = ();

            async fn init(
                &self,
                _ctx: &ProcContext,
                _args: Self::Args,
            ) -> Result<(Self::State, Option<Action>), Error> {
                Ok(((), None))
            }
        }

        let _pid = rt
            .spawn(
                supervisor::start(
                    Default::default(),
                    [ChildSpec::new("dummy".into(), async |ctx| {
                        gen_server::start(DummyGenserver, ())(ctx).await
                    })],
                )
                .unwrap(),
            )
            .unwrap();
    }
}
