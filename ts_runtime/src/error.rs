use core::fmt::{Formatter, Write};

use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    error::{HookError, Infallible, SendError},
};

pub(crate) trait ResultExt {
    type T;

    /// Attach actor info to this result if it's an error.
    fn with_actor_info(self, aref: impl Into<ActorInfo>) -> Result<Self::T, Error>;
}

impl<T, E> ResultExt for Result<T, E>
where
    E: Into<Error>,
{
    type T = T;

    fn with_actor_info(self, aref: impl Into<ActorInfo>) -> Result<T, Error> {
        self.map_err(|e| e.into().with_actor_info(aref))
    }
}

/// Errors that may occur while executing or interacting with the runtime.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Error {
    /// Kind of error this is.
    pub kind: ErrorKind,

    /// Rust type name of sent message that caused the error.
    ///
    /// May not be populated if this was not generated as a result of sending a message.
    pub message_ty: Option<&'static str>,

    /// Actor to which the message was being sent (optional).
    ///
    /// May not be populated if either this wasn't from an actor message, or the actor ref
    /// wasn't available when the error was constructed.
    pub target_actor: Option<ActorInfo>,
}

impl Error {
    /// Attach information about a destination actor to this error.
    ///
    /// Typically, `aref` will be `&ActorRef`.
    pub fn with_actor_info(self, aref: impl Into<ActorInfo>) -> Self {
        Self {
            target_actor: Some(aref.into()),
            ..self
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // format is "sending MESSAGE_TYPE to ACTOR: ERROR_DESC", the complexity is to account for
        // independently-optional fields

        if let Some(ty) = self.message_ty {
            write!(f, "sending {ty}")?;

            if self.target_actor.is_some() {
                f.write_char(' ')?;
            }
        }

        if let Some(actor) = &self.target_actor {
            write!(f, "{actor}")?;
        }

        if self.message_ty.is_some() || self.target_actor.is_some() {
            f.write_str(": ")?;
        }

        self.kind.fmt(f)
    }
}

impl core::error::Error for Error {}

impl<M, E> From<SendError<M, E>> for Error {
    fn from(err: SendError<M, E>) -> Self {
        Self {
            kind: err.into(),
            message_ty: Some(core::any::type_name::<M>()),
            target_actor: None,
        }
    }
}

impl<E> From<HookError<E>> for Error {
    fn from(value: HookError<E>) -> Self {
        match value {
            HookError::Error(_) => Self {
                kind: ErrorKind::ReplyErr,
                target_actor: None,
                message_ty: Some("ActorStartOrStop"),
            },
            HookError::Panicked(_) => Self {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: Some("ActorStartOrStop"),
            },
        }
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

/// Info about an actor that caused an error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ActorInfo {
    /// The Rust type name of the actor.
    pub ty: &'static str,

    /// The actor's unique id.
    pub id: kameo::actor::ActorId,
}

impl<A> From<&ActorRef<A>> for ActorInfo
where
    A: Actor,
{
    fn from(aref: &ActorRef<A>) -> Self {
        Self {
            ty: core::any::type_name::<A>(),
            id: aref.id(),
        }
    }
}

impl<A> From<ActorRef<A>> for ActorInfo
where
    A: Actor,
{
    fn from(aref: ActorRef<A>) -> Self {
        Self::from(&aref)
    }
}

impl<A> From<&WeakActorRef<A>> for ActorInfo
where
    A: Actor,
{
    fn from(aref: &WeakActorRef<A>) -> Self {
        Self {
            ty: core::any::type_name::<A>(),
            id: aref.id(),
        }
    }
}

impl<A> From<WeakActorRef<A>> for ActorInfo
where
    A: Actor,
{
    fn from(aref: WeakActorRef<A>) -> Self {
        Self::from(&aref)
    }
}

impl core::fmt::Display for ActorInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", self.ty, self.id)
    }
}

/// Kinds of errors that may occur while running the runtime.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// An actor that was expected to be available was unreachable, probably because it
    /// either panicked or exited. It's unlikely this operation can be retried successfully.
    ActorGone,

    /// The actor replied with an error.
    ReplyErr,

    /// The target actor's mailbox was full.
    MailboxFull,

    /// An operation timed out.
    Timeout,
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActorGone => write!(f, "expected actor is unreachable"),
            Self::ReplyErr => write!(f, "actor replied with an error"),
            Self::MailboxFull => write!(f, "actor's mailbox was full"),
            Self::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl<M, E> From<SendError<M, E>> for ErrorKind {
    fn from(err: SendError<M, E>) -> Self {
        match err {
            SendError::ActorNotRunning(_) | SendError::ActorStopped => ErrorKind::ActorGone,
            SendError::HandlerError(_) => ErrorKind::ReplyErr,
            SendError::MailboxFull(..) => ErrorKind::MailboxFull,
            SendError::Timeout(_) => ErrorKind::Timeout,
        }
    }
}
