//! Facilities for sending asynchronous responses from NIFs.
//!
//! The motivation is that the Erlang DirtyIO scheduler is a thread-pool with inherently
//! limited concurrency (n = threads in the pool), and our NIFs will have to block a whole
//! thread on that pool while they're doing anything, even if it's asynchronous work running
//! on tokio.
//!
//! To avoid that, we adopt a more Erlang/Elixir-oriented approach and respond via message
//! passing. This doesn't block the BEAM at all, specifically because we're essentially
//! interacting with its event loop directly, rather than through the opaque abstraction of
//! a function running on a foreign thread.
//!
//! Our NIFs with async work to do return immediately with `{:async, REF}`, where `REF` is a
//! BEAM reference that uniquely identifies the function invocation. In the background, we
//! do whatever we need to and reply eventually (to the original caller's pid) with a
//! message holding the result of the function call and the original `REF` for correlation.

use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;
use rustler::{Encoder, NifResult, OwnedEnv, Term};

use crate::{TOKIO_RUNTIME, atoms};

pub type AsyncReply<'a> = (rustler::Atom, rustler::Reference<'a>);

/// Spiritual reimplementation of [`rustler::thread::spawn`] for futures.
///
/// `fut` is executed in a tokio task, and the result is passed to `post`, which encodes a
/// result to pass back to `pid` as a message. If `fut` or `post` panics, `on_panic` is
/// invoked instead with the encoded reason for the panic, and the returned term is passed
/// back to the calling `pid`.
///
/// Returns a [`rustler::Reference`] which uniquely identifies this particular spawn call.
/// The same reference is also provided to `post` and `on_panic`; they may or may not choose
/// to make use of it for correlation.
///
/// NB: this function intentionally does not encode any specifics about the response format.
/// Conventionally, our NIFs respond with `{{:tailscale, REF}, PAYLOAD}`, but this function
/// is general-purpose and doesn't make that assumption: it responds with whatever you
/// tell it to, in the interest of separating concerns. The pieces specific to our current
/// async reply convention are encoded in [`reply_async`] and [`try_reply_async`].
pub fn spawn<F, Post, OnPanic>(
    env: rustler::Env,
    fut: F,
    post: Post,
    on_panic: OnPanic,
) -> rustler::Reference
where
    F: Future + Send + 'static,
    F::Output: std::panic::UnwindSafe,
    Post: for<'env> FnOnce(rustler::Env<'env>, rustler::Reference<'env>, F::Output) -> Term<'env>
        + Send
        + std::panic::UnwindSafe
        + 'static,
    OnPanic: for<'env> FnOnce(rustler::Env<'env>, rustler::Reference<'env>, Term<'env>) -> Term<'env>
        + Send
        + 'static,
{
    let pid = env.pid();
    let ref_ = env.make_ref();

    let mut env = OwnedEnv::new();
    let saved_ref = env.save(ref_);

    TOKIO_RUNTIME.spawn(async move {
        let result = AssertUnwindSafe(fut).catch_unwind().await.and_then(|result| {
            std::panic::catch_unwind(|| {
                if env.run(|env| {
                    let ref_ = saved_ref.load(env).decode::<rustler::Reference>().unwrap();
                    let value = post(env, ref_, result).encode(env);

                    env.send(&pid, value)
                }).is_err() {
                    tracing::error!(target_pid = ?pid.as_c_arg(), "failed sending success reply from spawn, process dead?");
                }
            })
        });

        if let Err(err) = result {
            let send_result = env.send_and_clear(&pid, move |env| {
                let ref_ = saved_ref.load(env).decode::<rustler::Reference>().unwrap();

                let reason = if let Some(string) = err.downcast_ref::<String>() {
                    string.encode(env)
                } else if let Some(&s) = err.downcast_ref::<&'static str>() {
                    s.encode(env)
                } else {
                    ().encode(env)
                };

                on_panic(env, ref_, reason)
            });

            if send_result.is_err() {
                tracing::error!(target_pid = ?pid.as_c_arg(), "failed sending panic reply from spawn, process dead?");
            }
        }
    });

    ref_
}

/// Convenience wrapper for [`spawn`] when the return type is [`crate::Result`],
/// automatically converting the response to a reply
/// `{:ok, TERM} | {:error, TERM} | {:nif_panic, TERM} | {:raise | TERM}` wrapped in
/// `{:tailscale, ref, REPLY}`.
pub fn try_reply_async<F, T>(env: rustler::Env, fut: F) -> AsyncReply
where
    F: Future<Output = NifResult<T>> + Send + 'static,
    T: Encoder,
{
    let ref_ = spawn(
        env,
        async move { AssertUnwindSafe(fut.await) },
        move |env, ref_, t| {
            let resp = match t.0 {
                Ok(val) => (atoms::ok(), val).encode(env),
                Err(e) => encode_async_err(env, e),
            };

            async_resp(ref_, resp).encode(env)
        },
        move |env, ref_, reason| async_resp(ref_, (atoms::nif_panic(), reason)).encode(env),
    );

    (atoms::async_(), ref_)
}

#[rustler::nif]
fn raise_badarg() -> NifResult<()> {
    Err(rustler::Error::BadArg)
}

pub fn async_resp<'r, T>(ref_: rustler::Reference<'r>, value: T) -> (AsyncReply<'r>, T) {
    ((atoms::tailscale(), ref_), value)
}

/// Encode the given [`rustler::Error`] as a [`Term`].
///
/// This is needed because [`rustler::Error`] typically expects to be returned from a NIF,
/// where it can directly raise exceptions on the [`Env`]. We don't want to do that here, we
/// want to forward the exception to raise through message passing. On the Elixir side,
/// `Tailscale.Util.normalize_result` handles converting the value into the correct form
/// (`{:error, TERM}` or a raised exception).
fn encode_async_err(env: rustler::Env, err: rustler::Error) -> Term {
    match err {
        rustler::Error::Term(b) => (atoms::error(), b.encode(env)).encode(env),
        rustler::Error::Atom(a) => match rustler::Atom::from_str(env, a) {
            Ok(atom) => env.error_tuple(atom),
            Err(_e) => (atoms::raise(), atoms::badarg()).encode(env),
        },
        rustler::Error::BadArg => (atoms::raise(), atoms::badarg()).encode(env),
        rustler::Error::RaiseAtom(atom) => match rustler::Atom::from_str(env, atom) {
            Ok(atom) => (atoms::raise(), atom).encode(env),
            Err(_e) => (atoms::raise(), atoms::badarg()).encode(env),
        },
        rustler::Error::RaiseTerm(t) => (atoms::raise(), t.encode(env)).encode(env),
    }
}
