//! NIFs that intentionally return errors, panic, and raise exceptions.
//!
//! These are intended for testing the async message passing code and require the
//! `testing-nifs` feature flag to be enabled.

use rustler::{Env, Error};

use crate::async_reply::{AsyncReply, try_reply_async};

#[rustler::nif]
pub fn async_panic(env: Env, msg: Option<String>) -> AsyncReply {
    try_reply_async(env, async move {
        if let Some(msg) = msg {
            panic!("{msg}");
        } else {
            panic!()
        }

        // Needed to indicate return type
        #[allow(unreachable_code)]
        Ok(())
    })
}

#[rustler::nif]
pub fn async_error<'e>(env: Env<'e>, s: String, atom: bool) -> AsyncReply<'e> {
    try_reply_async(env, async move {
        Result::<(), _>::Err(if atom {
            Error::Atom(String::leak(s))
        } else {
            Error::Term(Box::new(s))
        })
    })
}

#[rustler::nif]
pub fn async_raise<'e>(env: Env<'e>, s: String, atom: bool) -> AsyncReply<'e> {
    try_reply_async(env, async move {
        Result::<(), _>::Err(if atom {
            Error::RaiseAtom(String::leak(s))
        } else {
            Error::RaiseTerm(Box::new(s))
        })
    })
}

#[rustler::nif]
pub fn async_badarg<'e>(env: Env<'e>) -> AsyncReply<'e> {
    try_reply_async(env, async move { Result::<(), _>::Err(Error::BadArg) })
}
