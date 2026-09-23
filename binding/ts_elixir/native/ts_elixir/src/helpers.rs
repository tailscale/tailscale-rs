use std::{error::Error, fmt::Display, net::SocketAddr};

use rustler::{Encoder, NifResult, ResourceArc, Term};

use crate::{atoms, erl_ip::ErlIp};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync + 'static>>;

/// Wrap the given [`rustler::Resource`] in a [`ResourceArc`] inside a [`NifResult`].
pub fn ok_arc<T>(t: T) -> NifResult<ResourceArc<T>>
where
    T: rustler::Resource,
{
    Ok(ResourceArc::new(t))
}

/// Convert the argument into a [`rustler::Error`] by making it into a string.
pub fn term_err(e: impl Display) -> rustler::Error {
    rustler::Error::Term(Box::new(e.to_string()))
}

pub fn sockaddr_to_erl(addr: SocketAddr) -> (ErlIp, u16) {
    (ErlIp(addr.ip()), addr.port())
}

pub fn erl_result(env: rustler::Env, r: Result<impl Encoder>) -> NifResult<Term> {
    match r {
        Ok(t) => Ok((atoms::ok(), t).encode(env)),
        Err(e) => Err(term_err(e)),
    }
}
