use std::{fmt::Display, net::SocketAddr};

use rustler::{NifResult, ResourceArc};

use crate::erl_ip::ErlIp;

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
