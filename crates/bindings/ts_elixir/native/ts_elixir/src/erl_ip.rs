use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use rustler::{Encoder, NifResult, Term};

/// Erlang-formatted IP.
///
/// Supports decoding from either a string or `:inet` (tuple of octets or segments) format,
/// always encodes into the `:inet` format.
#[derive(Copy, Clone, Debug)]
pub struct ErlIp(pub IpAddr);

impl From<Ipv4Addr> for ErlIp {
    fn from(value: Ipv4Addr) -> Self {
        Self(value.into())
    }
}

impl From<Ipv6Addr> for ErlIp {
    fn from(value: Ipv6Addr) -> Self {
        Self(value.into())
    }
}

impl From<IpAddr> for ErlIp {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl From<ErlIp> for IpAddr {
    fn from(value: ErlIp) -> Self {
        value.0
    }
}

impl<'a> rustler::Decoder<'a> for ErlIp {
    fn decode(ip: Term<'a>) -> NifResult<Self> {
        if let Ok(tuple) = rustler::types::tuple::get_tuple(ip) {
            if tuple.len() == 4 {
                let mut octets = [0u8; 4];

                for (i, elem) in tuple.into_iter().take(4).enumerate() {
                    octets[i] = elem.decode()?;
                }

                return Ok(Self(Ipv4Addr::from_octets(octets).into()));
            }

            if tuple.len() == 8 {
                let mut segments = [0u16; 8];

                for (i, elem) in tuple.into_iter().take(8).enumerate() {
                    segments[i] = elem.decode()?;
                }

                return Ok(Self(Ipv6Addr::from_segments(segments).into()));
            }
        }

        if let Ok(s) = ip.decode::<&str>() {
            let ip = IpAddr::from_str(s).map_err(|e| {
                tracing::error!(error = %e, "parsing ip addr");

                rustler::Error::BadArg
            })?;

            return Ok(Self(ip));
        }

        Err(rustler::Error::BadArg)
    }
}

impl Encoder for ErlIp {
    fn encode<'a>(&self, env: rustler::Env<'a>) -> Term<'a> {
        match self.0 {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                (octets[0], octets[1], octets[2], octets[3]).encode(env)
            }
            IpAddr::V6(ip) => {
                // rustler doesn't provide `impl Encoder` for 8-length tuples
                let segments = ip.segments().map(|segment| segment.encode(env));

                let tuple = rustler::types::tuple::make_tuple(env, &segments);
                tuple.encode(env)
            }
        }
    }
}
