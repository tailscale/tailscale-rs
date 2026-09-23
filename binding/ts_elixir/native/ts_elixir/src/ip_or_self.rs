use std::net::IpAddr;

use rustler::{Error, NifResult, Term};

use crate::{atoms, erl_ip::ErlIp};

/// A literal IP address, the atom `:ip4`, or the atom `:ip6`.
///
/// The latter two mean this node's IPv4 or IPv6 address, respectively.
pub enum IpOrSelf {
    Ip(ErlIp),
    SelfV4,
    SelfV6,
}

impl<'a> rustler::Decoder<'a> for IpOrSelf {
    fn decode(ip: Term<'a>) -> NifResult<Self> {
        if let Ok(ip) = ip.decode::<ErlIp>() {
            return Ok(Self::Ip(ip));
        }

        let atom = ip.decode::<rustler::Atom>()?;
        if atom == atoms::ip4() {
            return Ok(Self::SelfV4);
        }

        if atom == atoms::ip6() {
            return Ok(Self::SelfV6);
        }

        Err(Error::BadArg)
    }
}

impl IpOrSelf {
    pub async fn resolve(&self, dev: &tailscale::Device) -> NifResult<IpAddr> {
        match self {
            IpOrSelf::Ip(ip) => Ok(ip.0),
            IpOrSelf::SelfV4 => dev
                .ipv4_addr()
                .await
                .map(Into::into)
                .map_err(|e| Error::Term(Box::new(e.to_string()))),
            IpOrSelf::SelfV6 => dev
                .ipv6_addr()
                .await
                .map(Into::into)
                .map_err(|e| Error::Term(Box::new(e.to_string()))),
        }
    }
}
