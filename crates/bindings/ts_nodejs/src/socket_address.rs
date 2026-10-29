use std::net::SocketAddr;

use napi_derive::napi;

/// An IP address and port, e.g. `{ address: "100.64.0.1", port: 1234 }`.
#[napi(object, object_to_js = false)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddress {
    /// IP address, in string form.
    pub address: String,
    /// Port number.
    pub port: u16,
}

impl TryFrom<SocketAddress> for SocketAddr {
    type Error = napi::Error;

    fn try_from(value: SocketAddress) -> Result<Self, Self::Error> {
        let ip = value.address.parse().map_err(crate::error::js_arg_err)?;
        Ok(SocketAddr::new(ip, value.port))
    }
}

/// An IP address, address family, and port, similar to Node's `net.AddressInfo`.
#[napi(object, object_from_js = false)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo {
    /// IP address, in string form.
    pub address: String,
    /// Address family (`IPv4` or `IPv6`).
    #[napi(ts_type = "'IPv4' | 'IPv6'")]
    pub family: String,
    /// Port number.
    pub port: u16,
}

impl From<SocketAddr> for AddressInfo {
    fn from(value: SocketAddr) -> Self {
        Self {
            address: value.ip().to_string(),
            family: if value.is_ipv4() { "IPv4" } else { "IPv6" }.to_owned(),
            port: value.port(),
        }
    }
}
