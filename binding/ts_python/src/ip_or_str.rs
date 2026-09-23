use std::net::IpAddr;

/// IP address in python `ipaddress.IpAddress` form, or as a string.
#[derive(pyo3::FromPyObject)]
pub enum IpRepr {
    String(String),
    Ip(IpAddr),
}

impl TryFrom<IpRepr> for IpAddr {
    type Error = pyo3::PyErr;

    fn try_from(value: IpRepr) -> Result<Self, Self::Error> {
        match value {
            IpRepr::Ip(ip) => Ok(ip),
            IpRepr::String(s) => s.parse::<IpAddr>().map_err(crate::py_value_err),
        }
    }
}
