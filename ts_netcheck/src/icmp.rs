use std::io;
use socket2::{Domain, Protocol, Type};

pub struct IcmpProber {}

impl IcmpProber {
    pub fn new() -> io::Result<Self> {
        let sock = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        sock.send_to(b"icmp", )?;
        sock.
    }
}
