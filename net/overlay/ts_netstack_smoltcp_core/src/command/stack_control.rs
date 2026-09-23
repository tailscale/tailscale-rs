//! Commands that mutate network stack configuration.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::command;

/// Mutate the network stack's configuration.
#[derive(Debug)]
pub enum Command {
    /// Set the network interface's IPs.
    SetIps {
        /// IPs to assign to the netstack's interface.
        ///
        /// If the netstack was configured with
        /// [`Config::loopback`](crate::Config::loopback) enabled, the loopback addresses
        /// should not be included here.
        ///
        /// May fail if `smoltcp` was not configured with a sufficient
        /// `iface-max-addr-count-*` (feature flag).
        new_ips: Vec<IpAddr>,
    },
}

impl From<Command> for command::Command {
    fn from(command: Command) -> Self {
        command::Command::StackControl(command)
    }
}
