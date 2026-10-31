//! Generic registry protocol: to register a process, send [`Lookup`], receive
//! [`Reply`].

use smol_str::SmolStr;

use crate::{Handle, Pid};

/// Request to look up a process by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The process to reply to.
    pub reply: Pid,
    /// The name to look up.
    pub name: SmolStr,
    /// [`Handle`] for correlation.
    pub rf: Handle,
}

/// Response to a [`Lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The same [`Handle`] as in the original [`Lookup`].
    pub rf: Handle,
    /// The lookup result, if found.
    pub pid: Option<Pid>,
}
