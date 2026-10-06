//! Generic registry protocol: to register a process, send [`Lookup`], receive
//! [`Reply`].

use smol_str::SmolStr;

use crate::{Pid, Ref};

/// Request to look up a process by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The process to reply to.
    pub reply: Pid,
    /// The name to look up.
    pub name: SmolStr,
    /// [`Ref`] for correlation.
    pub rf: Ref,
}

/// Response to a [`Lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The same [`Ref`] as in the original [`Lookup`].
    pub rf: Ref,
    /// The lookup result, if found.
    pub pid: Option<Pid>,
}
