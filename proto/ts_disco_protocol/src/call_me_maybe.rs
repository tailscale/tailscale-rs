use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
};

use crate::{Endpoint, Message, MessageType};

/// A message sent only over derp to request that the recipient try to opn a magicsock path
/// back to the sender.
///
/// The sender should have already sent UDP packets to the peer to open up the inbound
/// stateful firewall mappings.
///
/// The recipient may choose not to open a path back if it's already happy with its path,
/// but usually it will.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct CallMeMaybe {
    /// What the peer believes its endpoints are.
    ///
    /// Prior to Tailscale Go 1.4, these endpoints were only exchanged between nodes and
    /// the control server.
    ///
    /// Starting with Tailscale Go 1.4, clients advertise their endpoints. Older clients
    /// won't use this, but newer clients should use any endpoints here that aren't
    /// included from control
    ///
    /// Control might have sent stale endpoints if the client was idle before contacting
    /// us. In that case, the client likely did a STUN request immediately before sending
    /// this message to recreate its NAT port mapping, and that new good endpoint is
    /// included in this field, but might not yet be in control's endpoints. In the future,
    /// control will stop distributing endpoints when clients are suitably new.
    pub endpoints: [Endpoint],
}

impl Message for CallMeMaybe {
    const TYPE: MessageType = MessageType::CallMeMaybe;
}

impl CallMeMaybe {
    /// The size of a [`CallMeMaybe`] message containing the given number of endpoints.
    pub const fn size_for_endpoint_count(endpoint_count: usize) -> usize {
        size_of::<Endpoint>() * endpoint_count
    }
}

impl Debug for &CallMeMaybe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallMeMaybe")
            .field("endpoints", &&self.endpoints)
            .finish()
    }
}

impl PartialEq for &CallMeMaybe {
    fn eq(&self, other: &Self) -> bool {
        self.endpoints.eq(&other.endpoints)
    }
}

impl Eq for &CallMeMaybe {}

impl PartialOrd for &CallMeMaybe {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for &CallMeMaybe {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.endpoints.cmp(&other.endpoints)
    }
}

impl Hash for &CallMeMaybe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.endpoints.hash(state);
    }
}
