use core::fmt::{Debug, Display, Formatter};

use crate::{Disco, ExportableKey, KeyPair, Machine, NetworkLock, Node};

/// The portion of the key state that should be retained between runs of the same device.
///
/// Disco keys are ephemeral and should be generated anew each time a device runs, so are
/// excluded from this state.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistState {
    /// The machine private key for the hardware this Tailnet peer runs on.
    pub machine_key: ExportableKey<Machine>,

    /// The network lock private key for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_key: ExportableKey<NetworkLock>,

    /// The node private key for this Tailnet peer.
    pub node_key: ExportableKey<Node>,
}

impl From<&NodeState> for PersistState {
    fn from(value: &NodeState) -> Self {
        Self {
            node_key: value.node_keys.private.clone().export(),
            machine_key: value.machine_keys.private.clone().export(),
            network_lock_key: value.network_lock_keys.private.clone().export(),
        }
    }
}

impl From<NodeState> for PersistState {
    fn from(value: NodeState) -> Self {
        Self::from(&value)
    }
}

impl Default for PersistState {
    fn default() -> Self {
        Self {
            machine_key: ExportableKey::random(),
            network_lock_key: ExportableKey::random(),
            node_key: ExportableKey::random(),
        }
    }
}

/// The complete runtime key state for a Tailscale node.
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct NodeState {
    /// The disco keypair this Tailnet peer uses for the Disco protocol.
    ///
    /// These should be randomly generated for each run of a Tailscale device.
    pub disco_keys: KeyPair<Disco>,

    /// The machine keypair for the hardware this Tailnet peer runs on.
    pub machine_keys: KeyPair<Machine>,

    /// The network lock keypair for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_keys: KeyPair<NetworkLock>,

    /// The node keypair for this Tailnet peer.
    pub node_keys: KeyPair<Node>,
}

impl Debug for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NodeState")
            .field(&self.machine_keys)
            .field(&self.node_keys)
            .field(&self.disco_keys)
            .field(&self.network_lock_keys)
            .finish()
    }
}

impl Display for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl NodeState {
    /// Generate a new [`NodeState`]. All keys get random values.
    pub fn generate() -> Self {
        Default::default()
    }
}

impl From<&PersistState> for NodeState {
    fn from(value: &PersistState) -> Self {
        Self {
            disco_keys: Default::default(),
            node_keys: value.node_key.clone().into(),
            machine_keys: value.machine_key.clone().into(),
            network_lock_keys: value.network_lock_key.clone().into(),
        }
    }
}

impl From<PersistState> for NodeState {
    fn from(value: PersistState) -> Self {
        Self::from(&value)
    }
}
