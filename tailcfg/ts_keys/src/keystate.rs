use core::fmt::{Debug, Display, Formatter};

use crate::{DiscoKeyPair, Export, ExportableKey, MachineKeyPair, NetworkLockKeyPair, NodeKeyPair};

/// The portion of the key state that should be retained between runs of the same device.
///
/// Disco keys are ephemeral and should be generated anew each time a device runs, so are
/// excluded from this state.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistState {
    /// The [`crate::MachinePrivateKey`] for the hardware this Tailnet peer runs on.
    pub machine_key: Export<MachineKeyPair>,

    /// The [`crate::NetworkLockPrivateKey`] for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_key: Export<NetworkLockKeyPair>,

    /// The [`crate::NodePrivateKey`] for this Tailnet peer.
    pub node_key: Export<NodeKeyPair>,
}

impl From<&NodeState> for PersistState {
    fn from(value: &NodeState) -> Self {
        Self {
            node_key: value.node_keys.export(),
            machine_key: value.machine_keys.export(),
            network_lock_key: value.network_lock_keys.export(),
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
            machine_key: MachineKeyPair::random().export(),
            network_lock_key: NetworkLockKeyPair::random().export(),
            node_key: NodeKeyPair::random().export(),
        }
    }
}

/// The complete runtime key state for a Tailscale node.
#[derive(Clone)]
pub struct NodeState {
    /// The [`DiscoKeyPair`] this Tailnet peer uses for the Disco protocol.
    ///
    /// These should be randomly generated for each run of a Tailscale device.
    pub disco_keys: DiscoKeyPair,

    /// The [`MachineKeyPair`] for the hardware this Tailnet peer runs on.
    pub machine_keys: MachineKeyPair,

    /// The [`NetworkLockKeyPair`] for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_keys: NetworkLockKeyPair,

    /// The [`NodeKeyPair`] for this Tailnet peer.
    pub node_keys: NodeKeyPair,
}

impl Debug for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NodeState")
            .field(&self.machine_keys.public)
            .field(&self.node_keys.public)
            .field(&self.disco_keys.public)
            .field(&self.network_lock_keys.public)
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
        Self {
            machine_keys: MachineKeyPair::random(),
            node_keys: NodeKeyPair::random(),
            disco_keys: DiscoKeyPair::random(),
            network_lock_keys: NetworkLockKeyPair::random(),
        }
    }
}

impl From<&PersistState> for NodeState {
    fn from(value: &PersistState) -> Self {
        Self {
            disco_keys: DiscoKeyPair::random(),
            node_keys: value.node_key.import(),
            machine_keys: value.machine_key.import(),
            network_lock_keys: value.network_lock_key.import(),
        }
    }
}

impl From<PersistState> for NodeState {
    fn from(value: PersistState) -> Self {
        Self::from(&value)
    }
}
