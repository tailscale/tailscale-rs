use core::fmt::{Debug, Display, Formatter};

use crate::{DiscoKey, Export, MachineKey, NetworkLockKey, NodeKey, Pair};

/// The portion of the key state that should be retained between runs of the same device.
///
/// Disco keys are ephemeral and should be generated anew each time a device runs, so are
/// excluded from this state.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistState {
    /// The machine private key for the hardware this Tailnet peer runs on.
    pub machine_key: Export<MachineKey>,

    /// The network lock private key for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_key: Export<NetworkLockKey>,

    /// The node private key for this Tailnet peer.
    pub node_key: Export<NodeKey>,
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
            machine_key: Export::random(),
            network_lock_key: Export::random(),
            node_key: Export::random(),
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
    pub disco_keys: Pair<DiscoKey>,

    /// The machine keypair for the hardware this Tailnet peer runs on.
    pub machine_keys: Pair<MachineKey>,

    /// The network lock keypair for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_keys: Pair<NetworkLockKey>,

    /// The node keypair for this Tailnet peer.
    pub node_keys: Pair<NodeKey>,
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
