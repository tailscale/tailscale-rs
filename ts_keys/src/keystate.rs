use core::fmt::{Debug, Display, Formatter};

use crate::{
    DiscoKeyPair, MachineKeyPair, MachinePrivateKey, NetworkLockKeyPair, NetworkLockPrivateKey,
    NodeKeyPair, NodePrivateKey,
};

/// The portion of the key state that should be retained between runs of the same device.
///
/// Disco keys are ephemeral and should be generated anew each time a device runs, so are
/// excluded from this state.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistState {
    /// The [`MachinePrivateKey`] for the hardware this Tailnet peer runs on.
    pub machine_key: MachinePrivateKey,

    /// The [`NetworkLockPrivateKey`] for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_key: NetworkLockPrivateKey,

    /// The [`NodePrivateKey`] for this Tailnet peer.
    pub node_key: NodePrivateKey,
}

impl From<&NodeState> for PersistState {
    fn from(value: &NodeState) -> Self {
        Self {
            node_key: value.node_keys.private.clone(),
            machine_key: value.machine_keys.private.clone(),
            network_lock_key: value.network_lock_keys.private.clone(),
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
            machine_key: MachinePrivateKey::random(),
            network_lock_key: NetworkLockPrivateKey::random(),
            node_key: NodePrivateKey::random(),
        }
    }
}

/// The complete runtime key state for a Tailscale node.
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
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
