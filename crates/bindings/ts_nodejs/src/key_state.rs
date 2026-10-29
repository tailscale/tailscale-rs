use napi::bindgen_prelude::{Buffer, Result};
use napi_derive::napi;
use tailscale::keys::{Export, PersistState};
use zerocopy::IntoBytes;

use crate::error::js_arg_err;

/// A node's private keys, as raw bytes.
#[napi(object)]
pub struct Keys {
    /// Machine key.
    pub machine: Buffer,
    /// Node (device) key.
    pub node: Buffer,
    /// Network lock key.
    pub network_lock: Buffer,
}

/// A node's public keys, hex-encoded.
#[napi(object, object_from_js = false)]
pub struct PublicKeys {
    /// Machine key.
    pub machine: String,
    /// Node (device) key.
    pub node: String,
    /// Network lock key.
    pub network_lock: String,
}

/// Randomly generate a new set of keys.
#[napi]
pub fn generate_keys() -> Keys {
    let state = PersistState::default();

    Keys {
        machine: state.machine_key.as_bytes().as_slice().into(),
        node: state.node_key.as_bytes().as_slice().into(),
        network_lock: state.network_lock_key.as_bytes().as_slice().into(),
    }
}

/// Derive the public keys from a set of private keys.
#[napi]
pub fn public_keys(keys: Keys) -> Result<PublicKeys> {
    let state = PersistState::try_from(&keys)?;

    Ok(PublicKeys {
        machine: hex::encode(state.machine_key.import().public.as_bytes()),
        node: hex::encode(state.node_key.import().public.as_bytes()),
        network_lock: hex::encode(state.network_lock_key.import().public.as_bytes()),
    })
}

impl TryFrom<&Keys> for PersistState {
    type Error = napi::Error;

    fn try_from(value: &Keys) -> Result<Self> {
        fn key(name: &str, bytes: &[u8]) -> Result<[u8; 32]> {
            bytes
                .try_into()
                .map_err(|_| js_arg_err(format!("{name} key must be 32 bytes")))
        }

        Ok(Self {
            machine_key: Export::from_bytes(key("machine", &value.machine)?),
            node_key: Export::from_bytes(key("node", &value.node)?),
            network_lock_key: Export::from_bytes(key("network lock", &value.network_lock)?),
        })
    }
}
