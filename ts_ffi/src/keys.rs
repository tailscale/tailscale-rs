use std::{
    ffi,
    ffi::{CStr, c_char},
};

use crate::TOKIO_RUNTIME;

/// A Tailscale cryptographic key.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct key(pub [u8; 32]);

macro_rules! impl_to_from {
    ($key:ty, $($keys:ty),+) => {
        impl_to_from!($key);
        impl_to_from!($($keys),+);
    };

    ($key:ty$(,)?) => {
        impl From<key> for $key {
            fn from(value: key) -> Self {
                value.0.into()
            }
        }

        impl From<&key> for $key {
            fn from(value: &key) -> Self {
                value.0.into()
            }
        }

        impl From<$key> for key {
            fn from(value: $key) -> Self {
                key(conv::<[u8; 32]>(value))
            }
        }
        impl From<&$key> for key {
            fn from(value: &$key) -> Self {
                key(conv::<[u8; 32]>(*value))
            }
        }
    };
}

impl_to_from!(
    ts_keys::NodePublicKey,
    ts_keys::NodePrivateKey,
    ts_keys::DiscoPublicKey,
    ts_keys::DiscoPrivateKey,
    ts_keys::MachinePrivateKey,
    ts_keys::MachinePublicKey,
    ts_keys::NetworkLockPrivateKey,
    ts_keys::NetworkLockPublicKey
);

#[derive(Debug, Default)]
#[repr(C)]
pub struct node_key_state {
    pub node_private_key: key,
    pub machine_private_key: key,
    pub network_lock_private_key: key,
    pub disco_private_key: key,
}

fn conv<T>(u: impl Into<T>) -> T {
    u.into()
}

impl From<node_key_state> for ts_keys::NodeState {
    fn from(value: node_key_state) -> Self {
        (&value).into()
    }
}

impl From<&node_key_state> for ts_keys::NodeState {
    fn from(value: &node_key_state) -> Self {
        ts_keys::NodeState {
            disco_keys: conv::<ts_keys::DiscoPrivateKey>(&value.disco_private_key).into(),
            machine_keys: conv::<ts_keys::MachinePrivateKey>(&value.machine_private_key).into(),
            network_lock_keys: conv::<ts_keys::NetworkLockPrivateKey>(
                &value.network_lock_private_key,
            )
            .into(),
            node_keys: conv::<ts_keys::NodePrivateKey>(&value.node_private_key).into(),
        }
    }
}

impl From<ts_keys::NodeState> for node_key_state {
    fn from(value: ts_keys::NodeState) -> Self {
        Self {
            machine_private_key: value.machine_keys.private.into(),
            network_lock_private_key: value.network_lock_keys.private.into(),
            disco_private_key: value.disco_keys.private.into(),
            node_private_key: value.node_keys.private.into(),
        }
    }
}

/// Load the key state from the given file path.
///
/// The second parameter indicates whether to overwrite the file with a new key state if the
/// contents couldn't be read.
///
/// Returns a negative number on error.
///
/// # Safety
///
/// `path` must be safe to convert to a [`CStr`], i.e. it must be NUL-terminated and valid for read
/// up to the NUL-terminator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_load_key_file(
    path: *const c_char,
    overwrite_if_invalid: bool,
    key_state: &mut node_key_state,
) -> ffi::c_int {
    let s = unsafe { CStr::from_ptr(path) };
    let s = match s.to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "converting path to str");
            return -1;
        }
    };

    let mode = if overwrite_if_invalid {
        tailscale::BadFormatBehavior::Overwrite
    } else {
        tailscale::BadFormatBehavior::Error
    };

    let _span = tracing::trace_span!("ts_load_key_file", ?mode, path = %s).entered();

    match TOKIO_RUNTIME.block_on(tailscale::load_key_file(s, mode)) {
        Ok(state) => {
            *key_state = state.into();
            tracing::info!(?key_state, "loaded key state");

            0
        }
        Err(e) => {
            tracing::error!(error = %e, "loading key file");

            -1
        }
    }
}
