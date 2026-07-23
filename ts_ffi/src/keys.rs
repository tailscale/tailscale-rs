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
                key(value.into())
            }
        }

        impl From<&$key> for key {
            fn from(value: &$key) -> Self {
                key(value.into())
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

/// Tailscale key state for running a device.
#[derive(Default)]
#[repr(C)]
pub struct persisted_key_state {
    /// Private key for the node (device) identity.
    pub node_private_key: key,
    /// Private key for the machine.
    pub machine_private_key: key,
    /// Private key for tailnet lock.
    pub network_lock_private_key: key,
}

impl From<persisted_key_state> for ts_keys::PersistState {
    fn from(value: persisted_key_state) -> Self {
        (&value).into()
    }
}

impl From<&persisted_key_state> for ts_keys::PersistState {
    fn from(value: &persisted_key_state) -> Self {
        ts_keys::PersistState {
            machine_key: (&value.machine_private_key).into(),
            network_lock_key: (&value.network_lock_private_key).into(),
            node_key: (&value.node_private_key).into(),
        }
    }
}

impl From<ts_keys::PersistState> for persisted_key_state {
    fn from(value: ts_keys::PersistState) -> Self {
        Self {
            machine_private_key: value.machine_key.into(),
            network_lock_private_key: value.network_lock_key.into(),
            node_private_key: value.node_key.into(),
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
    key_state: &mut persisted_key_state,
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
        tailscale::config::BadFormatBehavior::Overwrite
    } else {
        tailscale::config::BadFormatBehavior::Error
    };

    let _span = tracing::trace_span!("ts_load_key_file", ?mode, path = %s).entered();

    match TOKIO_RUNTIME.block_on(tailscale::config::load_key_file(s, mode)) {
        Ok(state) => {
            *key_state = state.into();
            0
        }
        Err(e) => {
            tracing::error!(error = %e, "loading key file");

            -1
        }
    }
}
