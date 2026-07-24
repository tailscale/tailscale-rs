use std::collections::HashMap;

use rustler::{Atom, NifResult, Term};

mod atoms {
    rustler::atoms! {
        keys,
        control_url,
        hostname,
        tags,
        auth_key,
        ephemeral,
    }
}

/// Load a [`tailscale::Config`] from the specified `erl_config`.
///
/// `erl_config` is expected to be a keyword list. Any keys missing from the list will adopt
/// default values.
pub fn config_from_erl(
    erl_config: &HashMap<Atom, Term>,
) -> NifResult<(tailscale::Config, Option<String>)> {
    let mut config = tailscale::Config {
        client_name: Some("ts_elixir".to_owned()),
        ..Default::default()
    };
    let mut auth_key = None;

    if let Some(value) = erl_config.get(&atoms::keys()) {
        config.key_state = value
            .decode::<Keystate>()?
            .try_into()
            .map_err(|_| rustler::Error::BadArg)?;
    }

    if let Some(value) = erl_config.get(&atoms::control_url()) {
        config.control_server_url = value.decode::<&str>()?.parse().map_err(|e| {
            tracing::error!(error = %e, "parsing control server url");

            rustler::Error::BadArg
        })?;
    }

    if let Some(value) = erl_config.get(&atoms::hostname()) {
        config.requested_hostname = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::tags()) {
        config.requested_tags = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::auth_key()) {
        auth_key = Some(value.decode()?);
    }

    if let Some(value) = erl_config.get(&atoms::ephemeral()) {
        config.ephemeral = value.decode()?;
    }

    Ok((config, auth_key))
}

#[derive(rustler::NifStruct, Debug, Clone)]
#[module = "Tailscale.Keystate"]
pub struct Keystate {
    pub machine: Vec<u8>,
    pub node: Vec<u8>,
    pub network_lock: Vec<u8>,
}

impl From<tailscale::keys::PersistState> for Keystate {
    fn from(value: tailscale::keys::PersistState) -> Self {
        Self {
            machine: value.machine_key.as_bytes().into(),
            node: value.node_key.as_bytes().into(),
            network_lock: value.network_lock_key.as_bytes().into(),
        }
    }
}

impl TryFrom<Keystate> for tailscale::keys::PersistState {
    type Error = ();

    fn try_from(value: Keystate) -> Result<Self, ()> {
        Ok(Self {
            machine_key: value.machine.try_into()?,
            node_key: value.node.try_into()?,
            network_lock_key: value.network_lock.try_into()?,
        })
    }
}
