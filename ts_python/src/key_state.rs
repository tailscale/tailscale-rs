/// Tailscale keys.
#[derive(Clone, PartialEq, Eq)]
#[pyo3::pyclass(frozen, get_all, from_py_object, module = "tailscale")]
pub struct Keystate {
    /// Machine key.
    pub machine: Vec<u8>,
    /// Node (device) key.
    pub node: Vec<u8>,
    /// Network lock key.
    pub network_lock: Vec<u8>,
}

#[pyo3::pymethods]
impl Keystate {
    #[new]
    #[pyo3(signature = (machine: "bytes | None" = None, node: "bytes | None" = None, network_lock: "bytes | None" = None))]
    pub fn new(
        machine: Option<Vec<u8>>,
        node: Option<Vec<u8>>,
        network_lock: Option<Vec<u8>>,
    ) -> Self {
        let mut out: Self = ts::keys::PersistState::default().into();

        if let Some(machine) = machine {
            out.machine = machine;
        }

        if let Some(node) = node {
            out.node = node;
        }

        if let Some(network_lock) = network_lock {
            out.network_lock = network_lock;
        }

        out
    }

    pub fn __repr__(&self) -> String {
        match tailscale::keys::PersistState::try_from(self) {
            Ok(state) => {
                format!(
                    "tailscale.Keystate(machine={}, node={}, network_lock={})",
                    hex::encode(state.machine_key.import().public_key().as_bytes()),
                    hex::encode(state.node_key.import().public_key().as_bytes()),
                    hex::encode(state.network_lock_key.import().public_key().as_bytes()),
                )
            }
            Err(_) => "tailscale.Keystate(<invalid>)".to_owned(),
        }
    }
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

impl TryFrom<&Keystate> for tailscale::keys::PersistState {
    type Error = ();

    fn try_from(value: &Keystate) -> Result<Self, ()> {
        Ok(Self {
            machine_key: (&value.machine).try_into()?,
            node_key: (&value.node).try_into()?,
            network_lock_key: (&value.network_lock).try_into()?,
        })
    }
}
