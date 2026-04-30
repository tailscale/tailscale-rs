use std::sync::Mutex;

/// Trait providing conversion between [`ts_keys::NodePublicKey`] (required to send and
/// receive derp messages) and [`ts_transport::PeerId`] (tailscale-rs internal type).
pub trait PeerLookup: Send + Sync {
    /// Convert `key` to a [`ts_transport::PeerId`], allocating a new id if the peer doesn't
    /// exist yet.
    fn key_to_id(&self, key: &ts_keys::NodePublicKey) -> Option<ts_transport::PeerId>;

    /// Convert the `id` to a [`ts_keys::NodePublicKey`].
    ///
    /// Returns `None` if the `id` is not stored.
    fn id_to_key(&self, id: ts_transport::PeerId) -> Option<ts_keys::NodePublicKey>;
}

impl<T> PeerLookup for &T
where
    T: PeerLookup,
{
    fn key_to_id(&self, key: &ts_keys::NodePublicKey) -> Option<ts_transport::PeerId> {
        (*self).key_to_id(key)
    }

    fn id_to_key(&self, id: ts_transport::PeerId) -> Option<ts_keys::NodePublicKey> {
        (*self).id_to_key(id)
    }
}

impl<T> PeerLookup for &mut T
where
    T: PeerLookup,
{
    fn key_to_id(&self, key: &ts_keys::NodePublicKey) -> Option<ts_transport::PeerId> {
        (**self).key_to_id(key)
    }

    fn id_to_key(&self, id: ts_transport::PeerId) -> Option<ts_keys::NodePublicKey> {
        (**self).id_to_key(id)
    }
}

/// Dummy implementation of [`PeerLookup`] wrapping a [`Vec`], suitable for tests and
/// examples.
///
/// Peer entries are never removed from the inner `Vec`.
#[doc(hidden)]
#[derive(Default)]
pub struct DummyStaticLookup(Mutex<Vec<ts_keys::NodePublicKey>>);

impl PeerLookup for DummyStaticLookup {
    fn key_to_id(&self, key: &ts_keys::NodePublicKey) -> Option<ts_transport::PeerId> {
        let mut mp = self.0.lock().unwrap();

        if let Some((id, _)) = mp.iter().enumerate().find(|(_id, k)| *k == key) {
            return Some(ts_transport::PeerId(id as _));
        }

        let id = mp.len();
        mp.push(*key);

        Some(ts_transport::PeerId(id as _))
    }

    fn id_to_key(
        &self,
        ts_transport::PeerId(id): ts_transport::PeerId,
    ) -> Option<ts_keys::NodePublicKey> {
        let mp = self.0.lock().unwrap();
        mp.get(id as usize).cloned()
    }
}
