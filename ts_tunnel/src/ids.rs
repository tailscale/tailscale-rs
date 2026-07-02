use std::collections::HashMap;

use ts_keys::NodePublicKey;

use crate::{PeerId, handshake::Handshake, messages::SessionId};

/// Tracks and allocates session IDs for peer sessions.
#[derive(Default)]
pub struct IdMap {
    sessions: HashMap<SessionId, PeerId>,
    // TODO: track recently abandoned session IDs, avoid reusing them for
    // one or two session lifetimes to avoid confusion with reordered packets.
    node_keys: HashMap<NodePublicKey, PeerId>,
}

impl IdMap {
    /// Return the peer handle for a node public key, if any.
    pub fn get_by_nodekey(&self, key: &NodePublicKey) -> Option<PeerId> {
        self.node_keys.get(key).copied()
    }

    /// Return the peer handle for a session, if any.
    pub fn get_by_session_id(&self, key: &SessionId) -> Option<&PeerId> {
        self.sessions.get(key)
    }

    /// Add a peer handle for communicating with the given peer pubkey.
    ///
    /// Returns `false` if a peer already exists for the key.
    pub fn add_peer(&mut self, id: PeerId, key: &NodePublicKey) -> bool {
        if self.node_keys.contains_key(key) {
            return false;
        }

        self.node_keys.insert(*key, id);
        true
    }

    /// Allocate a new session ID for communication with the given peer.
    ///
    /// Note that due to key rotation, a peer can have multiple session IDs in use at once.
    pub fn allocate_session(&mut self, peer: PeerId) -> SessionId {
        loop {
            let ret = SessionId::random();
            if self.sessions.contains_key(&ret) {
                continue;
            }
            self.sessions.insert(ret, peer);
            return ret;
        }
    }

    /// Abandon the given session ID.
    ///
    /// Panics if the session ID isn't currently in use.
    pub fn remove_session(&mut self, id: SessionId) {
        self.sessions.remove(&id).unwrap();
    }

    /// Abandon the session ID associated with a handshake.
    ///
    /// Panics if the handshake's ID wasn't allocated in this IdMap.
    pub fn remove_handshake_session(&mut self, handshake: &Handshake) {
        if let Some(id) = handshake.session_id() {
            self.remove_session(id);
        }
    }

    /// Delete the peer handle for the given key.
    ///
    /// Panics if there is no peer currently using that key.
    pub fn remove_peer(&mut self, key: &NodePublicKey) {
        self.node_keys.remove(key).unwrap();
    }
}
