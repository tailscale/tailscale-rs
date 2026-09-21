use core::fmt::{Debug, Formatter};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use ts_keys::NodePublicKey;

use crate::{PeerId, messages::SessionId};

/// Tracks and allocates session IDs for peer sessions.
#[derive(Default)]
pub struct IdMap {
    sessions: Arc<Mutex<HashMap<SessionId, PeerId>>>,
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
    pub fn get_by_session_id(&self, key: &SessionId) -> Option<PeerId> {
        self.sessions.lock().unwrap().get(key).copied()
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

    /// Delete the peer handle for the given key.
    ///
    /// Panics if there is no peer currently using that key.
    pub fn remove_peer(&mut self, key: &NodePublicKey) {
        self.node_keys.remove(key).unwrap();
    }

    /// Allocate a new session ID for communication with the given peer.
    ///
    /// Note that due to key rotation, a peer can have multiple session IDs in use at once.
    pub fn allocate_session(&mut self, peer: PeerId) -> SessionHandle {
        let mut sessions = self.sessions.lock().unwrap();
        loop {
            let ret = SessionId::random();
            if sessions.contains_key(&ret) {
                continue;
            }
            sessions.insert(ret, peer);
            return SessionHandle {
                sessions: Arc::downgrade(&self.sessions),
                id: ret,
            };
        }
    }
}

/// A handle for a receiving session.
pub struct SessionHandle {
    sessions: Weak<Mutex<HashMap<SessionId, PeerId>>>,
    id: SessionId,
}

impl SessionHandle {
    /// Return the wire ID for this session.
    pub fn id(&self) -> SessionId {
        self.id
    }
}

impl Debug for SessionHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

impl AsRef<SessionId> for SessionHandle {
    fn as_ref(&self) -> &SessionId {
        &self.id
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let Some(sessions) = self.sessions.upgrade() else {
            return;
        };
        let mut sessions = sessions.lock().unwrap();
        sessions.remove(&self.id).unwrap();
    }
}
