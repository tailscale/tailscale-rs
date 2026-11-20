use std::sync::LazyLock;
use sha2::{Digest, Sha256};

#[derive(serde::Serialize, serde::Deserialize, Debug, Copy, Clone)]
pub struct LogtailPrivateId(pub(crate) [u8; 32]);

impl LogtailPrivateId {
    pub fn public_id(&self) -> String {
        hex::encode(Sha256::digest(&self.0))
    }
}

impl Default for LogtailPrivateId {
    fn default() -> Self {
        let mut id = [0; 32];
        rand::fill(&mut id);
        LogtailPrivateId(id)
    }
}

pub(crate) struct LogtailProcId(pub u32);

impl LogtailProcId {
    fn new() -> Self {
        // 0 is treated as null/nonexistent
        LogtailProcId(rand::random_range(1..=u32::MAX))
    }
}

/// The proc_id field is used in the backend to disambiguate multiple client instances sharing a
/// privateid, e.g. to detect restarts. It should be fixed for all clients in a single process.
pub(crate) static PROC_ID: LazyLock<LogtailProcId> = LazyLock::new(|| {
    LogtailProcId::new()
});