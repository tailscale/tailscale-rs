use std::{
    cmp::min,
    collections::{VecDeque, vec_deque},
};

use ts_packet::PacketMut;

const MAX_QUEUED_PER_PEER: usize = 32;

/// A bounded packet queue that drops oldest packets when full.
#[derive(Default)]
pub struct Queue(VecDeque<PacketMut>);

impl Queue {
    /// Append packets to the queue, dropping older packets as needed.
    pub fn append(&mut self, packets: Vec<PacketMut>) {
        let new_packets = min(packets.len(), MAX_QUEUED_PER_PEER);
        let drop_incoming = packets.len() - new_packets;
        let keep_queued = MAX_QUEUED_PER_PEER - new_packets;
        let drop_queued = self.0.len().saturating_sub(keep_queued);
        self.0.drain(..drop_queued);
        self.0.extend(packets.into_iter().skip(drop_incoming));
    }

    /// Remove all packets from the queue.
    ///
    /// The queue's memory footprint is shrunk to its minimum, on the assumption that
    /// it is unlikely to be used again soon.
    pub fn clear(&mut self) {
        self.0.clear();
        self.0.shrink_to_fit();
    }

    /// Drain all packets from the queue into a `Vec`.
    ///
    /// The queue's memory footprint is shrunk to its minimum, on the assumption that
    /// it is unlikely to be used again soon.
    pub fn drain(&mut self) -> Vec<PacketMut> {
        let ret = self.0.drain(..).collect();
        self.clear();
        ret
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for Queue {
    type Item = PacketMut;
    type IntoIter = vec_deque::IntoIter<PacketMut>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<Queue> for Vec<PacketMut> {
    fn from(queue: Queue) -> Self {
        queue.0.into()
    }
}
