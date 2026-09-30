//! Implementation of the packet replay protection algorithm from RFC 6479.
//!
//! The overall goal of replay protection is to only accept new packets in an established session,
//! and reject attempts at playing back older packets.
//!
//! We could naively do this by tracking the highest packet counter we've seen on a valid packet,
//! and reject all packets presenting an older counter. However, this is overly conservative in
//! the face of packet reordering on the network, wherein a burst of packets may arrive slightly
//! out of order.
//!
//! Precisely tracking all previously seen packet IDs for all time is prohibitively expensive, so
//! practical systems compromise and track both the highest counter seen so far, and a sliding
//! window of the N packets prior to the latest. Packets in that window can be received out
//! of order while still rejecting replays. Packets that fall earlier than the window are rejected
//! unconditionally, on the assumption that sufficiently old packets have all been received or lost
//! permanently.
//!
//! The window can be implemented with a regular bitset, with each bit tracking one packet in the
//! window of recent counters. The downside of the naive implementation is that whenever a newer
//! packet is accepted, sliding the window forward involves doing a bit shift operation on the
//! entire bitset. This is fairly expensive to do at high packet line rates.
//!
//! The first idea of RFC 6479 is that, if we make the window a power of two, we can directly map
//! a counter value to a bit index by masking the higher order bits of the counter. This turns
//! the bitset into a ring buffer, where the bit position of the highest seen counter is the head
//! pointer. As the highest seen counter value increments when receiving packets, the window's head
//! position automatically slides forward.
//!
//! Here's a visual representation of what that looks like in a small 32-bit window:
//!
//! | 0 0 0 1 1 0 1 0 1 0 0 1 1 1 1 1 1 1 0 1 0 1 1 1 1 1 1 1 1 1 1 1 |
//!                   ^     ^ ^
//!                   |     | \
//!                   |     |  Current tail: 144_844
//!                   |     |  Bit index after masking: 12
//!                   |     \
//!                   |      Current head: 144_875
//!                   |      Bit index after masking: 11
//!                   \
//!                    Counter 144_872 has already been received
//!                    Bit index after masking: 8
//!
//! This approach introduces a new issue: when advancing the head of the window, we have to take
//! care to zero out bits that have wrapped around from the window's tail. We want this operation
//! to be cheaper than bit shifting, since that's what we've been trying to avoid this whole time.
//!
//! RFC 6479's second idea is to observe that replay windows usually span several machine words.
//! The window is represented as an array of blocks, for example a `[u64; 8]` for 512 bits total.
//! If we shrink the usable window to leave one of those blocks unused, then the ring's head and
//! tail pointers never occupy the same block.
//!
//! This lets us advance the head pointer very cheaply: whenever the head position crosses over
//! into a new block, we zero that block entirely. This may result in zeroing several consecutive
//! blocks if the head advances by a large amount, or even the entire ring if the head advances
//! more than the window size. Finally, once the appropriate blocks have been zeroed, the bit
//! corresponding to the new highest counter is set.
//!
//! The resulting window after sliding has exactly the same content as in the bit-shift
//! implementation, but the cost of advancing has been reduced to zeroing a few machine words.
//! Similarly, the cost of setting a bit within the window is a clean bit masking operation
//! (because the overall ring size is a power of 2), followed by a bit set operation within a
//! single machine word. The cost of checking an arbitrary counter value consists of a few
//! comparisons to check if the counter is before or after the current window, and as mask+bit test
//! for counters within the window.

use std::fmt::Debug;

/// A packet replay tracker.
///
/// In the abstract, the tracker rejects previously seen counter values. However, to
/// do this perfectly would require a large amount of storage. Instead, the tracker assumes
/// that counter values are seen mostly in ascending order, and only explicitly tracks seen
/// counter values in a short window behind the latest seen value.
///
/// Values that fall before this window are unconditionally rejected; values larger than any seen
/// so far are unconditionally accepted (and advance the tracker's sliding window); values that
/// fall within the window are tracked explicitly with a bitset, to ensure they are accepted once
/// only.
#[derive(Default)]
pub struct ReplayWindow {
    // nonce counter value of the end of the sliding window
    last: u64,
    blocks: [u64; ReplayWindow::N_BLOCKS as usize],
}

impl Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct BlockFormatter<'b>(&'b [u64]);

        impl<'b> Debug for BlockFormatter<'b> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for b in self.0 {
                    write!(f, "{:08b} ", b.reverse_bits())?;
                }

                Ok(())
            }
        }

        f.debug_struct("ReplayWindow")
            .field("last", &self.last)
            .field("bits", &BlockFormatter(&self.blocks))
            .finish()
    }
}

impl ReplayWindow {
    const TOTAL_BITS: u64 = 256;
    const N_BLOCKS: u64 = Self::TOTAL_BITS / u64::BITS as u64;
    const BIT_IDX_BITMASK: u64 = (u64::BITS - 1) as u64;
    const BIT_IDX_SHIFT: u32 = u64::BITS.ilog2();
    const BLOCK_IDX_BITMASK: u64 = Self::N_BLOCKS - 1;

    pub const WINDOW_SIZE: u64 = (Self::N_BLOCKS - 1) * u64::BITS as u64;

    fn smallest_valid(&self) -> u64 {
        self.last.saturating_sub(Self::WINDOW_SIZE - 1)
    }

    fn block_idx_unbounded(&self, counter: u64) -> u64 {
        counter >> Self::BIT_IDX_SHIFT
    }

    fn bit_idx(&self, counter: u64) -> u64 {
        counter & Self::BIT_IDX_BITMASK
    }

    fn block_idx_and_bit_mask(&self, counter: u64) -> (usize, u64) {
        let block_idx = self.block_idx_unbounded(counter) & Self::BLOCK_IDX_BITMASK;
        (block_idx as usize, 1 << self.bit_idx(counter))
    }

    /// Report whether counter is a new value that can be processed.
    ///
    /// Does not update the replay window state, so should be called prior to doing
    /// expensive processing. After processing, you must call `ReplayWindow::set` to
    /// update the replay window state.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if counter < self.smallest_valid() {
            return false;
        }
        let (block_idx, bit_mask) = self.block_idx_and_bit_mask(counter);
        self.blocks[block_idx] & bit_mask == 0
    }

    /// Update the replay window to mark the given counter as seen and accepted
    ///
    /// # Panics
    ///
    /// If [`ReplayWindow::check(counter)`] is false.
    pub fn set(&mut self, counter: u64) {
        if counter < self.smallest_valid() {
            panic!(
                "invalid set: counter {} is older than smallest valid {}",
                counter,
                self.smallest_valid()
            );
        }
        if counter > self.last {
            let cur_block = self.block_idx_unbounded(self.last);
            let new_block = self.block_idx_unbounded(counter);
            let delta = new_block - cur_block;
            if delta >= Self::N_BLOCKS {
                self.blocks = [0; Self::N_BLOCKS as usize];
            } else {
                for i in cur_block..new_block {
                    let idx = (i + 1) & Self::BLOCK_IDX_BITMASK;
                    self.blocks[idx as usize] = 0;
                }
            }
            self.last = counter;
        }
        let (block_idx, bit_mask) = self.block_idx_and_bit_mask(counter);
        if self.blocks[block_idx] & bit_mask != 0 {
            panic!(
                "invalid set: counter {} was already set previously",
                counter
            );
        }
        self.blocks[block_idx] |= bit_mask;
    }

    #[cfg(test)]
    fn check_and_set(&mut self, counter: u64) -> bool {
        let accept = self.check(counter);
        if accept {
            self.set(counter);
        }
        accept
    }

    #[cfg(test)]
    fn received_in_window(&self) -> u64 {
        let counters = self.smallest_valid()..self.last + 1;
        counters
            .map(|ctr| if self.check(ctr) { 0 } else { 1 })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::{cmp::max, collections::HashSet};

    use super::*;

    #[test]
    fn just_advance() {
        let mut window = ReplayWindow::default();

        for counter in 0..600 {
            assert!(window.check_and_set(counter));
            assert_eq!(
                window.received_in_window(),
                (counter + 1).clamp(0, ReplayWindow::WINDOW_SIZE)
            );
        }
    }

    #[test]
    fn out_of_order() {
        let mut window = ReplayWindow::default();

        assert!(window.check_and_set(500));
        assert!(!window.check(500));
        assert!(!window.check(100));
        assert_eq!(window.received_in_window(), 1);
        for (i, counter) in (400..450).rev().enumerate() {
            assert!(window.check_and_set(counter));
            assert_eq!(window.received_in_window(), (i + 2) as u64);
        }
        for (i, counter) in (451..500).enumerate() {
            assert!(window.check_and_set(counter));
            assert_eq!(window.received_in_window(), (i + 52) as u64);
        }
    }

    proptest::proptest! {
        #[test]
        fn any_order(counters in proptest::collection::vec(0u64..1000, 0..2000)) {
            let mut seen = HashSet::new();
            let mut latest = None;
            let mut window = ReplayWindow::default();
            for counter in counters {
                let accepted = window.check_and_set(counter);
                if accepted {
                    assert!(!seen.contains(&counter));
                    if let Some(latest_ctr) = latest {
                        assert!(counter >= window.smallest_valid());
                        latest = Some(max(latest_ctr, counter))
                    } else {
                        latest = Some(counter);
                    }
                    seen.insert(counter);
                } else {
                    assert!(seen.contains(&counter) || counter < window.smallest_valid());
                }
            }
        }
    }
}
