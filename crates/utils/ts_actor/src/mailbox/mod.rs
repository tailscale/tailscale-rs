//! Process mailbox implementation.
//!
//! This isn't just a channel because processes need to be able to match on incoming messages, which
//! means potentially accepting them out-of-order.

mod async_mailbox;

use core::ops::{Index, IndexMut};

pub use async_mailbox::{Receiver, Sender, TryRecvError, TrySendError, async_mailbox};

use crate::{Message, StaticStorage};

/// A mailbox for a process; essentially a channel for incoming messages.
///
/// This can't use a conventional `mpsc` or `spsc` channel because the receiving process
/// needs to be able to match on the incoming messages: i.e., it may need to dequeue a
/// message from deeper in the channel than the head.
// TODO(npry): a bunch of optimization potential. We probably want to use atomics, and this
//  can be optimized if we know there's only one receiver. It may be worth treating the
//  storage kind of like a rope by allowing holes which indicate the number of positions to
//  skip and doing compaction only when necessary. Not done right now because the current
//  shape is sufficient to express the api semantics we want, even if inefficient.
pub struct Mailbox {
    /// The position of the next item which would be popped out of the mailbox.
    head: u16,

    /// The number of items in the mailbox.
    len: u16,

    /// The messages in the mailbox.
    ///
    /// Unpopulated elements are set to the default message `()`.
    elems: StaticStorage<[Message]>,
}

/// Helper alias indicating this is a "logical" index into the mailbox (0 is always the
/// start of the queue). This is what callers always see / what we expose as API.
type LogicalIndex = usize;
/// Helper alias indicating this is a slice index into mailbox storage. Internal only.
type SliceIndex = usize;

impl Mailbox {
    /// Construct a new mailbox that can hold `capacity` messages.
    ///
    /// The mailbox is allocated on the heap.
    pub fn new(capacity: u16) -> Self {
        Self {
            head: 0,
            len: 0,
            elems: StaticStorage::Box(
                core::iter::from_fn(|| Some(Message::default()))
                    .take(capacity as _)
                    .collect(),
            ),
        }
    }

    /// Construct a new mailbox from `&'static` storage.
    ///
    /// # Panics
    ///
    /// If `storage.len() > u16::MAX` (mailboxes cannot hold more than 64k items).
    pub const fn from_static(storage: &'static mut [Message]) -> Self {
        if storage.len() > u16::MAX as usize {
            panic!("storage too large for mailbox (max 64k items)");
        }

        Self {
            head: 0,
            len: 0,
            elems: StaticStorage::Ref(storage),
        }
    }

    /// Report the current number of items in the mailbox.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Report whether the mailbox is empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Report whether the mailbox is full.
    pub const fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Report the number of items the mailbox can hold.
    pub const fn capacity(&self) -> usize {
        self.elems.len()
    }

    /// Remove all items from the mailbox.
    pub fn clear(&mut self) {
        // Side-effect: set all the elems to default, set len = 0.
        for _ in &mut *self {}
    }

    /// Push `msg` into the mailbox if there's capacity.
    pub fn push(&mut self, msg: Message) -> Result<(), Message> {
        if self.is_full() {
            return Err(msg);
        }

        let tail = self.tail();
        self.elems[tail] = msg;
        self.len += 1;

        Ok(())
    }

    /// Pop the first message out of the mailbox if there is one.
    pub fn pop(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        let elem = core::mem::take(&mut self.elems[self.head as usize]);
        self.head = ((self.head as usize + 1) % self.capacity()) as u16;
        self.len -= 1;

        Some(elem)
    }

    /// Remove the first message from the mailbox matching the predicate.
    ///
    /// This performs a linear number of copies in the size of the mailbox, as the rest of
    /// the messages after the matching one must be bubbled down. The exception is if the
    /// matching message is the first one, in which case this acts like `pop` (constant
    /// time, no copying).
    pub fn remove_first_where(
        &mut self,
        mut pred: impl FnMut(&Message) -> bool,
    ) -> Option<Message> {
        for i in 0..self.len() {
            let i: LogicalIndex = i;

            if !pred(&self[i]) {
                continue;
            }

            if i == 0 {
                return self.pop();
            }

            return Some(self.remove_inner(i));
        }

        None
    }

    /// Report the tail position, i.e. the index one-past the last valid item.
    const fn tail(&self) -> usize {
        (self.head as usize + self.len()) % self.capacity()
    }

    /// Convert a logical index to an index into the element slice.
    #[track_caller]
    const fn convert_index(&self, idx: LogicalIndex) -> SliceIndex {
        if idx >= self.len() {
            panic!("index out of range");
        }

        (self.head as usize + idx) % self.capacity()
    }

    /// Remove an item which may be in the middle of the element array.
    fn remove_inner(&mut self, index: LogicalIndex) -> Message {
        let result = core::mem::take(&mut self[index]);

        for i in index..self.len().saturating_sub(1) {
            let a = self.convert_index(i);
            let b = self.convert_index(i + 1);

            self.elems.swap(a, b);
        }

        self.len -= 1;

        result
    }
}

impl Iterator for Mailbox {
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }
}

impl Index<usize> for Mailbox {
    type Output = Message;

    fn index(&self, index: LogicalIndex) -> &Self::Output {
        let idx: SliceIndex = self.convert_index(index);
        &self.elems[idx]
    }
}

impl IndexMut<usize> for Mailbox {
    fn index_mut(&mut self, index: LogicalIndex) -> &mut Self::Output {
        let idx: SliceIndex = self.convert_index(index);
        &mut self.elems[idx]
    }
}
