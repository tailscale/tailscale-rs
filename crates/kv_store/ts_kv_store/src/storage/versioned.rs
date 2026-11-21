use crate::{schema::PrimaryTableDesc, transactions::TxnId};

/// An MVCC value with only two versions (versioned by [`TxnId`]).
#[doc(hidden)]
#[derive(Debug)]
pub struct VersionedValue<T> {
    slot_a: Option<(TxnId, T)>,
    slot_b: Option<(TxnId, T)>,
}

impl<T> Default for VersionedValue<T> {
    fn default() -> Self {
        VersionedValue {
            slot_a: None,
            slot_b: None,
        }
    }
}

impl<T> VersionedValue<T> {
    pub(crate) fn new(t: T, id: TxnId) -> Self {
        VersionedValue {
            slot_a: Some((id, t)),
            slot_b: None,
        }
    }

    pub fn gc_txn(&mut self, txn_id: TxnId) {
        if let Some((id, _)) = self.slot_a
            && id == txn_id
        {
            self.slot_a = None;
        }
        if let Some((id, _)) = self.slot_b
            && id == txn_id
        {
            self.slot_b = None;
        }
    }

    /// The value written by `txn_id`, if that transaction wrote to either slot.
    pub fn modified_in_txn(&self, txn_id: TxnId) -> Option<&T> {
        if let Some((id, v)) = &self.slot_a
            && *id == txn_id
        {
            return Some(v);
        }
        if let Some((id, v)) = &self.slot_b
            && *id == txn_id
        {
            return Some(v);
        }
        None
    }

    /// True if neither slot holds a value.
    pub(super) fn is_empty(&self) -> bool {
        self.slot_a.is_none() && self.slot_b.is_none()
    }

    /// True if either slot holds a value committed before `txn_id` (i.e., from an earlier transaction).
    pub(super) fn has_prior_value(&self, txn_id: TxnId) -> bool {
        let older = |slot: &Option<(TxnId, T)>| matches!(slot, Some((id, _)) if *id < txn_id);
        older(&self.slot_a) || older(&self.slot_b)
    }

    /// If there is a value visible to `txn_id` in one slot, clone it into the other slot and return
    /// a mutable reference to it.
    pub(super) fn internal_clone(&mut self, txn_id: TxnId) -> Option<&mut T>
    where
        T: Clone,
    {
        // The unpleasantness with `unwrap`s is to work around lifetime issues.
        if let Some((aid, a)) = &mut self.slot_a {
            if txn_id == *aid {
                Some(&mut self.slot_a.as_mut().unwrap().1)
            } else if let Some((bid, b)) = &mut self.slot_b {
                // Use the current transaction's value, or clone the newer of the two committed values
                // over the older.
                if txn_id == *bid {
                    Some(&mut self.slot_b.as_mut().unwrap().1)
                } else if aid > bid {
                    debug_assert!(txn_id > *aid && txn_id > *bid);
                    self.slot_b = Some((txn_id, a.clone()));
                    Some(&mut self.slot_b.as_mut().unwrap().1)
                } else {
                    debug_assert!(txn_id > *aid && txn_id > *bid);
                    self.slot_a = Some((txn_id, b.clone()));
                    Some(&mut self.slot_a.as_mut().unwrap().1)
                }
            } else {
                self.slot_b = Some((txn_id, a.clone()));
                Some(&mut self.slot_b.as_mut().unwrap().1)
            }
        } else if let Some((bid, b)) = &mut self.slot_b {
            if txn_id == *bid {
                Some(b)
            } else {
                self.slot_a = Some((txn_id, b.clone()));
                Some(&mut self.slot_a.as_mut().unwrap().1)
            }
        } else {
            None
        }
    }

    pub(super) fn was_mutated<D: PrimaryTableDesc<Value = T>>(&self) -> bool {
        match (&self.slot_a, &self.slot_b) {
            (Some((_, a)), Some((_, b))) => !D::value_eq(a, b),
            _ => false,
        }
    }

    pub fn get(&self, id: TxnId) -> Option<&T> {
        // This could be expressed more simply with a match, but that doesn't work for `get_mut` because
        // of mutable borrows. Since the functions do the same thing, I use the more complex code
        // here too.
        if let Some((aid, a)) = &self.slot_a
            && id >= *aid
        {
            if let Some((bid, b)) = &self.slot_b
                && id >= *bid
            {
                debug_assert_ne!(aid, bid);
                if aid > bid { Some(a) } else { Some(b) }
            } else {
                Some(a)
            }
        } else if let Some((bid, b)) = &self.slot_b
            && id >= *bid
        {
            Some(b)
        } else {
            None
        }
    }

    pub(crate) fn get_mut(&mut self, id: TxnId) -> Option<&mut T> {
        if let Some((aid, a)) = &mut self.slot_a
            && id >= *aid
        {
            if let Some((bid, b)) = &mut self.slot_b
                && id >= *bid
            {
                debug_assert_ne!(aid, bid);
                if aid > bid { Some(a) } else { Some(b) }
            } else {
                Some(a)
            }
        } else if let Some((bid, b)) = &mut self.slot_b
            && id >= *bid
        {
            Some(b)
        } else {
            None
        }
    }

    pub(crate) fn set(&mut self, value: T, id: TxnId) {
        match (&mut self.slot_a, &mut self.slot_b) {
            (Some((vid, v)), _) | (_, Some((vid, v))) if id == *vid => {
                // Overwrite a value from the current transaction.
                *v = value;
            }
            (Some((aid, a)), Some((bid, b))) => {
                // Overwrite the older of two committed values.
                if aid > bid {
                    *b = value;
                    *bid = id;
                } else {
                    *a = value;
                    *aid = id;
                }
            }
            (None, _) => {
                // Write into an empty slot (the other must be committed or also empty).
                self.slot_a = Some((id, value));
            }
            (_, None) => {
                // Write into an empty slot (the other must be committed).
                self.slot_b = Some((id, value));
            }
        }
    }
}

impl<T: Clone + PartialEq> VersionedValue<T> {
    /// Pass a mutable reference to the value visible to `txn_id` (if there is one) to `f`.
    ///
    /// The value is cloned into `txn_id`'s slot (if it is not already there). If `f` leaves the
    /// value unchanged and `txn_id` had not already written the value, then the clone is
    /// discarded so that the value does not count as mutated.
    ///
    /// Returns `None` (and does not call `f`) if there is no value.
    pub(super) fn with_mut_value<R>(
        &mut self,
        txn_id: TxnId,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        // If this transaction has already written to the value, then it counts as mutated.
        let previously_written = self.modified_in_txn(txn_id).is_some();

        let value = self.internal_clone(txn_id)?;
        let old_value = (!previously_written).then(|| value.clone());
        let result = f(value);

        if old_value.is_some_and(|old_value| *value == old_value) {
            // `f` left the value alone, so discard the clone.
            self.gc_txn(txn_id);
        }

        Some(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transactions::TxnId;

    #[test]
    fn get_returns_none_when_empty() {
        let v: VersionedValue<u32> = VersionedValue::default();
        assert!(v.get(TxnId::new(2)).is_none());
    }

    #[test]
    fn get_returns_value_from_slot_a() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(2), 42u32)),
            slot_b: None,
        };
        assert_eq!(v.get(TxnId::new(2)), Some(&42));
    }

    #[test]
    fn get_returns_value_from_slot_b() {
        let v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 42u32)),
        };
        assert_eq!(v.get(TxnId::new(2)), Some(&42));
    }

    #[test]
    fn get_returns_none_when_id_less_than_slot_id() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(3), 42u32)),
            slot_b: None,
        };
        assert!(v.get(TxnId::new(2)).is_none());
    }

    #[test]
    fn get_returns_most_recent_when_both_slots_visible() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.get(TxnId::new(5)), Some(&10));
    }

    #[test]
    fn get_returns_value_when_id_exceeds_slot_id() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(2), 42u32)),
            slot_b: None,
        };
        assert_eq!(v.get(TxnId::new(5)), Some(&42));
    }

    #[test]
    fn get_returns_visible_value_when_one_slot_is_not_visible() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(5), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.get(TxnId::new(3)), Some(&20));
    }

    #[test]
    fn internal_clone_returns_none_when_empty() {
        let mut v: VersionedValue<u32> = VersionedValue::default();
        assert!(v.internal_clone(TxnId::new(2)).is_none());
    }

    #[test]
    fn internal_clone_copies_committed_value_into_free_slot() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: None,
        };
        *v.internal_clone(TxnId::new(4)).unwrap() = 99;
        // The committed value is left intact so that the transaction can be rolled back.
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 99)));
    }

    #[test]
    fn internal_clone_reuses_slot_from_same_txn() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: Some((TxnId::new(4), 99u32)),
        };
        *v.internal_clone(TxnId::new(4)).unwrap() += 1;
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 100)));
    }

    #[test]
    fn internal_clone_overwrites_older_of_two_committed_slots() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        // The most recently committed value is the one cloned, and the older one is overwritten.
        *v.internal_clone(TxnId::new(5)).unwrap() = 99;
        assert_eq!(v.slot_a, Some((TxnId::new(3), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(5), 99)));
    }

    #[test]
    fn set_into_empty_writes_to_slot_a() {
        let mut v: VersionedValue<u32> = VersionedValue::default();
        v.set(42, TxnId::new(2));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 42)));
        assert!(v.slot_b.is_none());
    }

    #[test]
    fn set_overwrites_same_txn_id_in_slot_a() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 1u32)),
            slot_b: None,
        };
        v.set(99, TxnId::new(2));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 99)));
    }

    #[test]
    fn set_overwrites_same_txn_id_in_slot_b() {
        let mut v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 1u32)),
        };
        v.set(99, TxnId::new(2));
        assert_eq!(v.slot_b, Some((TxnId::new(2), 99)));
    }

    #[test]
    fn set_overwrites_older_slot_when_both_valid() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        v.set(99, TxnId::new(4));
        assert_eq!(v.slot_a, Some((TxnId::new(3), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 99)));
    }

    #[test]
    fn set_writes_to_empty_slot_a_when_slot_b_populated() {
        let mut v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        v.set(99, TxnId::new(3));
        assert_eq!(v.slot_a, Some((TxnId::new(3), 99)));
        assert_eq!(v.slot_b, Some((TxnId::new(2), 20)));
    }

    #[test]
    fn set_writes_to_slot_b_when_slot_a_populated() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: None,
        };
        v.set(99, TxnId::new(3));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(3), 99)));
    }
}
