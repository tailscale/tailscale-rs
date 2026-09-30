use crate::{PrefixReadOps, iptrie, node::NodePrefixIter};

/// Iterator over prefixes matching a particular address.
///
/// Built by [`iptrie::lookup_address_all`].
pub struct LookupIter<'n, T> {
    /// The first item, if there was a child entry.
    pub(super) value: Option<&'n T>,

    /// The stack of nodes in the trie that matched the address query.
    pub(super) stack: heapless::Vec<(&'n dyn PrefixReadOps<T = T>, u8), { iptrie::MAX_DEPTH }>,

    /// Intermediate partially-yielded state for prefix matches on the current stack item.
    pub(super) prefix_iter: Option<NodePrefixIter<'n, T>>,
}

impl<T> Default for LookupIter<'_, T> {
    fn default() -> Self {
        Self {
            value: None,
            stack: Default::default(),
            prefix_iter: None,
        }
    }
}

impl<'n, T> Iterator for LookupIter<'n, T>
where
    T: 'static,
{
    type Item = &'n T;

    fn next(&mut self) -> Option<Self::Item> {
        // There was a terminal leaf or fringe value: return it first.
        if let Some(val) = self.value.take() {
            return Some(val);
        }

        walk_stack(&mut self.stack, &mut self.prefix_iter)
    }
}

pub(super) fn walk_stack<'n, T>(
    stack: &mut heapless::Vec<(&'n dyn PrefixReadOps<T = T>, u8), { iptrie::MAX_DEPTH }>,
    prefix_iter: &mut Option<NodePrefixIter<'n, T>>,
) -> Option<&'n T>
where
    T: 'static,
{
    while let Some(&(node, octet)) = stack.last() {
        if let Some(iter) = prefix_iter {
            if let Some((_idx, val)) = iter.next() {
                return Some(val);
            }

            prefix_iter.take();
            stack.pop();
            continue;
        }

        // Populate state for the next iteration of the loop
        *prefix_iter = Some(NodePrefixIter::for_octet(node, octet));
    }

    None
}
