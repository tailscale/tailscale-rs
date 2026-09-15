use crate::{
    Node,
    node::{Child, child_storage::Storage},
};

impl<T, C> Node<T, C>
where
    C: Storage + ?Sized,
{
    /// Get all the descendant [`Child`]ren of this node. Order is depth-first,
    /// in-order by address.
    pub fn descendants(
        &self,
        include_self: bool,
    ) -> impl Iterator<Item = (heapless::Vec<u8, 16>, Child<&Self, &T>)> {
        DescendantIter::new(self, include_self)
    }

    /// Get all the descendant [`Node`]s of this node. Order is depth-first,
    /// in-order by address.
    pub fn descendant_nodes(
        &self,
        include_self: bool,
    ) -> impl Iterator<Item = (heapless::Vec<u8, 16>, &Self)> {
        DescendantIter::new(self, include_self).filter_map(|(addr, child)| match child {
            Child::Path(node) => Some((addr, node)),
            _ => None,
        })
    }
}

/// Provides a DFS walk of the trie rooted at a given node.
struct DescendantIter<'a, T, C>
where
    C: Storage + ?Sized,
{
    /// The current (being-iterated) item in the trie.
    node_path: heapless::Vec<(u8, &'a Node<T, C>), 16>,

    /// The next child address to be considered.
    next_child: u8,

    yield_self: bool,
}

impl<'a, T, C> DescendantIter<'a, T, C>
where
    C: Storage + ?Sized,
{
    fn new(node: &'a Node<T, C>, include_self: bool) -> Self {
        Self {
            // The first address in the path is ignored.
            node_path: heapless::Vec::from_iter([(0, node)]),
            next_child: 0,
            yield_self: include_self,
        }
    }
}

impl<'a, T, C> Iterator for DescendantIter<'a, T, C>
where
    C: Storage + ?Sized,
{
    type Item = (heapless::Vec<u8, 16>, Child<&'a Node<T, C>, &'a T>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.yield_self {
            self.yield_self = false;
            return Some((
                heapless::Vec::new(),
                // invariant: always constructed with `new`, there is always at least one
                // entry
                Child::Path(self.node_path.first().unwrap().1),
            ));
        }

        while let Some(&(this_addr, node)) = self.node_path.last() {
            let ret = match node
                .children
                .iter()
                .find(|&(addr, _)| addr >= self.next_child)
            {
                Some((addr, child)) => {
                    let mut path = self
                        .node_path
                        .iter()
                        .map(|&(addr, _node)| addr)
                        .skip(1) // skip the root item's path
                        .collect::<heapless::Vec<u8, 16>>();

                    path.push(addr).unwrap();

                    if let Child::Path(node) = child {
                        // invariant: node path is sized to fit any ipv4/ipv6 addr
                        self.node_path
                            .push((addr, C::as_ref(node)))
                            .map_err(|_| ())
                            .unwrap();
                        self.next_child = 0;
                        return Some((path, child.as_ref().map_node(C::as_ref)));
                    }

                    self.next_child = addr;

                    Some((path, child.as_ref().map_node(C::as_ref)))
                }

                None => {
                    self.node_path.pop();
                    self.next_child = this_addr;
                    None
                }
            };

            while self.next_child == 255 {
                let Some((popped, _)) = self.node_path.pop() else {
                    break;
                };

                self.next_child = popped;
            }

            self.next_child += 1;

            if ret.is_some() {
                return ret;
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::node::StrideOpsExt;

    #[test]
    fn zero() {
        assert_eq!(0, Node::<()>::EMPTY.descendants(false).count());
        assert_eq!(0, Node::<()>::EMPTY.descendant_nodes(false).count());

        assert_eq!(1, Node::<()>::EMPTY.descendants(true).count());
        assert_eq!(1, Node::<()>::EMPTY.descendant_nodes(true).count());
    }

    #[test]
    fn single_level() {
        let node = Node::<()>::EMPTY
            .with_child(0, Child::Fringe(()))
            .with_child(1, Child::Fringe(()))
            .with_child(255, Child::Fringe(()));

        assert_eq!(3, node.descendants(false).count());

        let node = node.with_child(
            3,
            Child::Leaf {
                prefix: Default::default(),
                value: Default::default(),
            },
        );
        assert_eq!(4, node.descendants(false).count());
        assert_eq!(0, node.descendant_nodes(false).count());

        node.descendants(false)
            .zip([0, 1, 3, 255])
            .for_each(|((path, child), addr)| {
                assert_eq!(&path, &[addr]);
                match child {
                    Child::Leaf { .. } | Child::Fringe(..) => {}
                    Child::Path(..) => panic!(),
                }
            });
    }

    #[test]
    fn multi_level() {
        let node = Node::<()>::EMPTY
            .with_child(0, Child::dummy_leaf())
            .with_child(
                2,
                Node::EMPTY
                    .with_child(12, Child::dummy_leaf())
                    .with_child(32, Child::dummy_fringe())
                    .into_child(),
            )
            .with_child(5, Child::dummy_leaf())
            .with_child(
                255,
                Node::EMPTY
                    .with_child(0, Child::dummy_fringe())
                    .with_child(1, Child::dummy_fringe())
                    .with_child(255, Node::EMPTY.into_child())
                    .into_child(),
            );

        assert_eq!(9, node.descendants(false).count());
        assert_eq!(10, node.descendants(true).count());
        assert_eq!(3, node.descendant_nodes(false).count());
        assert_eq!(4, node.descendant_nodes(true).count());

        for ((path, _child), expected_path) in node.descendants(false).zip([
            &[0u8] as &[u8],
            &[2],
            &[2, 12],
            &[2, 32],
            &[5],
            &[255],
            &[255, 0],
            &[255, 1],
            &[255, 255],
        ]) {
            assert_eq!(&path, expected_path);
        }

        for ((path, _child), expected_path) in
            node.descendant_nodes(false)
                .zip([&[2u8] as &[u8], &[255], &[255, 255]])
        {
            assert_eq!(&path, expected_path);
        }
    }
}
