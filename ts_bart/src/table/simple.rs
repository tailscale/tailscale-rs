use core::net::IpAddr;

use crate::{RouteModification, RoutingTable, iptrie, node};

/// Simple routing table that doesn't segregate IPv4 and IPv6
/// routes.
///
/// The prefix `8.0.0.0/8` is treated equivalently to `0800::/8` by this table.
/// You most likely want [`SplitStackTable`][super::SplitStackTable] if you're
/// operating in a dual-IP-stack environment.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct SimpleTable<Node> {
    root: Node,
    size: usize,
}

impl<Node> SimpleTable<Node> {
    /// Get a handle to the root node.
    pub const fn root(&self) -> &Node {
        &self.root
    }
}

impl<T, C> SimpleTable<crate::Node<T, C>>
where
    C: ?Sized + crate::Storage,
{
    /// The empty table.
    pub const EMPTY: Self = SimpleTable {
        root: crate::Node::EMPTY,
        size: 0,
    };
}

impl<Node> RoutingTable for SimpleTable<Node>
where
    Node: node::StrideOps,
{
    type Value = Node::T;

    fn contains(&self, ip: IpAddr) -> bool {
        iptrie::contains(&self.root, ip)
    }

    fn insert(&mut self, prefix: ipnet::IpNet, val: Node::T) -> Option<Node::T> {
        let ret = iptrie::insert(&mut self.root, prefix.trunc(), val);

        if ret.is_none() {
            self.size += 1;
        }

        ret
    }

    fn remove(&mut self, prefix: ipnet::IpNet) -> Option<Node::T> {
        iptrie::remove(&mut self.root, prefix).inspect(|_| {
            self.size -= 1;
        })
    }

    fn modify_impl(
        &mut self,
        prefix: ipnet::IpNet,
        modify: &mut dyn FnMut(Option<&mut Node::T>) -> RouteModification<Node::T>,
    ) -> Option<Node::T> {
        enum Op {
            Noop,
            Insert,
            Remove,
        }

        let mut op = Op::Noop;

        let ret = iptrie::modify(&mut self.root, prefix, |val| {
            let ret = modify(val);
            op = match &ret {
                RouteModification::Noop => Op::Noop,
                RouteModification::Remove => Op::Remove,
                RouteModification::Insert(..) => Op::Insert,
            };

            ret
        });

        match (&ret, op) {
            (None, Op::Insert) => {
                self.size += 1;
            }
            (Some(..), Op::Remove) => {
                self.size -= 1;
            }
            _ => {}
        }

        ret
    }

    fn clear(&mut self) {
        self.root = Node::default();
        self.size = 0;
    }

    fn lookup(&self, ip: IpAddr) -> Option<&Node::T> {
        iptrie::lookup_address(&self.root, ip)
    }

    fn lookup_all(&self, ip: IpAddr) -> iptrie::LookupIter<'_, Self::Value> {
        iptrie::lookup_address_all(&self.root, ip)
    }

    fn lookup_prefix_exact(&self, prefix: ipnet::IpNet) -> Option<&Node::T> {
        iptrie::lookup_prefix_exact(&self.root, prefix)
    }

    fn lookup_prefix(&self, prefix: ipnet::IpNet) -> Option<&Node::T> {
        iptrie::lookup_prefix_lpm(&self.root, prefix).map(|(_, t)| t)
    }

    fn lookup_prefix_lpm(&self, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &Node::T)> {
        iptrie::lookup_prefix_lpm(&self.root, prefix)
    }

    fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{RoutingTableExt, pfx};

    #[test]
    fn size_tracking() {
        let mut table = crate::SimpleTable::EMPTY;

        table.insert(pfx!("1.2.3.4/8"), 32);
        assert_eq!(1, table.size());

        table.remove(pfx!("1.2.3.4/8"));
        assert_eq!(0, table.size());

        {
            table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Insert(33));
            assert_eq!(1, table.size());

            // Idempotent
            table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Insert(33));
            assert_eq!(1, table.size());
        }

        table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Noop);
        assert_eq!(1, table.size());

        {
            table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Remove);
            assert_eq!(0, table.size());

            // Idempotent (no panic)
            table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Remove);
            assert_eq!(0, table.size());
        }

        // Noop on empty table is fine
        table.modify(pfx!("1.2.3.4/8"), |_entry| RouteModification::Noop);
        assert_eq!(0, table.size());
    }
}
