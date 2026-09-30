use core::net::IpAddr;

use crate::{RouteModification, RoutingTable, iptrie, node, table};

/// Routing table that segregates routes into independent IPv4 and IPv6 tables.
///
/// This is likely the kind of table you want unless you know you'll be
/// operating in an exclusively-single-stack environment and want to save the
/// slight runtime overhead of discriminating on address type.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct SplitStackTable<Node> {
    table4: table::SimpleTable<Node>,
    table6: table::SimpleTable<Node>,
}

impl<T, C> SplitStackTable<crate::Node<T, C>>
where
    C: ?Sized + crate::Storage,
{
    /// The empty table.
    pub const EMPTY: Self = Self {
        table4: table::SimpleTable::EMPTY,
        table6: table::SimpleTable::EMPTY,
    };
}

impl<Node> SplitStackTable<Node>
where
    Node: node::StrideOps,
{
    /// Report the total number of IPv4 routes stored in the table.
    pub fn size4(&self) -> usize {
        self.table4.size()
    }

    /// Report the total number of IPv6 routes stored in the table.
    pub fn size6(&self) -> usize {
        self.table6.size()
    }

    /// Get a reference to the root node for the given ip stack.
    pub const fn root(&self, ipv4: bool) -> &Node {
        if ipv4 {
            self.table4.root()
        } else {
            self.table6.root()
        }
    }

    const fn stack_table(&self, ipv4: bool) -> &table::SimpleTable<Node> {
        if ipv4 { &self.table4 } else { &self.table6 }
    }

    const fn stack_table_mut(&mut self, ipv4: bool) -> &mut table::SimpleTable<Node> {
        if ipv4 {
            &mut self.table4
        } else {
            &mut self.table6
        }
    }
}

impl<Node> RoutingTable for SplitStackTable<Node>
where
    Node: node::StrideOps,
{
    type Value = Node::T;

    fn contains(&self, ip: IpAddr) -> bool {
        self.stack_table(ip.is_ipv4()).contains(ip)
    }

    fn insert(&mut self, prefix: ipnet::IpNet, val: Node::T) -> Option<Node::T> {
        self.stack_table_mut(prefix.addr().is_ipv4())
            .insert(prefix, val)
    }

    fn remove(&mut self, prefix: ipnet::IpNet) -> Option<Node::T> {
        self.stack_table_mut(prefix.addr().is_ipv4()).remove(prefix)
    }

    fn modify_impl(
        &mut self,
        prefix: ipnet::IpNet,
        modify: &mut dyn FnMut(Option<&mut Node::T>) -> RouteModification<Node::T>,
    ) -> Option<Node::T> {
        self.stack_table_mut(prefix.addr().is_ipv4())
            .modify_impl(prefix, modify)
    }

    fn clear(&mut self) {
        self.table4.clear();
        self.table6.clear();
    }

    fn lookup(&self, ip: IpAddr) -> Option<&Node::T> {
        self.stack_table(ip.is_ipv4()).lookup(ip)
    }

    fn lookup_all(&self, ip: IpAddr) -> iptrie::LookupIter<'_, Self::Value> {
        self.stack_table(ip.is_ipv4()).lookup_all(ip)
    }

    fn lookup_prefix_exact(&self, prefix: ipnet::IpNet) -> Option<&Node::T> {
        self.stack_table(prefix.addr().is_ipv4())
            .lookup_prefix_exact(prefix)
    }

    fn lookup_prefix(&self, prefix: ipnet::IpNet) -> Option<&Node::T> {
        self.stack_table(prefix.addr().is_ipv4())
            .lookup_prefix(prefix)
    }

    fn lookup_prefix_lpm(&self, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &Node::T)> {
        self.stack_table(prefix.addr().is_ipv4())
            .lookup_prefix_lpm(prefix)
    }

    fn size(&self) -> usize {
        self.table4.size() + self.table6.size()
    }
}
