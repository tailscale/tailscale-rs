# bart

"BAlanced Routing Table", a path-compressed radix trie optimized for fast IP
address and prefix lookup with minimal memory footprint.

Based on the [Go implementation] of the same name.

[Go implementation]: <https://github.com/gaissmai/bart>

## Examples

```rust
use core::{
    str::FromStr,
    net::IpAddr,
};
use ts_bart::{
    Table,
    RoutingTable,
    RoutingTableExt,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut table = Table::default();

    let route_prefix = "1.0.0.0/8".parse()?;
    let forward_dst = "7.8.9.10".parse::<IpAddr>()?;

    // Insert a route into the table
    table.insert(route_prefix, forward_dst);

    // It can be retrieved with `lookup`
    assert_eq!(Some(&forward_dst), table.lookup("1.0.0.1".parse()?));

    let new_dst = "8.9.10.11".parse()?;

    // Modify the route in-place
    table.modify(route_prefix, |entry| {
        let entry = entry.unwrap();
        *entry = new_dst;

        ts_bart::RouteModification::Noop // do not remove or insert a new route
    });
    assert_eq!(Some(&new_dst), table.lookup("1.2.3.4".parse()?));

    // More-specific routes are preferred in lookups
    let child_prefix = "1.1.0.0/16".parse()?;
    let child_dst = "32.32.32.32".parse()?;
    table.insert(child_prefix, child_dst);

    assert_eq!(Some(&child_dst), table.lookup("1.1.3.4".parse()?));

    // Remove the route
    let removed_value = table.remove(route_prefix);
    assert_eq!(Some(new_dst), removed_value);
    assert_eq!(None, table.lookup("1.8.7.254".parse()?));

    Ok(())
}
```

## Performance

You can run the benchmarks with:

```sh
$ cargo bench
```

Current performance figures put us in the same ballpark as go-bart.

## Memory utilization

Amortized memory utilization for a large route table is about 24 bytes/route for IPv4 routes and
40 bytes/route for IPv6 routes -- this is just the prefix storage, the actual memory size will vary
with the stored value type. This is slightly worse than go-bart, which on my machine reports 20
bytes/rt for combined IPv4/IPv6, 37 bytes/rt for IPv6, and confusingly 101 bytes/rt for IPv4-only.

If using the table as a RIB (`IpAddr` table values), this comes out to ~48 bytes/rt for IPv4 and ~75
bytes/rt for IPv6.

## Implementation status

The current implementation should be usable as a routing table, though it hasn't been tested
in anger yet. Some of the more involved functionality provided by bart is lacking, however:

- Table inspection (sorted prefix walk primarily, we do provide a DFS node iterator)
- Table merging and intersection
- Optional persistent data structure functionality (shallow clone on mutate)
- Subnet/supernet queries
