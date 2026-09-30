This crate is a port of [bart](https://github.com/gaissmai/bart) to Rust. Bart is somewhat lacking
in documentation/explanation, so this is an attempt at more clearly capturing the implicit
reasoning that went into its design, which is largely replicated in this port.

At a high level, this crate provides an IP address prefix trie providing lookup from IP prefixes to
a user-provided value type: `Table` looks like a typical `Map<IpPrefix, Value>` interface,
with `insert`, `remove`, `modify` (in-place), `lookup`. If we specify the `Value` type to be an IP
address, this is a routing table: we would have `bart::Table<IpAddr>`, which supports operations
like `insert(0.0.0.0/0, 192.168.0.1)` (create a default route `via 192.168.0.1`) and
`lookup(1.2.3.4)`, returning the narrowest matching table entry.

The value of this specialized implementation (as compared to a generic radix trie) is optimization
in both speed and memory. We know certain facts a priori about IP prefixes, like that their bits are
always set contiguously from the left, and that they have a hierarchical ordering (/0 supersets two
/1s, which each superset two /2s, etc.). These invariants enable a compact prefix representation
(Knuth's `baseIndex`), which can store an n-bit address-and-prefix (e.g. `123/7`) in an n+1 bit
encoding. This saves memory in the keyspace representation, but more importantly is amenable to
rapid superset/subset queries using bitwise operations (see `Bitset256::rank` as well as the
functions in `allot` and `lpm`).

Notably, this crate's `BaseIndex` is 8 bits, meaning that it can only represent up to /7 prefixes,
while the IP addresses we operate on are divided into octets. This turns out to be fine because we
represent the extra bit as a structural feature of the trie nodes: this node's prefixes (indexed by
`BaseIndex`, up through /7) are stored in one location, and the node's _children_ (arbitrarily-deep
descendants, starting at the next /8) are stored adjacently, indexed by next-octet.

Memory is optimized in a few ways. First, through the use of sparse, `Vec`-backed arrays of up to
256 elements (intentionally corresponding to both the cardinality of u8 and BaseIndex): `Array256<T>`
presents an interface like `[Option<T>; 256]`, but only occupies memory up to the actual array
occupancy. This can represent substantial memory savings in a characteristically sparsely-occupied
structure like a routing table; it takes up "horizontal" sparseness in the structure. Second, path
compression is supported; trie nodes can be "leaves", a special kind that inlines a whole path
through the tree, when the prefix is a unique child of some parent. I.e. if I add `1.2.0.0/15` to
an empty trie, the root node will store it as a leaf under `1` without creating any children. Only
by adding another prefix sharing the first octet, e.g. `1.3.0.0/14`, will the leaf be upgraded into
a full node containing both prefixes. This takes up the "vertical sparseness" in the structure.

A slight further optimization worth mentioning is that child nodes may be "fringe" nodes when the
prefix length lies on an octet boundary, e.g. 1.2.0.0/16. In this case, the path to the node is
treated as its complete address: 1.2.0.0/16 is at: ROOT -> 1 -> 2 (FRINGE). Like leaf nodes, they
must be unique children at their address and are replaced by full nodes if multiple occupancy is
required at the given tree depth (and then stored as prefix values in the child).
