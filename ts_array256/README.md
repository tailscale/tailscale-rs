# ts_array256

A sparse array of 256 elements.

Used in `bart` as sparse backing storage for the node tries. Generally
useful for memory-efficient storage of items indexed by `u8`.

Indexed by [`Bitset256`] and has configurable backing [`ArrayStorage`]
(typically `Vec`).

# Examples

```rust
use ts_array256::Array256;
use ts_bitset::Bitset256;

fn main() {
    let mut ary = Array256::<Vec<usize>>::default();

    ary.insert(0, 1234);
    assert_eq!(ary.get(0), Some(&1234));
    assert_eq!(ary.get(123), None);

    *ary.get_mut(0).unwrap() += 1;
    assert_eq!(ary.get(0), Some(&1235));

    ary.insert(3, 555);

    let bitset_test = Bitset256::EMPTY.with_bits(&[0, 1, 2, 3, 4]);
    let intersected_bit = ary.intersection_top(&bitset_test);
    assert_eq!(intersected_bit, Some(3));
    assert_eq!(
        Bitset256::EMPTY.with_bits(&[0, 3]),
        bitset_test &*ary.bitset(),
    );
}
```
