use core::{fmt::Formatter, ops::RangeInclusive};

use ts_bart::BaseIndex;

use crate::port_trie::{Child, PortTrie};

#[derive(Clone, Copy, PartialEq)]
pub enum PortPrefix {
    Prefix(BaseIndex),
    ChildPrefix { hi: u8, lo_pfx: BaseIndex },
    Singleton(u16),
}

impl core::fmt::Debug for PortPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let ty = match self {
            Self::Prefix(..) => "pfx",
            Self::ChildPrefix { .. } => "child_pfx",
            Self::Singleton { .. } => "singleton",
        };

        let (pfx, bits) = self.prefix_form();
        write!(f, "PortPrefix({pfx}/{bits}: {ty})")
    }
}

impl PortPrefix {
    const fn from_pfx(port: u16, pfx: u8) -> Self {
        match pfx {
            16 => Self::singleton(port),
            0..8 => Self::Prefix(BaseIndex::from_prefix(PortTrie::<()>::port_byte(port), pfx)),
            _ => Self::ChildPrefix {
                hi: PortTrie::<()>::port_byte(port),
                lo_pfx: BaseIndex::from_prefix(Child::<()>::port_byte(port), pfx - 8),
            },
        }
    }

    const fn singleton(port: u16) -> Self {
        Self::Singleton(port)
    }

    const fn prefix_form(&self) -> (u16, u8) {
        match self {
            Self::Singleton(port) => (*port, 16),
            Self::ChildPrefix { hi, lo_pfx } => {
                let (lo_addr, lo_len) = lo_pfx.prefix();

                (u16::from_be_bytes([*hi, lo_addr]), 8 + lo_len)
            }
            Self::Prefix(idx) => {
                let (addr, len) = idx.prefix();

                (u16::from_be_bytes([addr, 0]), len)
            }
        }
    }

    pub const fn start(&self) -> u16 {
        let (addr, _len) = self.prefix_form();
        addr
    }

    pub const fn end(&self) -> u16 {
        let (addr, len) = self.prefix_form();

        if len == 0 {
            return u16::MAX;
        }

        let range = 0x8000u16 >> (len - 1);
        addr.saturating_add(range - 1)
    }

    pub const fn to_range(self) -> RangeInclusive<u16> {
        self.start()..=self.end()
    }
}

impl From<PortPrefix> for RangeInclusive<u16> {
    fn from(value: PortPrefix) -> Self {
        value.start()..=value.end()
    }
}

pub const fn iter_prefixes(ports: RangeInclusive<u16>) -> impl Iterator<Item = PortPrefix> {
    PortPrefixIter {
        start: *ports.start(),
        end: *ports.end(),
    }
}

struct PortPrefixIter {
    start: u16,
    end: u16,
}

impl Iterator for PortPrefixIter {
    type Item = PortPrefix;

    fn next(&mut self) -> Option<Self::Item> {
        use core::cmp::Ordering;

        match self.start.cmp(&self.end) {
            Ordering::Less => {
                let range = self.end.saturating_sub(self.start).saturating_add(1);

                if range == u16::MAX {
                    // Done with iteration, we have the whole range
                    self.end = 0;
                    self.start = 1;

                    return Some(PortPrefix::from_pfx(0, 0));
                }

                let range_bits = 16u8
                    .saturating_sub(range.leading_zeros() as _)
                    .saturating_sub(1);

                let start_tz = self.start.trailing_zeros() as u8;
                let new_prefix_len = 16 - core::cmp::min(range_bits, start_tz);

                let ret = PortPrefix::from_pfx(self.start, new_prefix_len);
                self.start = ret.end().saturating_add(1);
                if self.start == u16::MAX {
                    // This is the one case where the add saturates: kill iteration so as not to
                    // emit an overlapping 65535/16
                    self.end = 0;
                }

                Some(ret)
            }

            Ordering::Equal => {
                let ret = Some(PortPrefix::singleton(self.start));

                // Just ensure that the next call returns Ordering::Greater to end the iteration
                self.end = 0;
                self.start = 1;

                ret
            }

            Ordering::Greater => None,
        }
    }
}

#[cfg(test)]
mod test {
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn basic() {
        let s = PortPrefix::singleton(32);
        assert_eq!(32, s.start());
        assert_eq!(32, s.end());

        let s = PortPrefix::from_pfx(32, 16);
        assert_eq!(32, s.start());
        assert_eq!(32, s.end());

        let s = PortPrefix::from_pfx(32, 15);
        assert_eq!(32, s.start());
        assert_eq!(33, s.end());
    }

    fn pfxs(range: RangeInclusive<u16>) -> alloc::vec::Vec<PortPrefix> {
        iter_prefixes(range).collect()
    }

    #[test]
    fn iter() {
        assert_eq!(vec![PortPrefix::singleton(32)], pfxs(32..=32));

        assert_eq!(vec![PortPrefix::from_pfx(32, 15),], pfxs(32..=33));

        assert_eq!(
            vec![PortPrefix::from_pfx(32, 15), PortPrefix::singleton(34),],
            pfxs(32..=34)
        );

        assert_eq!(vec![PortPrefix::from_pfx(65534, 15)], pfxs(65534..=65535));

        assert_eq!(vec![PortPrefix::from_pfx(0, 0)], pfxs(0..=65535),);
    }

    fn check_iter(mut start: u16, mut end: u16) {
        if start > end {
            core::mem::swap(&mut start, &mut end);
        }

        let iter = PortPrefixIter { start, end };

        #[derive(Debug, PartialEq)]
        enum Current {
            Start(u16),
            SegmentEnd(u16),
        }

        let mut current = Current::Start(start);

        for elem in iter {
            match current {
                Current::Start(c) => assert_eq!(elem.start(), c),
                Current::SegmentEnd(c) => assert_eq!(elem.start(), c + 1),
            }

            current = Current::SegmentEnd(elem.end());
        }

        assert_eq!(Current::SegmentEnd(end), current);
    }

    #[test]
    fn iter_0_2() {
        check_iter(0, 2);
    }

    proptest::prop_compose! {
        fn port_prefix()(port: u16, pfx in 0u8..=16) -> PortPrefix {
            PortPrefix::from_pfx(port, pfx)
        }
    }

    proptest::proptest! {
        #[test]
        fn singleton(port: u16) {
            let s = PortPrefix::singleton(port);
            prop_assert_eq!(port, s.start());
            prop_assert_eq!(port, s.end());

            prop_assert_eq!((port, 16), s.prefix_form());

            prop_assert_eq!(vec![s], pfxs(port..=port));
        }

        #[test]
        fn pairs(port: u16) {
            let port = port - port % 2;

            let s = PortPrefix::from_pfx(port, 15);
            prop_assert_eq!(port, s.start());
            prop_assert_eq!(port + 1, s.end());
        }

        #[test]
        fn prefix_form_roundtrips(port: u16, pfx in 0u8..=16) {
            let s = PortPrefix::from_pfx(port, pfx);

            let n_pfx_mask = (1usize << (16 - pfx as usize)) - 1;
            let pfx_mask = !n_pfx_mask as u16;

            let port_canonical = port & pfx_mask;

            prop_assert_eq!((port_canonical, pfx), s.prefix_form());
        }

        #[test]
        fn range_correct_size(s in port_prefix()) {
            let (_, pfx) = s.prefix_form();

            let range = (s.end() - s.start()) as usize + 1; // inclusive
            let pfx_implied_range = 1usize << (16 - pfx) as usize;

            prop_assert_eq!(
                pfx_implied_range, range,
                "start: {}, end: {}, implied range: {}", s.start(), s.end(), pfx_implied_range
            );
        }

        #[test]
        fn iter_correct(mut start: u16, mut end: u16) {
            check_iter(start, end)
        }
    }
}
