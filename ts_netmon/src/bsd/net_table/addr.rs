use core::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use nom::{
    AsBytes, Compare, Parser,
    branch::alt,
    bytes::{tag, take},
    combinator::{complete, fail, opt, peek, rest_len, success},
    error::{FromExternalError, ParseError},
    number::{Endianness, u8, u16, u32},
    sequence::{preceded, terminated},
};

use crate::bsd::{
    net_table,
    net_table::{ALIGN, Af, CInt},
};

/// Parse a `sockaddr` header for the length and [`Af`].
pub fn sa_hdr<I, E>() -> impl Parser<I, Output = (u8, Af), Error = E>
where
    I: nom::Input<Item = u8> + Copy,
    E: ParseError<I>,
{
    (u8(), u8().map(|x| Af::from(CInt::new(x as _))))
}

const HEADER_LEN: u8 = 2;

/// An address parsed after a given message.
#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv6 address with scope.
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        /// The scope (interface index).
        scope: u32,
    },
    /// Link address: used as a place to put the link name and Ethernet MAC in most cases.
    Link(LinkAddr),
    /// Prefix length.
    PrefixLen(PrefixLen),
    /// This address was unspecified.
    Unspecified,
}

impl<'a> TryFrom<&'a Address> for IpAddr {
    type Error = ();

    fn try_from(addr: &'a Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ipv4) => Ok(IpAddr::V4(*ipv4)),
            Address::Ipv6 { addr, .. } => Ok(IpAddr::V6(*addr)),
            _ => Err(()),
        }
    }
}

impl TryFrom<Address> for IpAddr {
    type Error = ();

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        (&addr).try_into()
    }
}

/// An IP address prefix length.
///
/// Each field is populated if it was possible to parse it from the input. This may be unambiguous
/// if the input was too long to be IPv4 or too short to be IPv6.
///
/// It is done this way to make the parsing not context-sensitive (otherwise we would need a hint
/// about which kind of address we're supposed to be calculating a mask for).
///
/// The underlying representation of the mask is an actual address netmask, which could be invalid
/// as a prefix (i.e. discontiguous). These masks are rejected and the prefix len set to `None`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrefixLen {
    /// IPv4 prefix length, if it could be parsed from the input.
    pub v4: Option<u8>,
    /// IPv6 prefix length, if it could be parsed from the input.
    pub v6: Option<u8>,
}

impl Default for PrefixLen {
    fn default() -> Self {
        Self {
            v4: Some(32),
            v6: Some(128),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Ipv4(x) => x.fmt(f),
            Address::Ipv6 { addr, scope } => {
                if *scope == 0 {
                    addr.fmt(f)
                } else {
                    write!(f, "{addr:?}%{scope}")
                }
            }
            Address::Link(x) => x.fmt(f),
            Address::PrefixLen(x) => x.fmt(f),
            Address::Unspecified => write!(f, "Unspecified"),
        }
    }
}

/// Parse a possibly-XNU-truncated `sockaddr` from the input.
///
/// This parser is complicated by the fact that XNU both (may) truncate addresses with trailing
/// zeroes and pads each possibly-truncated message up to 4-byte alignment. Also, it mwy null out
/// the `sockaddr` completely (and truncate to _just_ `sa_len` and `sa_family`), which sometimes
/// means "no address" and other times means "full netmask" (/32 or /128) – the _empty_ netmask is,
/// of course, populated.
pub fn partial_sockaddr<I, E>() -> impl Parser<I, Output = Option<Address>, Error = E>
where
    I: nom::Input<Item = u8> + AsBytes + Copy + for<'a> Compare<&'a [u8]>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    sa_hdr().flat_map(|(sa_len, af)| {
        // tracing::trace!(?af, sa_len);

        let (addr_len, read_len) = if af == Af::Unspec && sa_len == 0 {
            // Special case: normally, sa_len refers to the whole length of the sockaddr structure.
            // If the af and sa_len are nulled out, the kernel is telling us this is an empty address
            // entry, so don't interpret sa_len.
            (0, ALIGN - HEADER_LEN)
        } else if sa_len == 0 {
            panic!("sa_len = 0 but af = {af:?} (expected {:?})", Af::Unspec)
        } else {
            // We need to pad based on the length of the full address chunk (including sa_{len,family}).
            // sa_len gives us that full length directly.
            let padded_len = net_table::round_up(sa_len as usize, ALIGN as _);

            // But the amount to read _from here_ excludes the len/family:
            let read_len = (padded_len - HEADER_LEN as usize) as u8;

            (sa_len - HEADER_LEN, read_len)
        };

        let padding_len = read_len - addr_len;

        // tracing::trace!(?af, addr_len, read_len, padding_len);

        terminated(take(addr_len), take(padding_len)).and_then({
            alt((
                cond_fail(af == Af::Link, sockaddr_dl_body()).map(|dl| Some(Address::Link(dl))),
                cond_fail(af == Af::Inet, partial_sockaddr_in_body())
                    .map(|addr| Some(Address::Ipv4(addr))),
                cond_fail(af == Af::Inet6, partial_sockaddr_in6_body())
                    .map(|(addr, scope)| Some(Address::Ipv6 { addr, scope })),
                cond_fail(af == Af::Unspec, success(Some(Address::Unspecified))),
                cond_fail(
                    af == Af::Other(0xff),
                    (
                        opt(peek(complete(partial_sockaddr_in_body()))),
                        opt(complete(partial_sockaddr_in6_body())),
                    ),
                )
                .map(|(v4, v6)| {
                    Some(Address::PrefixLen(PrefixLen {
                        v4: v4.and_then(|addr| {
                            let x = u32::from(addr);
                            let count = x.count_ones();

                            if x.leading_ones() != count {
                                tracing::warn!(mask = ?addr, "reject non-prefix ipv4 netmask");
                                return None;
                            }

                            Some(count as u8)
                        }),
                        v6: v6.and_then(|(addr, _)| {
                            let x = u128::from(addr);
                            let count = x.count_ones();

                            if x.leading_ones() != count {
                                tracing::warn!(mask = ?addr, "reject non-prefix ipv6 netmask");
                                return None;
                            }

                            Some(count as u8)
                        }),
                    }))
                }),
                success(None).map(move |x| {
                    tracing::warn!(unhandled_af = ?af);
                    x
                }),
            ))
        })
    })
}

/// Like [`nom::combinator::cond`], but fails if the condition is `false`.
///
/// Can be used with [`alt`] to emulate a `match` statement with different parsers in each arm.
fn cond_fail<I, P>(c: bool, mut parser: P) -> impl Parser<I, Error = P::Error, Output = P::Output>
where
    P: Parser<I>,
{
    move |input| {
        if c {
            parser.parse(input)
        } else {
            fail().parse(input)
        }
    }
}

/// Parse a partial `sockaddr_in`, retrieving a possibly-truncated IP address.
///
/// It's assumed that `sin_len` and `sin_addr` have already been consumed and the input is starting
/// at the first port byte, and all trailing padding has been removed (i.e. the input ends on the
/// last byte of the address).
pub fn partial_sockaddr_in_body<I, E>() -> impl Parser<I, Output = Ipv4Addr, Error = E>
where
    I: nom::Input<Item = u8> + AsBytes,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    let port = u16(Endianness::Native);
    preceded(port, partial_inaddr())
}

/// Parse a partial `sockaddr_in6`, retrieving a possibly-truncated IP address.
///
/// It's assumed that `sin6_len` and `sin6_addr` have already been consumed and the input is
/// starting at the first port byte, and all trailing padding has been removed (i.e. the input ends
/// on the last byte of the address).
pub fn partial_sockaddr_in6_body<I, E>() -> impl Parser<I, Output = (Ipv6Addr, u32), Error = E>
where
    I: nom::Input<Item = u8> + AsBytes + for<'a> Compare<&'a [u8]>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    let port = u16(Endianness::Native);
    let flowinfo = u32(Endianness::Native);

    preceded((port, flowinfo), partial_in6addr())
}

/// Parse an IPv4 address from a possibly-truncated `in_addr`.
///
/// The address is left-justified and can be any length up to 4 bytes, including zero; any bytes not
/// included in the address are zeroed.
pub fn partial_inaddr<I, E>() -> impl Parser<I, Output = Ipv4Addr, Error = E>
where
    I: nom::Input<Item = u8> + AsBytes,
    E: ParseError<I>,
{
    take_array_zeroed::<_, _, 4>().map(|(addr, _n)| Ipv4Addr::from_octets(addr))
}

/// Parse an IPv6 address from a possibly-truncated `in6_addr`.
///
/// The address is left justified and can be any length up to 16 bytes, including zero; any bytes not
/// included in the address are zeroed. The scope is only parsed if there are a full 20 bytes
/// available in the input.
///
/// We also attempt to parse the scope from its conventional KAME embedding in an interface- or
/// link-local address.
pub fn partial_in6addr<I, E>() -> impl Parser<I, Output = (Ipv6Addr, u32), Error = E>
where
    I: nom::Input<Item = u8> + AsBytes + for<'a> Compare<&'a [u8]>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    (
        peek(opt(complete(kame_scope()))),
        take_array_zeroed::<_, _, 16>(),
        opt(complete(u32(Endianness::Native))),
    )
        .map(|(kame_scope, (mut octets, _n), scope)| {
            let mut scope = scope.unwrap_or_default();

            if let Some(kame_scope) = kame_scope
                && kame_scope != 0
            {
                if scope != 0 && scope != kame_scope as _ {
                    tracing::warn!(
                        sockaddr_in6_scope = scope,
                        kame_scope,
                        "kame-embedded scope mismatched sockaddr_in6 field"
                    );
                }

                scope = kame_scope as _;

                // Erase the embedded scope.
                octets[2..4].fill(0);
            }

            (Ipv6Addr::from(octets), scope)
        })
}

/// KAME stack conventionally embeds the scope in the link- or interface-local address: check
/// whether the prefix matches, then read the second segment.
fn kame_scope<I, E>() -> impl Parser<I, Output = u16, Error = E>
where
    I: nom::Input<Item = u8> + for<'a> Compare<&'a [u8]>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    preceded((peek(kame_pfx()), take(2usize)), u16(Endianness::Big))
}

fn kame_pfx<I, E>() -> impl Parser<I, Output = (), Error = E>
where
    I: nom::Input<Item = u8> + for<'a> Compare<&'a [u8]>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    alt((
        (tag(&[0xfe][..]), masked_u8(0xc0, 0x80)),
        (
            tag(&[0xff][..]),
            alt((masked_u8(0x0f, 0x01), masked_u8(0x0f, 0x02))),
        ),
    ))
    .map(|_| ())
}

fn masked_u8<I, E>(mask: u8, expected: u8) -> impl Parser<I, Output = (), Error = E>
where
    I: nom::Input<Item = u8>,
    E: ParseError<I> + FromExternalError<I, ()>,
{
    u8().map_res(move |x| {
        if x & mask == expected {
            Ok(())
        } else {
            Err(())
        }
    })
}

/// Link address.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkAddr {
    /// Name of this link.
    ///
    /// May be left empty.
    pub name: String,
    /// Index of this link.
    pub index: u16,
    /// Link type.
    ///
    /// According to [`<net/if_types.h>`], this is populated based on [RFC1573] and this
    /// [IANA numbers list].
    ///
    /// [`<net/if_types.h>`]: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_types.h
    /// [RFC1573]: https://datatracker.ietf.org/doc/html/rfc1573
    /// [IANA list]: https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-5
    pub ty: u8,
    /// Hardware address of this link.
    ///
    /// May be left empty. This is often done when the link addr is only populated to give the name,
    /// index, and type.
    pub addr: Vec<u8>,
}

impl Debug for LinkAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("LinkAddr");

        fmt.field("name", &self.name)
            .field("index", &self.index)
            .field("ty", &self.ty);

        if self.addr.is_empty() {
            fmt.field("addr", &format_args!("<empty>"));
        } else {
            use itertools::Itertools;

            #[allow(unstable_name_collisions)]
            let s = self
                .addr
                .iter()
                .map(|x| format!("{x:02x}"))
                .intersperse(":".to_string())
                .collect::<String>();

            fmt.field("addr", &format_args!("{s}"));
        }

        fmt.finish()
    }
}

/// Parse the body of a [`sockaddr_dl`][libc::sockaddr_dl].
///
/// Assumes that this is aligned with the start of the address block, i.e. `(sdl_len, sdl_family)`
/// are stripped, and all trailing padding is removed.
///
/// `sockaddr_dl` is laid out like this:
///
/// ```text
/// | index (2) | nlen (1) | alen (1) | slen (1) | name (nlen) | addr (alen) | selector (slen) |
/// ```
pub fn sockaddr_dl_body<I, E>() -> impl Parser<I, Output = LinkAddr, Error = E>
where
    I: nom::Input<Item = u8> + AsBytes,
    E: ParseError<I>,
{
    /// len = 0xff can mean "don't care"
    const fn alias_len(len: u8) -> u8 {
        if len == 0xff {
            return 0;
        }

        len
    }

    (
        u16(Endianness::Native),
        u8(),
        u8().map(alias_len),
        u8().map(alias_len),
        u8().map(alias_len),
    )
        .flat_map(|(index, ty, name_len, addr_len, selector_len)| {
            (
                take::<_, I, E>(name_len),
                take(addr_len),
                take(selector_len),
            )
                .map(move |(name, addr, selector)| {
                    let name = String::from_utf8_lossy(name.as_bytes());
                    let addr = addr.as_bytes().to_vec();

                    let sel = selector.as_bytes();
                    if !sel.is_empty() {
                        tracing::debug!("dropping nonempty link selector");
                    }

                    debug_assert!(sel.len() < ALIGN as _);

                    LinkAddr {
                        name: name.into_owned(),
                        ty,
                        addr,
                        index,
                    }
                })
        })
}

/// Produce a parser that populates an array of length `LEN` from the input.
///
/// The array is zeroed initially and is filled from the left; if there are fewer than `LEN` bytes
/// available, the array is not filled completely. This is not an error.
///
/// The second return parameter is the number of bytes actually read from the input.
fn take_array_zeroed<I, E, const LEN: usize>()
-> impl Parser<I, Output = ([u8; LEN], usize), Error = E>
where
    I: nom::Input<Item = u8> + AsBytes,
    E: ParseError<I>,
{
    rest_len.flat_map(|n| take(LEN.min(n))).map(|x: I| {
        let mut out = [0u8; LEN];

        let bs = x.as_bytes();
        out[..bs.len()].copy_from_slice(bs);

        (out, bs.len())
    })
}

#[cfg(test)]
mod test {
    use nom::multi::count;

    use super::*;

    type E<T> = nom::error::Error<T>;

    #[track_caller]
    fn assert_parse<'a, A>(
        sample: &'a [u8],
        mut parser: impl Parser<&'a [u8], Output = A, Error = E<&'a [u8]>>,
        expected: A,
    ) where
        A: PartialEq + Debug,
    {
        let (rest, addr) = parser.parse(sample).unwrap();
        assert_eq!(addr, expected);
        assert!(rest.is_empty());
    }

    #[test]
    fn unspec_chunk() {
        assert_parse(
            &[0, 0, 0, 0],
            partial_sockaddr(),
            Some(Address::Unspecified),
        );
    }

    #[test]
    fn ipv4() {
        assert_parse(
            &[224, 0, 0, 1],
            partial_inaddr(),
            Ipv4Addr::new(224, 0, 0, 1),
        );

        assert_parse(&[224, 0, 0], partial_inaddr(), Ipv4Addr::new(224, 0, 0, 0));
    }

    #[test]
    fn ipv4_padded() {
        assert_parse(
            &[0, 0, 224, 0, 0, 1],
            partial_sockaddr_in_body(),
            Ipv4Addr::new(224, 0, 0, 1),
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn ipv4_chunk() {
        assert_parse(
            &[16u8, 2, 0, 0, 224, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            partial_sockaddr(),
            Some(Address::Ipv4(Ipv4Addr::new(224, 0, 0, 1))),
        );
    }

    #[test]
    fn ipv6_full_with_scope() {
        assert_parse(
            &[
                0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
                0xa5, 0xa5, 0xa5, 0xa5,
            ],
            partial_in6addr(),
            ("1:203:405:607:809:a0b:c0d:e0f".parse().unwrap(), 0xa5a5a5a5),
        );
    }

    #[test]
    fn ipv6_full_no_scope() {
        assert_parse(
            &[
                0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
            ],
            partial_in6addr(),
            ("1:203:405:607:809:a0b:c0d:e0f".parse().unwrap(), 0),
        );
    }

    #[test]
    fn ipv6_partial() {
        assert_parse(
            &[0xab, 0x00],
            partial_in6addr(),
            ("ab00::".parse().unwrap(), 0),
        );

        assert_parse(&[], partial_in6addr(), (Ipv6Addr::UNSPECIFIED, 0));
    }

    #[test]
    fn ipv6_kame_scope() {
        assert_parse(
            &[0xff, 0x01, 0xab, 0xcd],
            partial_in6addr(),
            ("ff01::".parse().unwrap(), 0xabcd),
        );

        assert_parse(
            &[0xff, 0x02, 0xab, 0xcd],
            partial_in6addr(),
            ("ff02::".parse().unwrap(), 0xabcd),
        );

        assert_parse(
            &[0xfe, 0x80, 0xab, 0xcd],
            partial_in6addr(),
            ("fe80::".parse().unwrap(), 0xabcd),
        );

        // non-KAME encoding should not manipulate the address
        assert_parse(
            &[0xab, 0x80, 0xab, 0xcd],
            partial_in6addr(),
            ("ab80:abcd::".parse().unwrap(), 0x0),
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn ipv6_chunk() {
        // ff02::2:ffb2:bd7%24 (KAME scope encoding)
        assert_parse(
            &[
                28, 30, 0, 0, 0, 0, 0, 0, 255, 2, 0, 24, 0, 0, 0, 0, 0, 0, 0, 2, 255, 178, 11, 215,
                0, 0, 0, 0,
            ],
            partial_sockaddr(),
            Some(Address::Ipv6 {
                addr: "ff02::2:ffb2:bd7".parse().unwrap(),
                scope: 24,
            }),
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn prefix_v4only() {
        const PAYLOAD: &[u8] = &[
            0x10, 0x2, 0x0, 0x0, 0xe0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14,
            0x12, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x5, 0xff, 0xff, 0xff, 0xf0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0, 0x64, 0x40,
            0x0, 0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        assert_parse(
            PAYLOAD,
            count(partial_sockaddr(), 4),
            vec![
                Some(Address::Ipv4([224, 0, 0, 0].into())),
                Some(Address::Link(LinkAddr {
                    addr: vec![],
                    index: 23,
                    name: "".to_string(),
                    ty: 0,
                })),
                Some(Address::PrefixLen(PrefixLen {
                    v4: Some(4),
                    v6: None,
                })),
                Some(Address::Ipv4([100, 64, 0, 20].into())),
            ],
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn trailing_empty() {
        // This is an actual sample address payload captured from a PF_ROUTE socket.
        //
        // It's supposed to have RTA_NETMASK | RTA_IFP | RTA_IFA | RTA_BRD (4 entries), but it seems
        // that XNU will just omit the RTA_BRD address empty _completely_ if it's empty and is the
        // trailing address (so an AF_UNSPEC placeholder entry isn't strictly required for parsing
        // to succeed as it would in the middle of the sequence).
        //
        // You might think that this is a parsing bug and the 4 trailing bytes should be treated as
        // that placeholder, but the RTA_IFA address is preceded by 0x1c 0x1e, i.e. IPv6,
        // full-length. The scope bytes are unfilled because it uses the KAME embedding; there is no
        // placeholder at all. We can't have a sequencing issue otherwise – that last IPv6 can't be
        // the broadcast address, since IPv6 doesn't have them.
        const SAMPLE: &[u8] = &[
            0x1c, 0x1e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x12, 0x17,
            0x0, 0x1, 0x5, 0x0, 0x0, 0x75, 0x74, 0x75, 0x6e, 0x35, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x1c, 0x1e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x17, 0x0, 0x0, 0x0,
            0x0, 0x82, 0xa9, 0x97, 0xff, 0xfe, 0x19, 0xe7, 0x6f, 0x0, 0x0, 0x0, 0x0,
        ];

        let expected = vec![
            Some(Address::Ipv6 {
                addr: [0xffffu16, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0].into(),
                scope: 0,
            }),
            Some(Address::Link(LinkAddr {
                addr: vec![],
                index: 23,
                name: "utun5".to_string(),
                ty: 1,
            })),
            Some(Address::Ipv6 {
                addr: [0xfe80u16, 0, 0, 0, 0x82a9, 0x97ff, 0xfe19, 0xe76f].into(),
                scope: 23,
            }),
            // normally expected for RTA_BRD:
            // Some(Address::Unspecified),
        ];

        assert_parse(SAMPLE, count(partial_sockaddr(), expected.len()), expected);
    }
}
