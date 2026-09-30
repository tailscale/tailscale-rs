use nom::{AsBytes, IResult};
use zerocopy::TryFromBytes;

use crate::bsd::net_table::{
    Addrs, Flags, Header, Interface, Interface2, InterfaceAddr, MessageType, MulticastAddr,
    MulticastAddr2, Route, Route2,
};

/// Utility enum covering all `PF_ROUTE` message header variants.
///
/// Note that many [`MessageType`]s map to the same [`MessageHeader`] variants: the type indicates
/// the semantics, while [`MessageHeader`] discriminates on the actual structural encoding of the
/// message header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageHeader<'a> {
    /// This is a [`Route2`] message.
    Route2(&'a Route2),
    /// This is a [`Route`] message.
    Route(&'a Route),
    /// This is an [`Interface2`] message.
    Interface2(&'a Interface2),
    /// This is an [`Interface`] message.
    Interface(&'a Interface),
    /// This is an [`InterfaceAddr`] message.
    InterfaceAddr(&'a InterfaceAddr),
    /// This is a [`MulticastAddr2`] message.
    MulticastAddr2(&'a MulticastAddr2),
    /// This is a [`MulticastAddr`] message.
    MulticastAddr(&'a MulticastAddr),
}

impl<'a> MessageHeader<'a> {
    /// Parse a message header from the input according to the indicated type byte.
    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], (MessageType, Self)> {
        let (header, _rest) =
            Header::try_ref_from_prefix(input.as_bytes()).map_err(nom_cast_err)?;

        let (hdr, rest) = match header.ty {
            MessageType::Get2 => Route2::try_ref_from_prefix(input.as_bytes())
                .map(|(r2, rest)| (MessageHeader::Route2(r2), rest))
                .map_err(nom_cast_err),

            MessageType::IfInfo2 => Interface2::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Interface2(r), rest))
                .map_err(nom_cast_err),

            MessageType::Get
            | MessageType::Add
            | MessageType::Delete
            | MessageType::Change
            | MessageType::Lock
            | MessageType::Losing
            | MessageType::Miss
            | MessageType::Resolve
            | MessageType::Redirect => Route::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Route(r), rest))
                .map_err(nom_cast_err),

            MessageType::IfInfo => Interface::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Interface(r), rest))
                .map_err(nom_cast_err),
            MessageType::NewAddr | MessageType::DelAddr => {
                InterfaceAddr::try_ref_from_prefix(input.as_bytes())
                    .map(|(r, rest)| (MessageHeader::InterfaceAddr(r), rest))
                    .map_err(nom_cast_err)
            }
            MessageType::NewMaddr | MessageType::DelMaddr => {
                MulticastAddr::try_ref_from_prefix(input.as_bytes())
                    .map(|(r, rest)| (MessageHeader::MulticastAddr(r), rest))
                    .map_err(nom_cast_err)
            }
            MessageType::NewMaddr2 => MulticastAddr2::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::MulticastAddr2(r), rest))
                .map_err(nom_cast_err),
        }?;

        let diff = input.len() - rest.len();
        let rest = &input[diff..];

        Ok((rest, (header.ty, hdr)))
    }

    /// Get the message header.
    pub const fn header(&self) -> Header {
        match self {
            Self::Route2(r) => r.header,
            Self::Route(r) => r.header,
            Self::Interface2(i) => i.header,
            Self::Interface(i) => i.header,
            Self::InterfaceAddr(i) => i.header,
            Self::MulticastAddr(i) => i.header,
            Self::MulticastAddr2(i) => i.header,
        }
    }

    /// Get the address flags for the contained message.
    pub const fn addrs(&self) -> Addrs {
        match self {
            Self::Route2(r) => r.flag_block.addrs(),
            Self::Route(r) => r.flag_block.addrs(),
            Self::Interface2(i) => i.flag_block.addrs(),
            Self::Interface(i) => i.flag_block.addrs(),
            Self::InterfaceAddr(i) => i.flag_block.addrs(),
            Self::MulticastAddr(i) => i.flag_block.addrs(),
            Self::MulticastAddr2(i) => i.flag_block.addrs(),
        }
    }

    /// Get the flags for the contained message.
    pub const fn flags(&self) -> Flags {
        match self {
            Self::Route2(r) => r.flag_block.flags(),
            Self::Route(r) => r.flag_block.flags(),
            Self::Interface2(i) => i.flag_block.flags(),
            Self::Interface(i) => i.flag_block.flags(),
            Self::InterfaceAddr(i) => i.flag_block.flags(),
            Self::MulticastAddr(i) => i.flag_block.flags(),
            Self::MulticastAddr2(i) => i.flag_block.flags(),
        }
    }
}

fn nom_cast_err<D>(e: zerocopy::TryCastError<&[u8], D>) -> nom::Err<nom::error::Error<&[u8]>>
where
    D: ?Sized + TryFromBytes,
{
    nom::Err::Error(nom::error::Error::new(
        e.into_src(),
        nom::error::ErrorKind::MapRes,
    ))
}
