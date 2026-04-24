use core::fmt::Formatter;

use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, network_endian::U16};

use crate::Error;

/// The fixed length of an [`InitiationMessage`] payload, in bytes.
pub(crate) const INITIATION_PAYLOAD_LEN: usize = 96;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) enum ControlMessageType {
    Initiation = 0x1,
    Response = 0x2,
    #[allow(dead_code)]
    // TODO (dylan): investigate when errors can happen, handle them
    Error = 0x3,
    Record = 0x4,
}

#[derive(Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct ControlMessageHeader {
    pub typ: ControlMessageType,
    pub len: U16,
}

impl ControlMessageHeader {
    pub fn len(&self) -> usize {
        self.len.get() as usize
    }

    pub(crate) fn try_parse(buf: &[u8]) -> Result<&Self, Error> {
        Ok(ControlMessageHeader::try_ref_from_bytes(buf)?)
    }
}

#[repr(C)]
#[derive(IntoBytes, KnownLayout, Immutable)]
pub(crate) struct InitiationMessage {
    capability_version: U16,
    hdr: ControlMessageHeader,
    payload: [u8; INITIATION_PAYLOAD_LEN],
}

impl InitiationMessage {
    pub fn new(
        capability_version: u16,
        overhead_len: u16,
        payload: [u8; INITIATION_PAYLOAD_LEN],
    ) -> Self {
        Self {
            capability_version: capability_version.into(),
            hdr: ControlMessageHeader {
                typ: ControlMessageType::Initiation,
                len: overhead_len.into(),
            },
            payload,
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct ResponseMessage {
    pub hdr: ControlMessageHeader,
    pub data: [u8],
}

impl core::fmt::Debug for ResponseMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(core::any::type_name::<ResponseMessage>())
            .field("hdr", &self.hdr)
            .field("data", &&self.data as &dyn core::fmt::Debug)
            .finish()
    }
}

impl ResponseMessage {
    pub(crate) fn try_parse(buf: &[u8]) -> Result<&Self, Error> {
        let resp = ResponseMessage::try_ref_from_bytes(buf)?;

        if resp.hdr.typ != ControlMessageType::Response {
            return Err(Error::BadFormat);
        }
        Ok(resp)
    }
}

/// An error message sent from the control plane to the local node, indicating something went wrong
/// during the initial control handshake.
///
/// Use the [`ErrorMessage::message`] method to determine the exact error.
#[repr(C)]
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct ErrorMessage {
    pub hdr: ControlMessageHeader,
    msg: [u8],
}

#[allow(dead_code)]
impl ErrorMessage {
    /// Try to parse the given byte slice into an [`ErrorMessage`]; otherwise, return an error.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<&Self, Error> {
        let resp = ErrorMessage::try_ref_from_bytes(buf)?;
        if resp.hdr.typ != ControlMessageType::Error {
            return Err(Error::BadFormat);
        }
        Ok(resp)
    }

    /// Try to parse the [`ErrorMessage::msg`] field into a `&str` and return it; otherwise, return
    /// an error.
    pub fn message(&self) -> Result<&str, Error> {
        core::str::from_utf8(&self.msg).map_err(From::from)
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct RecordMessage {
    pub hdr: ControlMessageHeader,
    pub data: [u8],
}

impl RecordMessage {
    pub fn new_in(buf: &mut [u8], len: usize) -> Result<&mut Self, Error> {
        let len_be = U16::new(len as u16);
        let hdr = ControlMessageHeader {
            typ: ControlMessageType::Record,
            len: len_be,
        };
        hdr.write_to_prefix(buf)?;
        Ok(Self::try_mut_from_bytes(buf)?)
    }
}
