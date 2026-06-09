use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use aead::{AeadInPlace, generic_array::GenericArray};
use crypto_box::Tag;
use ts_keys::{DiscoPrivateKey, DiscoPublicKey};
use zerocopy::{FromBytes, IntoBytes, KnownLayout, TryFromBytes};

use crate::{Error, Header, Message, message_type::MessageType};

/// Marker type indicating that a [`Packet`] is in an encrypted state.
pub enum Encrypted {}

/// Payload of a plaintext [`Packet`].
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Plaintext {
    ty: u8,
    version: u8,
    message: [u8],
}

impl Plaintext {
    const VERSION: u8 = 0;

    fn ty(&self) -> Option<MessageType> {
        self.ty.try_into().ok()
    }

    const fn size_for_message(payload_size: usize) -> usize {
        2 + payload_size
    }
}

#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct AeadTaggedPayload {
    tag: [u8; 16],
    payload: [u8],
}

impl AeadTaggedPayload {
    pub const fn size_for_payload(payload_size: usize) -> usize {
        16 + payload_size
    }
}

/// A disco packet that may hold an encrypted or plaintext payload.
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Packet<CryptState: ?Sized> {
    phantom: PhantomData<CryptState>,
    header: Header,
    payload: AeadTaggedPayload,
}

impl Debug for Packet<Encrypted> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Packet<Encrypted>")
            .field("header", &self.header)
            .field("aead_tag", &self.payload.tag)
            .field(
                "payload",
                &format_args!("<encrypted> (len={})", self.payload.payload.len()),
            )
            .finish()
    }
}

macro_rules! fmt_pkt {
    ($fmt:expr, $self:expr, $($knownty:ident),*) => {
        match $self.ty() {
            $(
                Some(MessageType::$knownty) => match $self.as_msg::<crate::$knownty>() {
                    Some(x) => ($fmt).field("payload", &x),
                    None => ($fmt).field("payload", &concat!("<invalid ", stringify!($knownty), ">")),
                },
            )*

            // Rest: message types not implemented yet (UDP relay, at the moment)
            Some(no_msgty) => ($fmt)
                .field("payload", &"<unimplemented>")
                .field("ty", &no_msgty),

            None => ($fmt).field("payload", &"<unknown>").field("ty", &$self.ty_raw()),
        }
    }
}

impl Debug for Packet<Plaintext> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("Packet<Plaintext>");

        let d = d
            .field("header", &self.header)
            .field("aead_tag", &self.payload.tag);

        fmt_pkt!(d, self, Ping, Pong, CallMeMaybe).finish()
    }
}

impl<CryptState> Packet<CryptState>
where
    CryptState: ?Sized,
{
    /// Get a ref to the header contained in the packet.
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Get a ref to the sender's [`DiscoPublicKey`].
    pub const fn sender_pubkey(&self) -> &DiscoPublicKey {
        &self.header.sender_pub
    }
}

impl Packet<Plaintext> {
    /// Initialize a plaintext packet in the given byte slice `b`. The `init_msg` closure
    /// is used to set the message data.
    ///
    /// The byte slice must be sized exactly: use [`Packet::size_for_message`] to calculate
    /// this.
    ///
    /// This does not set the header: this is set at encryption time (in
    /// [`Packet::encrypt_in_place`]).
    pub fn init_from_bytes<Msg>(
        b: &mut [u8],
        init_msg: impl FnOnce(&mut Msg),
    ) -> Result<&mut Self, Error>
    where
        Msg: ?Sized + Message + zerocopy::Immutable + TryFromBytes + IntoBytes + KnownLayout,
    {
        let s = Self::try_mut_from_bytes(b)?;

        let pt = Plaintext::mut_from_bytes(&mut s.payload.payload)?;
        pt.ty = Msg::TYPE as _;
        pt.version = 0;

        let msg = Msg::try_mut_from_bytes(&mut pt.message)?;
        init_msg(msg);

        s.validate()?;

        Ok(s)
    }

    /// Cast the slice to a plaintext packet.
    ///
    /// # Safety
    ///
    /// This operation is safe but may be semantically unsound. Specifically, the type
    /// and version fields are not set and may disagree with the payload.
    pub unsafe fn from_bytes_unchecked(b: &[u8]) -> Result<&Self, Error> {
        Self::try_ref_from_bytes(b).map_err(From::from)
    }

    /// Cast the slice to a mutable plaintext packet.
    ///
    /// # Safety
    ///
    /// Like [`Packet::from_bytes_unchecked`], this operation is safe but may be
    /// semantically unsound.
    pub unsafe fn from_bytes_unchecked_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        Self::try_mut_from_bytes(b).map_err(From::from)
    }

    /// Encrypt this packet, converting it to a [`Packet<Encrypted>`].
    pub fn encrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        nonce: [u8; Header::NONCE_LEN],
    ) -> Result<&mut Packet<Encrypted>, Error> {
        let bx = crypto_box::SalsaBox::new(&receiver.into(), &secret.into());

        self.header = Header::new(secret.public_key(), nonce);

        let tag = bx
            .encrypt_in_place_detached(&GenericArray::from(nonce), &[], &mut self.payload.payload)
            .map_err(|_e| Error::CryptoFailed)?;

        self.payload.tag.copy_from_slice(tag.as_ref());

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;

        Ok(ret)
    }

    /// Report the type of the message stored in this packet, if it is recognized.
    pub fn ty(&self) -> Option<MessageType> {
        self.plaintext()?.ty()
    }

    /// Return the type byte for this packet, if the plaintext body is parseable.
    pub fn ty_raw(&self) -> Option<u8> {
        Some(self.plaintext()?.ty)
    }

    /// Return the version byte for this packet, if the body was parseable.
    pub fn version(&self) -> Option<u8> {
        Some(self.plaintext()?.version)
    }

    /// Convert the payload of this packet to the given message type.
    ///
    /// Fails if the body could not be parsed or the type field doesn't match.
    pub fn as_msg<T>(&self) -> Option<&T>
    where
        T: ?Sized + Message + zerocopy::Immutable + zerocopy::KnownLayout + zerocopy::FromBytes,
    {
        let pt = self.plaintext()?;

        if pt.ty() != Some(T::TYPE) {
            return None;
        }

        T::ref_from_bytes(&pt.message).ok()
    }

    /// Convert the payload of this packet to a mutable reference to the given message type.
    ///
    /// Fails if the body could not be parsed or the type field doesn't match.
    pub fn as_msg_mut<T>(&mut self) -> Option<&mut T>
    where
        T: ?Sized
            + Message
            + zerocopy::Immutable
            + zerocopy::KnownLayout
            + zerocopy::FromBytes
            + zerocopy::IntoBytes,
    {
        let pt = self.plaintext_mut()?;

        if pt.ty() != Some(T::TYPE) {
            return None;
        }

        T::mut_from_bytes(&mut pt.message).ok()
    }

    /// Calculate the size of the buffer required to store a packet with a message payload
    /// of the given size.
    pub const fn size_for_message(message_size: usize) -> usize {
        size_of::<Header>()
            + AeadTaggedPayload::size_for_payload(Plaintext::size_for_message(message_size))
    }

    /// Allocate a [`Vec`][alloc::vec::Vec] to store a packet of the given size.
    #[cfg(feature = "alloc")]
    pub fn vec_for_message(message_size: usize) -> alloc::vec::Vec<u8> {
        alloc::vec![0; Self::size_for_message(message_size)]
    }

    /// Allocate a [`Box`][alloc::boxed::Box]ed slice to store a packet of the given size.
    #[cfg(feature = "alloc")]
    pub fn box_for_message(message_size: usize) -> alloc::boxed::Box<[u8]> {
        Self::vec_for_message(message_size).into_boxed_slice()
    }

    /// Check that this is a valid packet: the inner plaintext is the right size and has
    /// a known version.
    ///
    /// Unknown message types do not fail validation.
    pub fn validate(&self) -> Result<(), Error> {
        let pt = Plaintext::ref_from_bytes(&self.payload.payload)?;

        if pt.version != Plaintext::VERSION {
            return Err(Error::UnknownVersion);
        }

        Ok(())
    }

    fn plaintext(&self) -> Option<&Plaintext> {
        Plaintext::ref_from_bytes(&self.payload.payload).ok()
    }

    fn plaintext_mut(&mut self) -> Option<&mut Plaintext> {
        Plaintext::mut_from_bytes(&mut self.payload.payload).ok()
    }
}

impl Packet<Encrypted> {
    /// Try to cast the given bytes to an encrypted packet.
    ///
    /// Fails if the format is invalid or the header magic bytes were incorrect.
    pub fn from_encrypted_bytes(b: &[u8]) -> Result<&Self, Error> {
        let slf = Self::try_ref_from_bytes(b)?;
        slf.header.validate()?;

        Ok(slf)
    }

    /// Try to cast the given bytes to a mutable encrypted packet.
    ///
    /// Fails if the format is invalid or the header magic bytes were incorrect.
    pub fn from_encrypted_bytes_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        let slf = Self::try_mut_from_bytes(b)?;
        slf.header.validate()?;

        Ok(slf)
    }

    /// Get a reference to the payload bytes.
    pub const fn payload_bytes(&self) -> &[u8] {
        &self.payload.payload
    }

    /// Decrypt this packet, turning it into a [`Packet<Plaintext>`].
    pub fn decrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
    ) -> Result<&mut Packet<Plaintext>, Error> {
        crypto_box::SalsaBox::new(&self.header.sender_pub.into(), &secret.into())
            .decrypt_in_place_detached(
                &self.header.nonce.into(),
                &[],
                &mut self.payload.payload,
                Tag::from_slice(&self.payload.tag),
            )
            .map_err(|_e| Error::CryptoFailed)?;

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;
        ret.validate()?;

        Ok(ret)
    }
}
