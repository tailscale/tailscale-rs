#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

mod call_me_maybe;
mod endpoint;
mod error;
mod header;
mod message_type;
mod packet;
mod ping;
mod pong;

pub use call_me_maybe::CallMeMaybe;
pub use endpoint::Endpoint;
pub use error::Error;
pub use header::Header;
pub use message_type::MessageType;
pub use packet::Packet;
pub use ping::Ping;
pub use pong::Pong;

/// Common disco message functionality.
pub trait Message {
    /// The [`MessageType`] for this message.
    const TYPE: MessageType;
}

/// Report whether `buf` looks like a disco message.
pub fn is_disco_message(buf: &[u8]) -> bool {
    Header::from_bytes(buf).is_ok()
}

#[cfg(test)]
mod test {
    use core::{
        fmt::Debug,
        net::{Ipv6Addr, SocketAddrV6},
    };

    use ts_keys::{DiscoPrivateKey, NodePrivateKey};
    use zerocopy::IntoBytes;

    use super::*;

    fn rand_array<const N: usize>(mut rng: impl rand::Rng) -> [u8; N] {
        let mut array = [0u8; N];
        rng.fill_bytes(&mut array[..]);
        array
    }

    #[test]
    fn roundtrip_header() {
        let mut rng = rand::rng();

        let header = Header::new(rand_array(&mut rng).into(), rand_array(&mut rng));
        header.validate().unwrap();

        let mut out = alloc::vec::Vec::new();
        header.write_to_io(&mut out).unwrap();

        let (parsed, rest) = Header::from_bytes(out.as_slice()).unwrap();
        assert_eq!(parsed, &header);
        assert!(rest.is_empty());
    }

    fn roundtrip_msg<Msg>(size: usize, init: impl FnOnce(&mut Msg))
    where
        Msg: Message
            + ?Sized
            + zerocopy::Immutable
            + zerocopy::FromBytes
            + zerocopy::IntoBytes
            + zerocopy::KnownLayout,
        for<'a> &'a Msg: PartialEq + Debug,
    {
        let mut rng = rand::rng();

        let mut buf = alloc::vec![0; Packet::size_for_message(size)];
        let pkt = Packet::init_from_bytes::<Msg>(&mut buf, init).unwrap();

        let init = pkt.as_bytes().to_vec();
        let init = unsafe { Packet::from_bytes_unchecked(&init) }.unwrap();

        let sender_key = DiscoPrivateKey::random();
        let receiver_key = DiscoPrivateKey::random();
        let nonce = rand_array(&mut rng);

        let pkt = pkt
            .encrypt_in_place(&sender_key, &receiver_key.public_key(), nonce)
            .unwrap();

        let decrypted = pkt.decrypt_in_place(&receiver_key).unwrap();
        assert_eq!(decrypted.header().nonce, nonce);
        assert_eq!(decrypted.header().sender_pub, sender_key.public_key());
        assert_eq!(decrypted.ty(), Some(Msg::TYPE));

        let result = decrypted.as_msg::<Msg>().unwrap();
        assert_eq!(init.as_msg::<Msg>().unwrap(), result);
    }

    #[test]
    fn roundtrip_ping() {
        let mut rng = rand::rng();

        roundtrip_msg::<Ping>(Ping::size_with_padding(0), |ping| {
            ping.node_key = NodePrivateKey::random().public_key();
            ping.tx_id = rand_array(&mut rng);
        });
    }

    #[test]
    fn roundtrip_pong() {
        let mut rng = rand::rng();

        let payload = Pong {
            tx_id: rand_array(&mut rng),
            src: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 1, 0, 0).into(),
        };

        roundtrip_msg(Pong::size(), |pong| {
            *pong = payload;
        });
    }

    #[test]
    fn roundtrip_callmemaybe() {
        roundtrip_msg::<CallMeMaybe>(CallMeMaybe::size_for_endpoint_count(3), |cmm| {
            cmm.endpoints[0] = "[a:b::]:80".parse::<SocketAddrV6>().unwrap().into();
            cmm.endpoints[1] = "[b:c::]:8080".parse::<SocketAddrV6>().unwrap().into();
            cmm.endpoints[2] = "[c:d::]:1234".parse::<SocketAddrV6>().unwrap().into();
        });
    }
}
