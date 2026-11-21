//! Implementation of the Noise IKhfs+psk2 handshake pattern.

use std::marker::PhantomData;

use ml_kem::{
    B32, Kem, KeyExport, MlKem768, TryKeyInit,
    ml_kem_768::{DecapsulationKey, EncapsulationKey},
};
use ts_keys::X25519KeyPair;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    core::{
        Psk,
        Role::{Initiator, Responder},
        Session, State,
    },
    messages::{HybridInit, HybridResp, Pod},
};

const PROTOCOL: &[u8] = b"Noise_IKhfs+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";

/// A partially completed handshake, where the peer is the handshake's initiator.
pub struct ReceivedHandshake {
    state: State,
    peer_ephemeral_pub: x25519_dalek::PublicKey,
    peer_ephemeral_kem: EncapsulationKey,
    /// The peer's static identity.
    pub peer_static_pub: x25519_dalek::PublicKey,
}

impl ReceivedHandshake {
    /// Size of the packet expected by [`ReceivedHandshake::finish`].
    pub const RESP_SIZE: usize = size_of::<HybridResp>();

    /// Process an incoming handshake initiation packet.
    ///
    /// Returns a [`ReceivedHandshake`] and the decrypted handshake payload, or None
    /// if the handshake message is invalid in some way.
    pub fn new<'packet, P: Pod>(
        packet: &'packet mut [u8],
        prologue: &[u8],
        my_static: X25519KeyPair,
    ) -> Option<(Self, &'packet mut P)> {
        let packet: &mut HybridInit<P> = HybridInit::mut_from_bytes(packet).ok()?;

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);

        let handshake = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(my_static.public.as_ref()) // <- s ...
            .mix_hash_and_key(&peer_ephemeral_pub) // -> e
            .mix_dh(&my_static.private, &peer_ephemeral_pub) // es
            .open(
                packet.ephemeral_kem.as_mut_bytes(),
                &packet.ephemeral_kem_tag,
            )?
            .open(&mut packet.static_pub, &packet.static_pub_tag)? // s
            .mix_dh(&my_static.private, &packet.static_pub.into()) // ss
            .open(packet.payload.as_mut_bytes(), &packet.payload_tag)?; // payload

        let peer_ephemeral_kem = EncapsulationKey::new_from_slice(&packet.ephemeral_kem).ok()?;

        Some((
            ReceivedHandshake {
                state: handshake,
                peer_ephemeral_pub,
                peer_ephemeral_kem,
                peer_static_pub: packet.static_pub.into(),
            },
            &mut packet.payload,
        ))
    }

    /// Finalize the handshake and generate a response.
    ///
    /// The response is written to `packet`, which must be exactly
    /// [`ReceivedHandshake::RESP_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// If `packet` is the wrong size.
    pub fn finish(self, psk: &Psk, out: &mut [u8]) -> Session {
        let ephemeral = X25519KeyPair::random();
        self.finish_with_ephemeral(psk, ephemeral, None, out)
    }

    fn finish_with_ephemeral(
        self,
        psk: &Psk,
        my_ephemeral: X25519KeyPair,
        kem_m: Option<B32>,
        out: &mut [u8],
    ) -> Session {
        assert_eq!(out.len(), Self::RESP_SIZE);
        let response = HybridResp::mut_from_bytes(out).unwrap();

        response.ephemeral_pub = my_ephemeral.public.to_bytes();

        self.state
            .mix_hash_and_key(&my_ephemeral.public) // <- e
            .mix_dh(&my_ephemeral.private, &self.peer_ephemeral_pub) // ee
            .encaps_kem(
                self.peer_ephemeral_kem,
                kem_m,
                &mut response.ephemeral_kem_ciphertext,
                &mut response.ephemeral_kem_tag,
            )
            .mix_dh(&my_ephemeral.private, &self.peer_static_pub) // se
            .mix_psk(psk) // psk
            .seal(&mut [], &mut response.auth_tag) // payload
            .finish(Responder)
    }
}

/// A partially completed handshake, where the peer is the handshake's responder.
pub struct SentHandshake<P: Pod> {
    state: State,
    my_ephemeral: x25519_dalek::StaticSecret,
    my_kem: DecapsulationKey,
    _phantom: PhantomData<P>,
}

impl<P: Pod> SentHandshake<P> {
    /// Size of the output packet to be provided to [`SentHandshake::new`].
    pub const INIT_SIZE: usize = size_of::<HybridInit<P>>();

    /// Generate an outgoing handshake initiation for the given peer identity.
    ///
    /// # Panics
    ///
    /// If `packet` is not [`SentHandshake::INIT_SIZE`] bytes.
    pub fn new(
        my_static: X25519KeyPair,
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        payload: P,
        out: &mut [u8],
    ) -> Self {
        let ephemeral = X25519KeyPair::random();
        let kem = MlKem768::generate_keypair();
        Self::new_with_ephemeral(
            my_static,
            ephemeral,
            kem,
            peer_static,
            prologue,
            payload,
            out,
        )
    }

    fn new_with_ephemeral(
        my_static: X25519KeyPair,
        my_ephemeral: X25519KeyPair,
        my_kem: (DecapsulationKey, EncapsulationKey),
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        payload: P,
        out: &mut [u8],
    ) -> Self {
        assert_eq!(out.len(), Self::INIT_SIZE);
        let out: &mut HybridInit<P> = HybridInit::mut_from_bytes(out).unwrap();

        out.ephemeral_pub = my_ephemeral.public.to_bytes();
        out.ephemeral_kem = my_kem.1.to_bytes().into();
        out.static_pub = my_static.public.to_bytes();
        out.payload = payload;

        let state = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(peer_static.as_ref()) // <- s
            .mix_hash_and_key(&my_ephemeral.public) // -> e
            .mix_dh(&my_ephemeral.private, &peer_static) // es
            .seal(&mut out.ephemeral_kem, &mut out.ephemeral_kem_tag)
            .seal(&mut out.static_pub, &mut out.static_pub_tag) // s
            .mix_dh(&my_static.private, &peer_static) // ss
            .seal(out.payload.as_mut_bytes(), &mut out.payload_tag); // payload

        SentHandshake {
            state,
            my_ephemeral: my_ephemeral.private,
            my_kem: my_kem.0,
            _phantom: PhantomData,
        }
    }

    /// Try to finalize the handshake and generate a response.
    ///
    /// If successful, consumes `self` and returns keys for the new session.
    /// If the response is invalid, returns `Err(self)` to allow for another finalization
    /// attempt later.
    pub fn try_finish(
        self,
        packet: &mut [u8],
        my_static: X25519KeyPair,
        psk: &Psk,
    ) -> Result<Session, Self> {
        let Ok(packet) = HybridResp::mut_from_bytes(packet) else {
            return Err(self);
        };

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let state = self.state.clone();

        let ret = match state
            .mix_hash_and_key(&peer_ephemeral_pub) // e
            .mix_dh(&self.my_ephemeral, &peer_ephemeral_pub) // ee
            .decaps_kem(
                // ekem1
                &self.my_kem,
                &mut packet.ephemeral_kem_ciphertext,
                &packet.ephemeral_kem_tag,
            ) {
            Some(state) => state,
            None => return Err(self),
        };

        let ret = ret
            .mix_dh(&my_static.private, &peer_ephemeral_pub) // se
            .mix_psk(psk) // psk
            .open(&mut [], &packet.auth_tag)
            .ok_or(self)?
            .finish(Initiator);

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use itertools::Itertools;
    use ml_kem::{Generate, Seed};
    use zerocopy::IntoByteSlice;

    use super::*;

    fn test_key(r: Range<u8>) -> X25519KeyPair {
        assert_eq!(r.len(), 32);
        let private = x25519_dalek::StaticSecret::from(r.collect_array().unwrap());
        let public = x25519_dalek::PublicKey::from(&private);
        X25519KeyPair { private, public }
    }

    fn test_kem(r: Range<u8>) -> (DecapsulationKey, EncapsulationKey) {
        assert_eq!(r.len(), 64);
        let seed = Seed::from(r.collect_array().unwrap());
        let decap = DecapsulationKey::from_seed(seed);
        let encap = decap.encapsulation_key().to_owned();
        (decap, encap)
    }

    #[test]
    fn test_handshake() {
        let init_static = test_key(0..32);
        let init_ephemeral = test_key(32..64);
        let init_kem = test_kem(0..64);

        let resp_static = test_key(64..96);
        let resp_ephemeral = test_key(96..128);
        let resp_kem_entropy: [u8; 32] = (0..32).collect_array().unwrap();

        let psk: Psk = (128..160).collect_array().unwrap();

        const PROLOGUE: &[u8] = b"TEST HANDSHAKE";
        const PAYLOAD: &[u8; 12] = b"TEST PAYLOAD";

        // Unfortunately nobody else uses ikhfs+psk2, so we have no outside test vectors to
        // compare against. These are packets generated with this implementation, and are here
        // as a regression test for future changes.
        let expected_init_packet = hex::decode("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254ddfd655294412e3199d8d84adebf8ee9d4565b4aaabe7bac08251d06a1da5019f75905c12a0067449895b736a3f46d0f4d82b9dfed465209ac627309833aa78ba22a69cd7c1f21e25e47fe46334f683e9710b2bf24abf1183d0ce6e37ff998d0e5c503b0e3e75f87c9378082c340c65044754b0e5c2e07917388bfc0f6a5e51f08e8e25985f510f0354f48fb6dda58392b9b871b5ddc916c7f81063d8fe12577c6febcc5c51228d4b0da56d3c21e9316dde55f8ac9f83ee234a868043f3f5c18498fe261a7a54bf51ce20f8bbaa16c40ea36599cb9860ade8f057834180562d122f3a84fce6404cde8afce0ea38d52053c5cd978771352c8387bf830636ec2d1b217180d58b30985545cee96e1e58d092fff5ed8f7a16cb7a62cd51f7b0443360737d1fa9038d058a6b768daaf4ee6fa79861b0f07ada9c1930ace681d28b99dc47da776093a3675f2a5f534a77d6271269c15f37346acb400c54f6e045fffb28f55a425719613164af8ce0a7b6920de085b849b53233b8a9c890147065a8e51f3fdc52274285d784c45e0877ecff86915dea65a1c9ac01cf18f012c85147e92c2d7d2a92b23a1a8425cf23a623cd1be59defd275371bfd0e8516f981324d7ec6166d7cb0f6a7f3f667db80fbd855c717c16cfb57fe7d6f1981d24124b4d7df2efaaea05762a291df92647dd704667f88b306371d0e75c9bb261cebc4e459546c25cd5f5f04e2010ec6bcf2da88e5043118f0b68d2fff793c67bfd91f0f19c0faff5e1285f0349594aed8329a8b7b53d98fc8140bf25a497b441d5edc18783ff7f2386a1ff61f40751bf7f09d6d57620175177306b34f6de274d69e2ca884076139f2d199afb92f0ed523620dfef4062f425f8820bda90676db669d43e92dc3866fe60ba0fd349e7f7441281e73d1061a3554055bc088ac3963e68fe3672f5abdec78133bc3ae09b152fee31ea968cd0b7c7ce0fe1da4a4238b9b788b2b7d96ee6eba82c867334f3a999713597dc3a1d7647207de9b3e8edcf5de30026347fb628a7db16734bdd75d756d1053cc1bfd3c52cb724bf5b6aa2fb2742689ed8c25aadc5d1f6d61699b3d5651874953f5970453947ac925b129e4771841ed302e9792a42182f5e2d238ad6b841249c2831673bda67542e82dc9500cb5eede95fe0c70dde6cb9e50a021128d09505f4a6daf1a693425fa9e6d0e49965d6fa67fe7119302f3e2118d154c2e4661da958a867fba67c8e66c3366dbfa15ce949cab2ea7392325e3233f2c88d9e340dca1eecf2f92ae4c20f21fbe57a9b8fb771b2721587e7c8ef7c3dc98504abc24dde134b723b8ee92b28dba8aca8a02517ad4373eee8c7de329e034c63fa7bf8d8d65f20fedf86a72c8f84beb7400ab3089a171dc8d33fc48d4fce6ffa295c60079ee94bd77e021f2dc02f4796bc909e9b8131c3de2e620ceefdb18be7f41751805e42ec8d004a447389327d93da009e90e782d9cb0e1764d94a54fe80509847b9c96072f71275d023747d3527eda203dc9458a39a7677117497b390fee34f9c65861ea1ae7ab5c7fb728ff619ad8f110478209e6f35b002eb9fb89b077bbdee540c159043401808da4c0878a6a9e28331dfd48cc1f077f74bb24a087db38346a0d1d4d0f415a4b5b8943b651ecf55d3b8598ac824b1c9edb2f253e1d71d4ac1cea17c6a5e24346aae1a4753efd973c0d46bea50a8c7b2c6e6be3bdf755925f1e297d7320c208c00aefe91a80c340fb1e01445d3238dcd5092fc4fd16d0b2096a7f282258efc4a15f80fd4e2196d0238a6ca").unwrap();
        let expected_resp_packet = hex::decode("675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f55a58dd12e96a82fc36d7abb613cc601d40956995884eeae9483f7a0d47b3dc77a1e94f8449f79bc0bc0c2ec577f8f6b23734ebe1a06030eeef5efe67c01ca53326ecffd6982406985495e1cb5ab5ebfc0eb25b94fdcb51d97e7693066bc5dde607a2c95588e7d4f326667166e7e93e956eb72323a33744e2a541c55e3a719325f1b81141f31275d3bd50f6f7e585cc046c0ba44564c514a6875c3a3b15c819e8e97a88cb0c0299fc2b256b4fe7003ce8336a63c59f92a31ade6749cf15c782966199370fa7c9a45e03d55928e316b22455de5edf85aad71a20c9c0483b555a520d9ba0c108e4bf53418a3835ef888680285429e9d37696613bd079103483b892496fd99af32dd285903e31cc0731226eb038378b99fbae6484b417d16bd01838d60a6a0da596461e075e780887080cee87eba06e518d46a1d0f3d68a7ba992a23f425a90a085c07c705d54f7262f5985746297002a9a08a9312485b65a30e9590520b7e5bffcf813b7d8522d13534c55dae33bb9c93a5ecbecc3a47bf7b1d71eed9e9855810cad5e0ad046dae58fec49cc2a2d156a1377f5a26656b1f9c2eccd728dda2501fdcc0e57190d5c3e5ef2bd6316b06d8afc54f976f688149724d19017cea72a37f634e3a5b6cc9ba52a17464fd7e2bcfa9574655ba63125c01149701b81427facb32ae0702050d82993fabe08cd467671eecdbf3ab051237bd2ee70839bb3f5cf5bfb6e5e4776bc7c9b9ead82c4fe9e4d669c42d058b418bcc5ae547556ca823cee14418724072656a979844df9f7dc8acecf1d7680ae21a56eb9b7d9a6ae82131e3514462cbf441fb200a8ada422a3394438f5b29b4209efcac9108e6b259a4d2fa718af191b23585cb3d10faca537dfd62e8964daf596f3bacabb29e2d12d2b2c935c984acaef341c5a14dc430ae61235a1baada5f4454fcd5a7b07b75b53ea84b79aecae827b36c48cb6eb0594b45a2873d8e00d2c0e58eeebda23a70541d9556abf7cc9d47b122043b5f0116abbf68bec4b14dae188d6d9603c75eee652e905258cb15265cd7fa5853e32b26f202d424fa59ac34da543305a6bff2469a1876ed0bc3a56947cb6837df501731085ba7754ee3431200c14e8b98769f42f8e8499595eda9ea973e0d520f738dc049bee7b805a4751f65760c31c4809c6de71a5436b1f06587ef3a8e1370d6c6e30a2e946161c3d578ac8ee1b67d30290cb59cb0011efc43c0c55b63a388ebd37a41b6e9cda4f01def216f2532178c910bd832f21c0b7cd97f3c9fb08ed86c000bc2be7444d4efca3e97c7efe27d7436f2af68f9ab86504807c10feb04c629945d5aaae348431d9f38342cd864d72b4425542cf7a2af4c126b3c60a8eeced81ef6fcb215187568493f4c8d3b69175a1e77c4813c62a549b4efac67abdd7070aeee33f50939f5425d644fa42043015eed96c61d35ff0020b98a13fe311c67b9b531a01dd3ddbb3b1d19841684f742158f4c8a3e25e011f31574756a0c68ad53884fa30c90848ecef820f9404fb1f248a23976050e077ce8be24ef7888362fe6496f6b8bffb6ee847c1c1c056dd365").unwrap();

        let mut init_packet = [0; SentHandshake::<[u8; 12]>::INIT_SIZE];
        let init_sent = SentHandshake::<[u8; 12]>::new_with_ephemeral(
            init_static.clone(),
            init_ephemeral,
            init_kem,
            resp_static.public,
            PROLOGUE,
            *PAYLOAD,
            &mut init_packet,
        );
        assert_eq!(init_packet, expected_init_packet.as_ref());

        let (resp_recv, resp_payload) =
            ReceivedHandshake::new::<[u8; 12]>(&mut init_packet, PROLOGUE, resp_static).unwrap();
        assert_eq!(resp_recv.peer_static_pub, init_static.public);
        assert_eq!(resp_payload, PAYLOAD);

        let mut resp_packet = [0; ReceivedHandshake::RESP_SIZE];
        let resp_session = resp_recv.finish_with_ephemeral(
            &psk,
            resp_ephemeral,
            Some(resp_kem_entropy.into()),
            &mut resp_packet,
        );
        assert_eq!(resp_packet, expected_resp_packet.as_ref());

        let Ok(init_session) = init_sent.try_finish(&mut resp_packet, init_static, &psk) else {
            panic!("initiator failed to finalize handshake");
        };

        assert_eq!(
            init_session.initiator_to_responder,
            resp_session.initiator_to_responder
        );
        assert_eq!(
            init_session.responder_to_initiator,
            resp_session.responder_to_initiator
        );
        assert_eq!(init_session.role, Initiator);
        assert_eq!(resp_session.role, Responder);
    }
}
