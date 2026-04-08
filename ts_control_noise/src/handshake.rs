use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::BufMut;
use noise_protocol::{HandshakeState, HandshakeStateBuilder, patterns::noise_ik};
use noise_rust_crypto::{Blake2s, X25519, sensitive::Sensitive};
use tokio::io::{AsyncRead, AsyncReadExt};
use ts_hexdump::{AsHexExt, Case};
use ts_keys::{MachinePrivateKey, MachinePublicKey};
use ts_packet::PacketMut;
use zerocopy::IntoBytes;
use zeroize::Zeroizing;

use crate::{
    Error, NoiseIo,
    messages::{ControlMessageHeader, INITIATION_PAYLOAD_LEN, InitiationMessage, ResponseMessage},
};

/// Noise handshake state.
pub struct Handshake {
    state: HandshakeState<X25519, crate::ChaCha20Poly1305BigEndian, Blake2s>,
}

impl Handshake {
    /// Create a new handshake with the given `prologue` and using the specified keys.
    ///
    /// `capability_version` is used to indicate our capabilities to the control server.
    ///
    /// The second returned value is a base64-encoded payload that should be transmitted
    /// to the control server in order to start the handshake.
    pub fn initialize(
        prologue: &str,
        node_machine_private_key: &MachinePrivateKey,
        control_public_key: &MachinePublicKey,
        capability_version: ts_capabilityversion::CapabilityVersion,
    ) -> (Self, String) {
        let key = Sensitive::from(Zeroizing::from(node_machine_private_key.to_bytes()));

        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(noise_ik());
        builder.set_is_initiator(true);
        builder.set_rs(control_public_key.to_bytes());
        builder.set_prologue(prologue.as_bytes());
        builder.set_s(key);

        let mut state = builder.build_handshake_state();

        let overhead = state.get_next_message_overhead();
        let mut ciphertext = [0u8; INITIATION_PAYLOAD_LEN];
        state
            .write_message(&[], &mut ciphertext)
            .expect("initiation payload size too small");
        let init_msg =
            InitiationMessage::new(capability_version.into(), overhead as u16, ciphertext);

        (Self { state }, STANDARD.encode(init_msg.as_bytes()))
    }

    /// Complete the handshake by reading the control server's response.
    pub async fn complete<T: AsyncRead + Unpin>(
        &mut self,
        mut conn: T,
    ) -> Result<NoiseIo<T>, Error> {
        let mut hdr_bytes = [0u8; 3];
        let mut bytes_read = conn.read_exact(&mut hdr_bytes[..]).await?;

        let hdr_bytes = &hdr_bytes[..bytes_read];
        let hdr = ControlMessageHeader::try_parse(hdr_bytes)?;

        let mut packet = PacketMut::with_capacity(hdr_bytes.len() + hdr.len());

        packet.put_slice(hdr_bytes);
        packet.put_bytes(0, hdr.len()); // capacity != len, fill empty

        bytes_read += conn.read_exact(&mut packet[hdr_bytes.len()..]).await?;

        tracing::trace!(
            ?hdr,
            %bytes_read,
            "received from control:\n{}",
            packet
                .iter()
                .hexdump(Case::Lower)
                .flatten()
                .collect::<String>()
        );
        let response = ResponseMessage::try_parse(packet.as_ref())?;
        let len = response.hdr.len.get() as usize;

        tracing::debug!(%len, ?response);

        let data = self.state.read_message_vec(&response.data[0..len])?;
        if !data.is_empty() || !self.state.completed() {
            return Err(Error::HandshakeFailed);
        }

        let (tx, rx) = self.state.get_ciphers();
        Ok(NoiseIo::new(conn, rx, tx))
    }
}
