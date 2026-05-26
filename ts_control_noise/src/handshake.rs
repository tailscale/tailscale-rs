use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::codec::Framed;
use ts_hexdump::{AsHexExt, Case};
use ts_keys::{MachinePrivateKey, MachinePublicKey};
use ts_noise::ik::SentHandshake;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    Error,
    codec::BiCodec,
    framed_io::FramedIo,
    messages::{Header, Initiation, MessageType},
};

type NoiseFramed<T> = Framed<T, BiCodec>;
type WrappedIo<T> = FramedIo<NoiseFramed<T>, BytesMut>;

/// Noise handshake state.
pub struct Handshake {
    state: SentHandshake,
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
        let mut ciphertext = [0; SentHandshake::INIT_SIZE];
        let state = SentHandshake::new(
            node_machine_private_key.into(),
            control_public_key.into(),
            prologue.as_bytes(),
            &mut ciphertext,
        );
        let init_msg = Initiation::new(
            capability_version.into(),
            SentHandshake::INIT_SIZE as u16,
            ciphertext,
        );

        (Self { state }, STANDARD.encode(init_msg.as_bytes()))
    }

    /// Complete the handshake by reading the control server's response.
    pub async fn complete<T: AsyncRead + Unpin>(
        mut self,
        mut conn: T,
        node_machine_private_key: &MachinePrivateKey,
    ) -> Result<WrappedIo<T>, Error> {
        let mut hdr_bytes = [0u8; 3];
        conn.read_exact(&mut hdr_bytes[..]).await?;

        let hdr = Header::try_ref_from_bytes(&hdr_bytes)?;

        let mut packet = BytesMut::zeroed(hdr.len.get() as _);
        conn.read_exact(&mut packet).await?;

        tracing::trace!(
            ?hdr,
            "response body from control:\n{}",
            packet
                .iter()
                .hexdump(Case::Lower)
                .flatten()
                .collect::<String>()
        );
        if hdr.typ != MessageType::Response {
            return Err(Error::BadFormat);
        }

        let session = match self
            .state
            .try_finish(&mut packet, node_machine_private_key.into())
        {
            Ok(session) => session,
            Err(state) => {
                self.state = state;
                return Err(Error::HandshakeFailed);
            }
        };

        Ok(FramedIo::new(Framed::new(conn, session.into())))
    }
}
