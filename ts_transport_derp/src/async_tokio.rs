use core::fmt;

use crypto_box::aead::{Aead, AeadCore, AeadMutInPlace, OsRng};
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use ts_http_util::Client as _;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::UnderlayTransport;
use url::Url;

use crate::{
    Error, ServerConnInfo, frame,
    frame::{ClientInfo, FrameType, PeerGone, Ping, RawFrame, ServerInfo, ServerKey},
};

type DefaultIo = ts_http_util::Upgraded;

/// Type alias for the default derp client over upgraded HTTP on a tokio executor.
pub type DefaultClient = Client<DefaultIo>;

/// Asynchronous DERP transport for a single DERP region.
pub struct Client<Io> {
    read_conn: Mutex<FramedRead<ReadHalf<Io>, frame::Codec>>,
    write_conn: Mutex<FramedWrite<WriteHalf<Io>, frame::Codec>>,
}

/// Establish and upgrade a http connection to the derp region.
#[tracing::instrument(skip_all, err)]
pub async fn connect<'c>(
    region: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Result<Option<DefaultIo>, Error> {
    let Some((conn, _, addr)) = crate::dial::dial_region_tls(region).await.unwrap() else {
        return Ok(None);
    };

    let url = Url::parse(&format!("https://{addr}/derp"))?;

    let client = ts_http_util::http1::connect(conn).await?;

    let resp = client
        .send(ts_http_util::make_upgrade_req(&url, "DERP", None)?)
        .await?;

    let upgraded = ts_http_util::do_upgrade(resp)
        .await
        .map_err(tokio::io::Error::other)
        .map_err(Error::from)?;

    Ok(Some(upgraded))
}

impl<Io> Client<Io>
where
    Io: AsyncRead + AsyncWrite,
{
    /// Perform a derp handshake over the given transport and return a [`Client`].
    #[tracing::instrument(skip_all)]
    pub async fn handshake(conn: Io, node_keypair: &NodeKeyPair) -> Result<Self, Error> {
        let (read_conn, write_conn) = tokio::io::split(conn);

        let mut fw = FramedWrite::new(write_conn, frame::Codec);
        let mut fr = FramedRead::new(read_conn, frame::Codec);

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server key",
            )
        })??;
        let (sk, _rest) = frame
            .get()
            .as_type::<ServerKey>()
            .ok_or_else(|| std::io::Error::other("initial message was not serverkey"))?;

        sk.validate()?;

        tracing::trace!(
            server_public_key = %sk.key,
            "derp server public key"
        );

        let (client_info, encrypted) = make_clientinfo(node_keypair, &sk.key)?;
        tracing::trace!(?client_info);

        fw.send((
            RawFrame::from_body(&client_info, encrypted.len())?,
            encrypted.as_ref(),
        ))
        .await?;

        tracing::trace!("sent client info");

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server info",
            )
        })??;
        let (si, payload) = frame
            .get()
            .as_type::<ServerInfo>()
            .ok_or_else(|| std::io::Error::other("frame was not serverinfo"))?;

        tracing::trace!(server_info = ?si, "got server info");

        let info = decrypt_server_info(node_keypair, sk, si, payload)?;
        tracing::trace!(server_info = ?info);

        Ok(Self {
            read_conn: Mutex::new(fr),
            write_conn: Mutex::new(fw),
        })
    }

    /// Send a frame to the derp server.
    pub async fn send_frame(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
    ) -> Result<(), Error> {
        self.send_frame_with_extra(frame, &[]).await
    }

    /// Send a frame to the derp server with the specified additional payload.
    pub async fn send_frame_with_extra(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
        additional_payload: &[u8],
    ) -> Result<(), Error> {
        let raw = RawFrame::from_body(frame, additional_payload.len())?;

        {
            let mut wr = self.write_conn.lock().await;
            wr.send((raw, additional_payload)).await?;
        }

        Ok(())
    }

    /// Waits for a single data packet from a peer to arrive via this DERP server and returns it.
    /// DERP control messages (KeepAlive, Ping, etc) are handled inline and are not returned.
    pub async fn recv_one(&self) -> Result<(NodePublicKey, PacketMut), Error> {
        // DERP exchanges control messages (KeepAlives, Pings, etc) in-band with data messages
        // (SendPacket, RecvPacket, etc). The caller only cares about the payloads of data
        // messages, so we recv_one_raw() in a loop to handle any control messages while waiting
        // for data messages.

        loop {
            let frame = {
                let mut r = self.read_conn.lock().await;
                r.next().await.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "derp stream ended")
                })??
            };
            let frame = frame.get();

            match frame.header.typ {
                // TODO (dylan): handle other control message types
                // TODO (dylan): handle other data message types (ForwardPacket, etc)
                #[allow(deprecated)]
                FrameType::KeepAlive => {
                    // TODO (dylan): do we need to do anything on KeepAlive other than reset a timer?
                    // TODO (dylan): handle KeepAlive timer
                    tracing::debug!(transport = %self, "received KeepAlive frame");
                }
                FrameType::Ping => {
                    let Some((&ping, _)) = frame.as_type::<Ping>() else {
                        tracing::warn!("ping frame was not ping");
                        continue;
                    };

                    tracing::trace!(payload = ?ping.payload, "ping");

                    let pong: frame::Pong = ping.into();
                    self.send_frame(&pong).await?;

                    tracing::trace!(payload = ?pong.payload, "pong");
                }
                FrameType::PeerGone => {
                    let (gone, _rest) = frame.as_type::<PeerGone>().unwrap();

                    tracing::debug!(
                        peer = %gone.key,
                        reason = %gone.reason()?,
                        "peer gone from derp server"
                    );
                }
                FrameType::RecvPacket => {
                    let (recv, payload) = frame.as_type::<frame::RecvPacket>().unwrap();
                    return Ok((recv.src, payload.into()));
                }
                t => {
                    return Err(Error::UnexpectedRecvFrameType(t));
                }
            }
        }
    }
}

impl Client<DefaultIo> {
    /// Connect to and handshake with the derp server with the given URL over HTTP.
    pub async fn connect<'c>(
        region: impl IntoIterator<Item = &'c ServerConnInfo>,
        node_keypair: &NodeKeyPair,
    ) -> Result<Self, Error> {
        let conn = connect(region).await?.unwrap();

        Client::handshake(conn, node_keypair).await
    }
}

impl<Io> fmt::Debug for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<Io> fmt::Display for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Client").finish()
    }
}

fn make_clientinfo(
    node_keypair: &NodeKeyPair,
    server_key: &ts_keys::DerpServerPublicKey,
) -> Result<(ClientInfo, Vec<u8>), Error> {
    let cbox = crypto_box::SalsaBox::new(&server_key.into(), &node_keypair.private.into());
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    let json = serde_json::to_vec(&frame::ClientInfoPayload {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_string(),
        version: 2,
    })?;
    let encrypted = cbox
        .encrypt(&nonce, &json[..])
        .map_err(|_| frame::Error::EncryptionFailed)?;

    Ok((
        ClientInfo {
            key: node_keypair.public,
            nonce: nonce.into(),
        },
        encrypted,
    ))
}

fn decrypt_server_info(
    node_keypair: &NodeKeyPair,
    sk: &ServerKey,
    server_info: &ServerInfo,
    payload: &[u8],
) -> Result<frame::ServerInfoPayload, Error> {
    let mut payload = PacketMut::from(payload);

    let mut cbox = crypto_box::SalsaBox::new(&sk.key.into(), &node_keypair.private.into());
    cbox.decrypt_in_place(&server_info.nonce.into(), &[], &mut payload)
        .map_err(|e| frame::Error::DecryptionFailed(format!("err: {e}")))?;

    let sip = serde_json::from_slice::<frame::ServerInfoPayload>(payload.as_ref())?;
    if sip.version() != frame::PROTOCOL_VERSION {
        return Err(Error::UnsupportedProtocolVersion(
            sip.version(),
            frame::PROTOCOL_VERSION,
        ));
    }

    Ok(sip)
}

impl<Io> UnderlayTransport for Client<Io>
where
    Io: AsyncRead + AsyncWrite + Send,
{
    type Error = Error;

    #[tracing::instrument(fields(%self))]
    async fn recv(
        &self,
    ) -> impl IntoIterator<
        Item = Result<(NodePublicKey, impl IntoIterator<Item = PacketMut>), Self::Error>,
    > {
        [self.recv_one().await.map(|(k, pkt)| (k, [pkt]))]
    }

    /// Send a batch of packets to a peer via this DERP server.
    async fn send<BatchIter, PacketIter>(&self, peer_packets: BatchIter) -> Result<(), Self::Error>
    where
        BatchIter: IntoIterator<Item = (NodePublicKey, PacketIter)> + Send,
        BatchIter::IntoIter: Send,
        PacketIter: IntoIterator<Item = PacketMut> + Send,
        PacketIter::IntoIter: Send,
    {
        for (peer, packets) in peer_packets {
            for packet in packets {
                self.send_frame_with_extra(&frame::SendPacket { dest: peer }, packet.as_ref())
                    .await?;
            }
        }

        Ok(())
    }
}
