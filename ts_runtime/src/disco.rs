use bytes::{Bytes, BytesMut};
use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_disco_protocol::{MessageType, Ping, Pong};
use ts_keys::{DiscoKeyPair, DiscoPublicKey};
use ts_transport::DynEndpoint;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::{dataplane::IncomingDiscoMsg, env::Env};

pub struct Disco {
    env: Env,
}

impl kameo::Actor for Disco {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<IncomingDiscoMsg>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self { env })
    }
}

#[derive(Clone)]
pub struct SendDisco {
    // TODO(npry): consumed by transports in future commits
    #[expect(dead_code)]
    pub buf: Bytes,
    #[expect(dead_code)]
    pub ep: DynEndpoint,
}

impl Message<IncomingDiscoMsg> for Disco {
    type Reply = ();

    #[tracing::instrument(skip_all, fields(ty = ?msg.packet.get().ty(), sender = ?msg.sender))]
    async fn handle(&mut self, msg: IncomingDiscoMsg, _ctx: &mut Context<Self, Self::Reply>) {
        let pkt = msg.packet.get();

        match pkt.ty() {
            Some(MessageType::CallMeMaybe) => {
                if !msg.sender.is_disco_coordinator() {
                    tracing::warn!("call me maybe received but from non-derp endpoint");
                    return;
                };

                let cmm = pkt.as_msg::<ts_disco_protocol::CallMeMaybe>().unwrap();

                for ep in &cmm.endpoints {
                    let addr = ep.socket_addr();
                    let ep = DynEndpoint::udp(ep.socket_addr());

                    let tx_id = rand::random();

                    let buf = Self::mk_pkt::<Ping>(
                        Ping::size_with_padding(0),
                        &self.env.keys.disco_keys,
                        pkt.sender_pubkey(),
                        |ping| {
                            ping.node_key = self.env.keys.node_keys.public;
                            ping.tx_id = tx_id;
                        },
                    );

                    tracing::debug!(
                        %addr,
                        ?ep,
                        tx_id = ?format_args!("{:x?}", ts_hexdump::IterFmt::contiguous(&tx_id)),
                        "sent callmemaybe response ping"
                    );

                    self.env
                        .publish_noretain(SendDisco {
                            buf: buf.clone(),
                            ep,
                        })
                        .await
                        .unwrap();
                }
            }
            Some(MessageType::Ping) => {
                let ping = pkt.as_msg::<Ping>().unwrap();
                tracing::debug!(?ping, "got ping");

                let Some(sender) = msg.sender.as_udp() else {
                    tracing::warn!(?ping, "ping is from non-udp peer, bail");
                    return;
                };

                let buf = Self::mk_pkt::<Pong>(
                    Pong::size(),
                    &self.env.keys.disco_keys,
                    pkt.sender_pubkey(),
                    |pong| {
                        pong.tx_id = ping.tx_id;
                        pong.src = sender.into();
                    },
                );

                self.env
                    .publish_noretain(SendDisco {
                        buf,
                        ep: msg.sender,
                    })
                    .await
                    .unwrap();
            }
            Some(MessageType::Pong) => {
                // ignore, handled by path discovery
            }
            Some(_ty) => {
                tracing::trace!("unhandled disco type");
            }
            None => {
                tracing::warn!("unknown disco type");
            }
        }
    }
}

impl Disco {
    pub fn mk_pkt<Msg>(
        payload_size: usize,
        disco_keys: &DiscoKeyPair,
        rcpt_key: &DiscoPublicKey,
        f: impl FnOnce(&mut Msg),
    ) -> Bytes
    where
        Msg: ?Sized
            + ts_disco_protocol::Message
            + Immutable
            + TryFromBytes
            + IntoBytes
            + KnownLayout,
    {
        let msg_size = ts_disco_protocol::Packet::size_for_message(payload_size);
        let mut buf = BytesMut::zeroed(msg_size);

        let resp = ts_disco_protocol::Packet::init_from_bytes::<Msg>(&mut buf, f).unwrap();

        resp.encrypt_in_place(&disco_keys.private, rcpt_key, rand::random())
            .unwrap();

        buf.freeze()
    }
}
