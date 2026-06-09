use std::{
    borrow::Borrow,
    collections::HashMap,
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::BytesMut;
use futures::Stream;
use futures_util::StreamExt;
use itertools::Itertools;
use kameo::{
    actor::ActorRef,
    message::{Context, Message, StreamMessage},
};
use tokio::net::UdpSocket;
use tokio_stream::wrappers::UnboundedReceiverStream;
use ts_bart::RoutingTable;
use ts_control::{Endpoint, EndpointType};
use ts_dataplane::async_tokio::{FromUnderlay, ToUnderlay, Tx};
use ts_packet::PacketMut;
use ts_transport::{DynEndpoint, UnderlayTransportId};

use crate::{
    dataplane::DataplaneActor,
    disco::SendDisco,
    env::Env,
    netmon,
    peer_tracker::{PeerDb, PeerState},
    stunner::StunAddress,
};

pub struct DirectActor {
    transport_id: UnderlayTransportId,

    sock4: Arc<UdpSocket>,
    sock6: Option<Arc<UdpSocket>>,

    tx: Tx<FromUnderlay>,

    peers: Arc<PeerDb>,

    stun_addr: Option<IpAddr>,
    addrs_v4: Vec<Endpoint>,
    addrs_v6: Vec<Endpoint>,

    reachable: ts_bart::Table<()>,

    env: Env,
}

#[derive(Clone, Debug)]
pub struct NewEndpoints(pub Arc<[Endpoint]>);

struct UdpRx(io::Result<HashMap<SocketAddr, Vec<PacketMut>>>);
struct UdpTx(ToUnderlay);

impl DirectActor {
    async fn publish_endpoints(&self) -> Result<(), crate::Error> {
        self.env
            .publish(NewEndpoints(
                self.addrs_v4
                    .iter()
                    .copied()
                    .chain(self.addrs_v6.iter().copied())
                    .chain(self.stun_addr.into_iter().map(|addr| {
                        let mut sockaddr = self.sock4.local_addr().unwrap();
                        sockaddr.set_ip(addr);

                        Endpoint {
                            endpoint: sockaddr,
                            ty: EndpointType::Stun,
                        }
                    }))
                    .collect(),
            ))
            .await
    }
}

impl kameo::Actor for DirectActor {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (id, rx, tx) = env
            .ask::<DataplaneActor, _>(None, crate::dataplane::NewUnderlayTransport, true)
            .await?;

        let sock4 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let sock4 = Arc::new(sock4);
        tracing::debug!(transport_id = ?id, local_addr = %sock4.local_addr().unwrap(), "direct udp4 socket bound");

        slf.attach_stream(udp_rx(sock4.clone()).boxed(), (), ());

        let sock6 = UdpSocket::bind("[::]:0").await.ok().map(Arc::new);
        if let Some(sock6) = sock6.as_ref() {
            tracing::debug!(transport_id = ?id, local_addr = %sock6.local_addr().unwrap(), "direct udp6 socket bound");
            slf.attach_stream(udp_rx(sock6.clone()).boxed(), (), ());
        } else {
            tracing::debug!("could not bind ipv6 direct");
        }

        slf.attach_stream(UnboundedReceiverStream::new(rx).map(UdpTx), (), ());

        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<StunAddress>(&slf).await?;
        env.subscribe::<Arc<netmon::State>>(&slf).await?;
        env.subscribe::<SendDisco>(&slf).await?;

        env.register(None, &slf).await?;

        Ok(Self {
            transport_id: id,
            sock4,
            sock6,
            env,
            peers: Default::default(),
            stun_addr: None,
            addrs_v4: vec![],
            addrs_v6: vec![],
            reachable: Default::default(),
            tx,
        })
    }
}

fn udp_rx(sock: impl Borrow<UdpSocket>) -> impl Stream<Item = UdpRx> {
    const REQUIRED_CAPACITY: usize = u16::MAX as _;

    let buf = BytesMut::zeroed(REQUIRED_CAPACITY);

    futures_util::stream::try_unfold((sock, buf), async |(sock, mut buf)| {
        let mut v = vec![];

        // Batch receive: wait until any packets are available from the socket, then try
        // to read as many as possible until we exhaust the underlying buffer and see a wouldblock.
        {
            let sock = sock.borrow();
            sock.readable().await?;

            loop {
                if buf.len() < u16::MAX as _ {
                    buf.resize(REQUIRED_CAPACITY, 0);
                }

                let (n, who) = match sock.try_recv_from(&mut buf) {
                    Ok((n, who)) => (n, who),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => return Err(e),
                };

                let pkt_buf = buf.split_to(n);
                v.push((who, PacketMut::from(pkt_buf)));
            }
        };

        tracing::trace!(n_pkts = v.len(), "udp rx batch");

        Ok(Some((v.into_iter().into_group_map(), (sock, buf))))
    })
    .map(UdpRx)
}

impl Message<Arc<PeerState>> for DirectActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        self.peers = msg.peers.clone();
    }
}

impl Message<SendDisco> for DirectActor {
    type Reply = ();

    async fn handle(
        &mut self,
        SendDisco { ep, buf }: SendDisco,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(ep) = ep.as_udp() else {
            return;
        };

        let sock = if ep.is_ipv4() {
            self.sock4.as_ref()
        } else if let Some(sock6) = self.sock6.as_deref() {
            sock6
        } else {
            tracing::trace!(?ep, "can't send disco, no ipv6");
            return;
        };

        if let Err(e) = sock.send_to(&buf, ep).await {
            tracing::warn!(?ep, error = %e, ?sock, "sending disco msg");
        } else {
            tracing::trace!(?ep, "sent disco msg");
        }
    }
}

const CGNAT_RANGE: ipnet::Ipv4Net = ipnet::Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10);
const TS_IP6_ULA: ipnet::Ipv6Net =
    ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48);

fn is_tailscale(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => CGNAT_RANGE.contains(v4),
        IpAddr::V6(v6) => TS_IP6_ULA.contains(v6),
    }
}

impl Message<Arc<netmon::State>> for DirectActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<netmon::State>, _ctx: &mut Context<Self, Self::Reply>) {
        self.addrs_v4.clear();
        self.addrs_v6.clear();
        self.reachable.clear();

        for (_id, addr) in msg.up_addrs() {
            let ip = addr.addr();

            let invalid = match ip {
                IpAddr::V4(v4) => {
                    v4.is_broadcast()
                        || v4.is_loopback()
                        || v4.is_unspecified()
                        || v4.is_documentation()
                        || v4.is_multicast()
                }
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified() || v6.is_loopback(),
            };

            if invalid {
                continue;
            }

            // NOTE(npry): this might be overly defensive -- while it probably makes sense to avoid
            // nesting our traffic through a VPN tun device if possible, this does cut off a
            // potential connectivity path, and we don't actually know for sure that it's tailscale.
            // Notionally, it's better to connect through another tailnet (via tailscaled) or a
            // 3rd-party VPN than not at all, but it may also make debugging horrible and this is
            // likely an edge case, so skip for the time being.
            if is_tailscale(&ip) {
                continue;
            }

            let port = match ip.is_ipv4() {
                true => self.sock4.local_addr().unwrap().port(),
                false => {
                    let Some(sock) = self.sock6.as_ref() else {
                        continue;
                    };
                    sock.local_addr().unwrap().port()
                }
            };

            let sockaddr = SocketAddr::new(ip, port);

            let ty = match ip {
                IpAddr::V4(x) => {
                    if x.is_link_local() || x.is_private() {
                        EndpointType::Local
                    } else {
                        EndpointType::Unknown
                    }
                }
                IpAddr::V6(x) => {
                    if x.is_unique_local() || x.is_unicast_link_local() {
                        EndpointType::Local
                    } else {
                        EndpointType::Unknown
                    }
                }
            };

            let ep = Endpoint {
                ty,
                endpoint: sockaddr,
            };

            if ep.endpoint.is_ipv4() {
                self.addrs_v4.push(ep);
            } else if self.sock6.is_some() {
                self.addrs_v6.push(ep);
            }

            self.reachable.insert(addr, ());
        }

        self.publish_endpoints().await.unwrap()
    }
}

impl Message<StunAddress> for DirectActor {
    type Reply = ();

    async fn handle(&mut self, _msg: StunAddress, _ctx: &mut Context<Self, Self::Reply>) {
        // TODO(npry): currently we're STUNning with the wrong socket (the global one in the
        //  stunner), so the local addr + NAT mapping is going to be wrong. don't add the STUNned
        //  address to our endpoints until it can actually reach this socket.

        // self.stun_addr = Some(msg.addr);
        // self.publish_endpoints().await.unwrap()
    }
}

impl Message<StreamMessage<UdpTx, (), ()>> for DirectActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<UdpTx, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let (ep_info, pkts) = match msg {
            StreamMessage::Next(msg) => msg.0,
            StreamMessage::Finished(_) => {
                tracing::warn!("udp tx stream shut down, closing");
                ctx.stop();
                return;
            }
            _ => return,
        };

        if pkts.is_empty() {
            return;
        }

        let Some(addr) = ep_info.as_udp() else {
            tracing::warn!(?ep_info, "invalid endpoint info for udp direct");
            return;
        };

        let sock = if addr.is_ipv4() {
            &self.sock4
        } else {
            self.sock6.as_ref().unwrap()
        };

        tracing::trace!(?ep_info, selected_addr = %addr, n_pkts = pkts.len(), "udp tx batch");

        for pkt in pkts {
            if let Err(e) = sock.send_to(&pkt, addr).await {
                tracing::error!(error = %e, "sending packet");
            }
        }
    }
}

impl Message<StreamMessage<UdpRx, (), ()>> for DirectActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<UdpRx, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let msg = match msg {
            StreamMessage::Next(msg) => msg.0,
            StreamMessage::Finished(_) => {
                tracing::warn!("udp rx stream shut down, closing");
                return;
            }
            _ => return,
        };

        const ACCEPTABLE_ERR: &[io::ErrorKind] = {
            use io::ErrorKind::*;
            &[NetworkDown, NetworkUnreachable, HostUnreachable, TimedOut]
        };

        match msg {
            Ok(mp) => {
                for (ep, pkts) in mp {
                    tracing::trace!(who = %ep, n_pkts = pkts.len(), "udp rx batch (by sender)");

                    self.tx
                        .send((self.transport_id, DynEndpoint::udp(ep), pkts))
                        .unwrap();
                }
            }
            Err(e) if ACCEPTABLE_ERR.contains(&e.kind()) => {
                tracing::error!(error = %e, "udp receive error");
            }
            Err(e) => {
                tracing::error!(error = %e, "unrecoverable error, die");
                panic!()
            }
        }
    }
}
