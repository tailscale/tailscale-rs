use core::net::{Ipv4Addr, Ipv6Addr};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::{Message, ReplySender},
    reply::DelegatedReply,
    supervision::RestartPolicy,
};
use ts_control::{
    ControlDialer, DialPlan, Endpoint, EndpointType, Error as ControlError, Node,
    RegistrationError, StateUpdate,
    client::{HttpConn, handle_ping, send_map_request},
};

use crate::{
    Task,
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    env::Env,
    netmon,
    stunner::StunAddress,
};

/// Temporary debugging configuration to report the stun- and netmon-discovered endpoints to control
/// with a dummy port. This does not result in direct UDP connectivity because there is no socket
/// hooked up anywhere, it just creates endpoint entries in control.
const SEND_DUMMY_ENDPOINTS: bool = false;

// placeholder: we will actually get this from the direct udp actor, which will consume
// these netmon::State messages to just directly give us an endpoint list to report.
// for testing, just use this dummy port. it won't result in a functional configuration
// because there's no udp socket listening, but should surface the endpoints in control
// and induce disco traffic from peers.
const DUMMY_PORT: u16 = 51823;

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    params: Params,
    state: RegState,

    derp_latency_measurement: Option<DerpLatencyMeasurement>,

    /// Endpoints not derived from public IPv4 STUN.
    local_endpoints: Vec<Endpoint>,
    /// Endpoint derived from public IPv4 STUN request.
    stun_endpoint: Option<Endpoint>,

    self_node: Option<Node>,
    pending_node_requests: Vec<PendingNodeRequest>,
}

enum RegState {
    NotRegistered {
        pending_auth_requests: Vec<ReplySender<Option<url::Url>>>,
    },
    AuthRequired(url::Url),
    Registered(HttpConn),
}

/// Control runner args.
#[derive(Clone)]
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`Env`] for this actor.
    pub(crate) env: Env,
}

#[doc(hidden)]
#[derive(Debug, Clone, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

#[derive(Clone)]
struct AuthRequired(url::Url);

struct RegisterResult(Result<HttpConn, RegistrationError>);

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        // NOTE(npry): ideally, we would use a monitor here. We actively don't want to link the
        // dialer, because if _we_ die, the dialer must not, as its whole goal is to outlive us
        // and provide a next-address in the presence of errors. But we want to take action in
        // response to the dialer panicking, probably involving killing our whole supervision tree
        // because something must be quite wrong. This can't be done with links without changing
        // the `kameo::Actor` implementation of the dialer. That's inappropriate because it's our
        // semantics that want to adapt to its behavior -- it shouldn't need to do adopt custom
        // behavior to ignore our DOWN messages because we have specific requirements.
        //
        // Having the dialer supervise us would solve this specific problem, but is semantically
        // incorrect because it's an internal implementation detail of this module (but the Runtime
        // actor would have to construct the dialer directly for the supervision tree to be right).
        // Logically (from the perspective of runtime code organization) we own the dialer, so even
        // though it would mechanistically work to have it supervise us, it doesn't make sense.
        //
        // Unfortunately, kameo doesn't currently support monitors. I'm leaving this note as a clear
        // example of a situation where those semantics are needed.
        let (_created, dialer) = params
            .env
            .ensure::<DialerActor, _, _>(None, {
                let env = params.env.clone();

                async || DialerActor {
                    dialer: Default::default(),
                    env,
                }
            })
            .await?;

        let client = dialer
            .ask(DialNext {
                url: params.config.server_url.clone(),
            })
            .await
            .map_err(|e| e.unwrap_err())?;

        Task::supervise_with(&slf, {
            let aref = slf.downgrade();
            let client = client.clone();
            let params = params.clone();

            move || {
                let aref = aref.clone();
                let client = client.clone();
                let params = params.clone();

                async move {
                    let mut followup = None;

                    loop {
                        let result = ts_control::register(
                            &params.config,
                            &params.config.server_url,
                            params.auth_key.as_deref(),
                            followup,
                            &params.env.keys,
                            &client,
                        )
                        .await;

                        if let Err(RegistrationError::MachineNotAuthorized(Some(u))) = result {
                            tracing::warn!(auth_url = %u, "machine not authorized");
                            followup = Some(u.clone());

                            let Some(aref) = aref.upgrade() else {
                                // if the control runner is dead, we should die shortly, no reason
                                // to keep running.
                                return;
                            };

                            if let Err(e) = aref.tell(AuthRequired(u)).await {
                                tracing::error!(error = %e, "failed to tell control runner required auth");
                            }

                            continue;
                        }

                        let Some(aref) = aref.upgrade() else {
                            return;
                        };
                        drop(aref.tell(RegisterResult(result.map(|_| client))).await);

                        break;
                    }
                }
            }
        })
        .restart_policy(RestartPolicy::Transient)
        .spawn()
        .await;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        params.env.subscribe::<Arc<netmon::State>>(&slf).await?;
        params.env.subscribe::<StunAddress>(&slf).await?;

        DerpLatencyMeasurer::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        params.env.register(None, &slf).await?;

        Ok(Self {
            state: RegState::NotRegistered {
                pending_auth_requests: Default::default(),
            },
            params,
            derp_latency_measurement: None,
            local_endpoints: Default::default(),
            stun_endpoint: None,
            self_node: None,
            pending_node_requests: Default::default(),
        })
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv4.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv4(replier));
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv6.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv6(replier));
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.clone()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::SelfNode(replier));
        }

        deleg
    }

    /// Wait for a report of whether interactive auth is needed, and if so, what the URL is.
    #[message(ctx)]
    pub fn auth_url(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<url::Url>>>,
    ) -> DelegatedReply<Option<url::Url>> {
        match &mut self.state {
            RegState::Registered(..) => ctx.reply(None),
            RegState::AuthRequired(u) => ctx.reply(Some(u.clone())),
            RegState::NotRegistered {
                pending_auth_requests,
            } => {
                let (deleg, replier) = ctx.reply_sender();
                if let Some(replier) = replier {
                    pending_auth_requests.push(replier);
                }

                deleg
            }
        }
    }
}

impl ControlRunner {
    async fn update_map_request(&self) {
        let RegState::Registered(conn) = &self.state else {
            tracing::error!("attempt to update map request while not registered");
            return;
        };

        let mut mrb = ts_control::MapRequestBuilder::new(&self.params.env.keys)
            .as_request()
            .endpoints(self.endpoints());

        if let Some(hostname) = self.params.config.hostname.as_deref() {
            mrb = mrb.hostname(hostname);
        }

        if let Some(latency) = &self.derp_latency_measurement {
            if let Some(result) = latency.measurement.first() {
                mrb = mrb.preferred_derp(result.id);
            };

            let iter = latency.measurement.iter().map(|result| {
                (
                    result.latency_map_key.as_str(),
                    result.latency.as_secs_f64(),
                )
            });

            mrb = mrb.derp_latencies(iter);
        }

        let client_name = self.params.config.format_client_name();

        let mut request = mrb.build();
        let host_info = request.host_info.get_or_insert_default();
        host_info.app = &client_name;
        host_info.ipn_version = ts_control::PKG_VERSION;

        send_map_request(
            request,
            &self.params.config.server_url.join("machine/map").unwrap(),
            conn,
        )
        .await
        .unwrap();
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let mut eps = self.local_endpoints.clone();
        eps.extend(self.stun_endpoint);

        eps
    }
}

impl Message<AuthRequired> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        AuthRequired(auth_url): AuthRequired,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let RegState::NotRegistered {
            pending_auth_requests,
        } = core::mem::replace(&mut self.state, RegState::AuthRequired(auth_url.clone()))
        else {
            tracing::warn!("got duplicate authrequired message");
            return;
        };

        for req in pending_auth_requests.into_iter() {
            req.send(Some(auth_url.clone()));
        }
    }
}

impl Message<RegisterResult> for ControlRunner {
    type Reply = ();

    #[tracing::instrument(skip_all, fields(result = ?msg.0))]
    async fn handle(&mut self, msg: RegisterResult, ctx: &mut Context<Self, Self::Reply>) {
        if matches!(self.state, RegState::Registered(..)) {
            tracing::warn!("got register result after already in registered state");
            return;
        }

        let conn = match msg.0 {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "unable to register with control server");
                ctx.stop();
                return;
            }
        };

        let old_state = core::mem::replace(&mut self.state, RegState::Registered(conn.clone()));

        if let RegState::NotRegistered {
            pending_auth_requests,
        } = old_state
        {
            for req in pending_auth_requests {
                req.send(None);
            }
        }

        let stream = ts_control::client::start_stream(
            &self.params.config.server_url,
            &self.params.env.keys,
            &self.params.config,
            conn,
        )
        .await
        .unwrap()
        .map(Arc::new);

        ctx.actor_ref().attach_stream(stream.boxed(), (), ());
    }
}

enum PendingNodeRequest {
    Ipv4(ReplySender<Option<Ipv4Addr>>),
    Ipv6(ReplySender<Option<Ipv6Addr>>),
    SelfNode(ReplySender<Option<Node>>),
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let msg = match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
                return;
            }

            StreamMessage::Next(msg) => msg,

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated");
                ctx.stop();
                return;
            }
        };

        if let RegState::Registered(conn) = &self.state {
            let _ = handle_ping(&msg, &self.params.config.server_url, conn).await;
        }

        if let Some(dial_plan) = &msg.dial_plan
            && self
                .params
                .env
                .ask::<DialerActor, _>(
                    None,
                    UpdateDialPlan {
                        dial_plan: dial_plan.clone(),
                    },
                    false,
                )
                .await
                .unwrap()
        {
            tracing::trace!(new_dial_plan = ?dial_plan);
        }

        if let Some(node) = msg.node.as_ref() {
            self.self_node = Some(node.clone());
        }

        if let Err(e) = self.params.env.publish(msg).await {
            tracing::error!(error = %e, "publishing netmap update");
        }

        if let Some(node) = &self.self_node {
            for req in self.pending_node_requests.drain(..) {
                match req {
                    PendingNodeRequest::Ipv4(sender) => {
                        sender.send(Some(node.tailnet_address.ipv4.addr()));
                    }
                    PendingNodeRequest::Ipv6(sender) => {
                        sender.send(Some(node.tailnet_address.ipv6.addr()));
                    }
                    PendingNodeRequest::SelfNode(sender) => {
                        sender.send(Some(node.clone()));
                    }
                }
            }
        }
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        if self.derp_latency_measurement.as_ref() == Some(&msg) {
            return;
        }

        self.derp_latency_measurement = Some(msg);
        self.update_map_request().await;
    }
}

const CGNAT_RANGE: ipnet::Ipv4Net = ipnet::Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10);
const TS_IP6_ULA: ipnet::Ipv6Net =
    ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48);

impl Message<Arc<netmon::State>> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<netmon::State>, _ctx: &mut Context<Self, Self::Reply>) {
        if !SEND_DUMMY_ENDPOINTS {
            return;
        }

        self.local_endpoints.clear();

        for (_iface, addr) in msg.up_addrs() {
            let ip = addr.addr();

            let viable_endpoint = match ip {
                IpAddr::V4(v4) => {
                    let invalid_addr = v4.is_broadcast()
                        || v4.is_loopback()
                        || v4.is_unspecified()
                        || v4.is_documentation()
                        || v4.is_multicast();

                    !invalid_addr && !CGNAT_RANGE.contains(&v4)
                }
                IpAddr::V6(v6) => {
                    let invalid_addr = v6.is_multicast() || v6.is_unspecified() || v6.is_loopback();

                    !invalid_addr && !TS_IP6_ULA.contains(&v6)
                }
            };

            if !viable_endpoint {
                continue;
            }

            let ep = Endpoint {
                ty: EndpointType::Local,
                endpoint: SocketAddr::new(ip, DUMMY_PORT),
            };

            self.local_endpoints.push(ep);
        }

        self.update_map_request().await;
    }
}

impl Message<StunAddress> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: StunAddress, _ctx: &mut Context<Self, Self::Reply>) {
        if !SEND_DUMMY_ENDPOINTS {
            return;
        }

        self.stun_endpoint = Some(Endpoint {
            ty: EndpointType::Stun,
            endpoint: SocketAddr::new(msg.addr, DUMMY_PORT),
        });

        self.update_map_request().await;
    }
}

#[derive(kameo::Actor)]
struct DialerActor {
    dialer: ControlDialer,
    env: Env,
}

#[kameo::messages]
impl DialerActor {
    #[message]
    async fn dial_next(&mut self, url: url::Url) -> Result<HttpConn, ts_control::Error> {
        self.dialer
            .full_connect_next(&url, &self.env.keys.machine_keys)
            .await
    }

    #[message]
    fn update_dial_plan(&mut self, dial_plan: DialPlan) -> bool {
        self.dialer.update_dial_plan(&dial_plan)
    }
}
