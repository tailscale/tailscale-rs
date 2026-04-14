#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod client_version;
mod debug;
mod derp_map;
mod dial_plan;
mod env_type;
mod host_info;
mod location;
mod net_info;
mod netmap;
mod node;
mod ping;
mod register;
mod service;
mod tka_info;
mod tpm;
mod user;
pub mod util;

pub use debug::Debug;
pub use derp_map::{
    DerpMap, DerpServer, IpUsage as DerpIpUsage, Region as DerpRegion, RegionId as DerpRegionId,
};
pub use dial_plan::{ControlDialPlan, ControlIpCandidate};
pub use host_info::HostInfo;
pub use net_info::{DerpLatencyMap, LinkType, NetInfo};
pub use netmap::{Endpoint, EndpointType, MapRequest, MapResponse};
pub use node::{MarshaledSignature, Node, NodeId, StableNodeId};
pub use ping::{PingRequest, PingResponse, PingType};
pub use register::{RegisterAuth, RegisterRequest, RegisterResponse, SignatureType};
pub use service::{Service, ServiceProto};
pub use tka_info::TkaInfo;
pub use tpm::TpmInfo;
pub use user::{Login, LoginId, User, UserId, UserProfile};

/// TODO (dylan): implement properly
#[derive(Debug, Clone, PartialEq, Hash, serde::Deserialize, serde::Serialize)]
pub struct DnsResolver<'a> {
    #[serde(skip)]
    phantom: core::marker::PhantomData<&'a ()>,
}
