#![doc = include_str!("../README.md")]

use core::fmt;

/// Indicates the capability level of a Tailscale node. This must be kept in-sync with the
/// CapabilityVersion constants in the Golang codebase (`tailcfg/tailcfg.go`).
///
/// It can be thought of as a node's simple version number; a single monotonically increasing
/// integer, rather than the complex x.y.z-cccccc semver+hash(es) versioning scheme. Whenever a
/// node gains a capability or wants to negotiate a change in semantics with the control plane,
/// peers, or an official frontend (such as LocalAPI in the Golang codebase), bump this number and
/// document what's changed.
///
/// The capability versions 0, 1, 2, and 35 are undefined; you cannot create a
/// [`CapabilityVersion`] with these values.
///
/// Note: Prior to 2022-03-06, this value was known as the "`MapRequest` version", `mapVer`, or "map
/// cap"; you'll still see that name used in comments throughout the Golang codebase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CapabilityVersion(u16);

impl Default for CapabilityVersion {
    #[inline]
    fn default() -> Self {
        Self::CURRENT
    }
}

impl CapabilityVersion {
    /// 2020-??-??: implicit compression, keep-alives
    pub const V3: Self = Self(3);
    /// 2020-??-??: opt-in keep-alives via KeepAlive field, opt-in compression via Compress
    pub const V4: Self = Self(4);
    /// 2020-10-19: implies IncludeIPv6; delta Peers/UserProfiles, supports MagicDNS
    pub const V5: Self = Self(5);
    /// 2020-12-07: means MapResponse.PacketFilter nil means unchanged
    pub const V6: Self = Self(6);
    /// 2020-12-15: FilterRule.SrcIPs accepts CIDRs+ranges, doesn't warn about 0.0.0.0/::
    pub const V7: Self = Self(7);
    /// 2020-12-19: client can buggily receive IPv6 addresses and routes if beta enabled server-side
    pub const V8: Self = Self(8);
    /// 2020-12-30: client doesn't auto-add implicit search domains from peers; only
    /// DNSConfig.Domains
    pub const V9: Self = Self(9);
    /// 2021-01-17: client understands MapResponse.PeerSeenChange
    pub const V10: Self = Self(10);
    /// 2021-03-03: client understands IPv6; multiple default routes, and goroutine dumping
    pub const V11: Self = Self(11);
    /// 2021-03-04: client understands PingRequest
    pub const V12: Self = Self(12);
    /// 2021-03-19: client understands FilterRule.IPProto
    pub const V13: Self = Self(13);
    /// 2021-04-07: client understands DNSConfig.Routes and DNSConfig.Resolvers
    pub const V14: Self = Self(14);
    /// 2021-04-12: client treats nil MapResponse.DNSConfig as meaning unchanged
    pub const V15: Self = Self(15);
    /// 2021-04-15: client understands Node.Online, MapResponse.OnlineChange
    pub const V16: Self = Self(16);
    /// 2021-04-18: MapResponse.Domain empty means unchanged
    pub const V17: Self = Self(17);
    /// 2021-04-19: MapResponse.Node nil means unchanged (all fields now omitempty)
    pub const V18: Self = Self(18);
    /// 2021-04-21: MapResponse.Debug.SleepSeconds
    pub const V19: Self = Self(19);
    /// 2021-06-11: MapResponse.LastSeen used even less
    /// (<https://github.com/tailscale/tailscale/issues/2107>)
    pub const V20: Self = Self(20);
    /// 2021-06-15: added MapResponse.DNSConfig.CertDomains
    pub const V21: Self = Self(21);
    /// 2021-06-16: added MapResponse.DNSConfig.ExtraRecords
    pub const V22: Self = Self(22);
    /// 2021-08-25: DNSConfig.Routes values may be empty (for ExtraRecords support in 1.14.1+)
    pub const V23: Self = Self(23);
    /// 2021-09-18: MapResponse.Health from control to node; node shows in "tailscale status"
    pub const V24: Self = Self(24);
    /// 2021-11-01: MapResponse.Debug.Exit
    pub const V25: Self = Self(25);
    /// 2022-01-12: (nothing, just bumping for 1.20.0)
    pub const V26: Self = Self(26);
    /// 2022-02-18: start of SSHPolicy being respected
    pub const V27: Self = Self(27);
    /// 2022-03-09: client can communicate over Noise.
    pub const V28: Self = Self(28);
    /// 2022-03-21: MapResponse.PopBrowserURL
    pub const V29: Self = Self(29);
    /// 2022-03-22: client can request id tokens.
    pub const V30: Self = Self(30);
    /// 2022-04-15: PingRequest & PingResponse TSMP & disco support
    pub const V31: Self = Self(31);
    /// 2022-04-17: client knows FilterRule.CapMatch
    pub const V32: Self = Self(32);
    /// 2022-07-20: added MapResponse.PeersChangedPatch (DERPRegion + Endpoints)
    pub const V33: Self = Self(33);
    /// 2022-08-02: client understands CapabilityFileSharingTarget
    pub const V34: Self = Self(34);
    /// 2022-08-02: added PeersChangedPatch.{Key,DiscoKey,Online,LastSeen,KeyExpiry,Capabilities}
    pub const V36: Self = Self(36);
    /// 2022-08-09: added Debug.{SetForceBackgroundSTUN,SetRandomizeClientPort}; Debug are sticky
    pub const V37: Self = Self(37);
    /// 2022-08-11: added PingRequest.URLIsNoise
    pub const V38: Self = Self(38);
    /// 2022-08-15: clients can talk Noise over arbitrary HTTPS port
    pub const V39: Self = Self(39);
    /// 2022-08-22: added Node.KeySignature, PeersChangedPatch.KeySignature
    pub const V40: Self = Self(40);
    /// 2022-08-30: uses 100.100.100.100 for route-less ExtraRecords if global nameservers is set
    pub const V41: Self = Self(41);
    /// 2022-09-06: NextDNS DoH support; see <https://github.com/tailscale/tailscale/pull/5556>
    pub const V42: Self = Self(42);
    /// 2022-09-21: clients can return usernames for SSH
    pub const V43: Self = Self(43);
    /// 2022-09-22: MapResponse.ControlDialPlan
    pub const V44: Self = Self(44);
    /// 2022-09-26: c2n /debug/{goroutines,prefs,metrics}
    pub const V45: Self = Self(45);
    /// 2022-10-04: c2n /debug/component-logging
    pub const V46: Self = Self(46);
    /// 2022-10-11: Register{Request,Response}.NodeKeySignature
    pub const V47: Self = Self(47);
    /// 2022-11-02: Node.UnsignedPeerAPIOnly
    pub const V48: Self = Self(48);
    /// 2022-11-03: Client understands EarlyNoise
    pub const V49: Self = Self(49);
    /// 2022-11-14: Client understands CapabilityIngress
    pub const V50: Self = Self(50);
    /// 2022-11-30: Client understands CapabilityTailnetLockAlpha
    pub const V51: Self = Self(51);
    /// 2023-01-05: client can handle c2n POST /logtail/flush
    pub const V52: Self = Self(52);
    /// 2023-01-18: client respects explicit Node.Expired + auto-sets based on Node.KeyExpiry
    pub const V53: Self = Self(53);
    /// 2023-01-19: Node.Cap added, PeersChangedPatch.Cap, uses Node.Cap for ExitDNS before
    /// Hostinfo.Services fallback
    pub const V54: Self = Self(54);
    /// 2023-01-23: start of c2n GET+POST /update handler
    pub const V55: Self = Self(55);
    /// 2023-01-24: Client understands CapabilityDebugTSDNSResolution
    pub const V56: Self = Self(56);
    /// 2023-01-25: Client understands CapabilityBindToInterfaceByRoute
    pub const V57: Self = Self(57);
    /// 2023-03-10: Client retries lite map updates before restarting map poll.
    pub const V58: Self = Self(58);
    /// 2023-03-16: Client understands Peers[].SelfNodeV4MasqAddrForThisPeer
    pub const V59: Self = Self(59);
    /// 2023-04-06: Client understands IsWireGuardOnly
    pub const V60: Self = Self(60);
    /// 2023-04-18: Client understand SSHAction.SSHRecorderFailureAction
    pub const V61: Self = Self(61);
    /// 2023-05-05: Client can notify control over noise for SSHEventNotificationRequest recording
    /// failure events
    pub const V62: Self = Self(62);
    /// 2023-06-08: Client understands SSHAction.AllowRemotePortForwarding.
    pub const V63: Self = Self(63);
    /// 2023-07-11: Client understands s/CapabilityTailnetLockAlpha/CapabilityTailnetLock
    pub const V64: Self = Self(64);
    /// 2023-07-12: Client understands DERPMap.HomeParams + incremental DERPMap updates with params
    pub const V65: Self = Self(65);
    /// 2023-07-23: UserProfile.Groups added (available via WhoIs) (removed in 87)
    pub const V66: Self = Self(66);
    /// 2023-07-25: Client understands PeerCapMap
    pub const V67: Self = Self(67);
    /// 2023-08-09: Client has dedicated updateRoutine; MapRequest.Stream true means ignore
    /// Hostinfo+Endpoints
    pub const V68: Self = Self(68);
    /// 2023-08-16: removed Debug.LogHeap* + GoroutineDumpURL; added c2n /debug/logheap
    pub const V69: Self = Self(69);
    /// 2023-08-16: removed most Debug fields; added NodeAttrDisable*, NodeAttrDebug* instead
    pub const V70: Self = Self(70);
    /// 2023-08-17: added NodeAttrOneCGNATEnable, NodeAttrOneCGNATDisable
    pub const V71: Self = Self(71);
    /// 2023-08-23: TS-2023-006 UPnP issue fixed; UPnP can now be used again
    pub const V72: Self = Self(72);
    /// 2023-09-01: Non-Windows clients expect to receive ClientVersion
    pub const V73: Self = Self(73);
    /// 2023-09-18: Client understands NodeCapMap
    pub const V74: Self = Self(74);
    /// 2023-09-12: Client understands NodeAttrDNSForwarderDisableTCPRetries
    pub const V75: Self = Self(75);
    /// 2023-09-20: Client understands ExitNodeDNSResolvers for IsWireGuardOnly nodes
    pub const V76: Self = Self(76);
    /// 2023-10-03: Client understands Peers[].SelfNodeV6MasqAddrForThisPeer
    pub const V77: Self = Self(77);
    /// 2023-10-05: can handle c2n Wake-on-LAN sending
    pub const V78: Self = Self(78);
    /// 2023-10-05: Client understands UrgentSecurityUpdate in ClientVersion
    pub const V79: Self = Self(79);
    /// 2023-11-16: can handle c2n GET /tls-cert-status
    pub const V80: Self = Self(80);
    /// 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
    pub const V81: Self = Self(81);
    /// 2023-12-01: Client understands NodeAttrLinuxMustUseIPTables, NodeAttrLinuxMustUseNfTables,
    /// c2n /netfilter-kind
    pub const V82: Self = Self(82);
    /// 2023-12-18: Client understands DefaultAutoUpdate
    pub const V83: Self = Self(83);
    /// 2024-01-04: Client understands SeamlessKeyRenewal
    pub const V84: Self = Self(84);
    /// 2024-01-05: Client understands MaxKeyDuration
    pub const V85: Self = Self(85);
    /// 2024-01-23: Client understands NodeAttrProbeUDPLifetime
    pub const V86: Self = Self(86);
    /// 2024-02-11: UserProfile.Groups removed (added in 66)
    pub const V87: Self = Self(87);
    /// 2024-03-05: Client understands NodeAttrSuggestExitNode
    pub const V88: Self = Self(88);
    /// 2024-03-23: Client no longer respects deleted PeerChange.Capabilities (use CapMap)
    pub const V89: Self = Self(89);
    /// 2024-04-03: Client understands PeerCapabilityTaildrive.
    pub const V90: Self = Self(90);
    /// 2024-04-24: Client understands PeerCapabilityTaildriveSharer.
    pub const V91: Self = Self(91);
    /// 2024-05-06: Client understands NodeAttrUserDialUseRoutes.
    pub const V92: Self = Self(92);
    /// 2024-05-06: added support for stateful firewalling.
    pub const V93: Self = Self(93);
    /// 2024-05-06: Client understands Node.IsJailed.
    pub const V94: Self = Self(94);
    /// 2024-05-06: Client uses NodeAttrUserDialUseRoutes to change DNS dialing behavior.
    pub const V95: Self = Self(95);
    /// 2024-05-29: Client understands NodeAttrSSHBehaviorV1
    pub const V96: Self = Self(96);
    /// 2024-06-06: Client understands NodeAttrDisableSplitDNSWhenNoCustomResolvers
    pub const V97: Self = Self(97);
    /// 2024-06-13: iOS/tvOS clients may provide serial number as part of posture information
    pub const V98: Self = Self(98);
    /// 2024-06-14: Client understands NodeAttrDisableLocalDNSOverrideViaNRPT
    pub const V99: Self = Self(99);
    /// 2024-06-18: Initial support for filtertype.Match.SrcCaps - actually usable in capver 109
    /// (issue #12542)
    pub const V100: Self = Self(100);
    /// 2024-07-01: Client supports SSH agent forwarding when handling connections with /bin/su
    pub const V101: Self = Self(101);
    /// 2024-07-12: NodeAttrDisableMagicSockCryptoRouting support
    pub const V102: Self = Self(102);
    /// 2024-07-24: Client supports NodeAttrDisableCaptivePortalDetection
    pub const V103: Self = Self(103);
    /// 2024-08-03: SelfNodeV6MasqAddrForThisPeer now works
    pub const V104: Self = Self(104);
    /// 2024-08-05: Fixed SSH behavior on systems that use busybox (issue #12849)
    pub const V105: Self = Self(105);
    /// 2024-09-03: fix panic regression from cryptokey routing change (65fe0ba7b5)
    pub const V106: Self = Self(106);
    /// 2024-10-30: add App Connector to conffile (PR #13942)
    pub const V107: Self = Self(107);
    /// 2024-11-08: Client sends ServicesHash in Hostinfo, understands c2n GET /vip-services.
    pub const V108: Self = Self(108);
    /// 2024-11-18: Client supports filtertype.Match.SrcCaps (issue #12542)
    pub const V109: Self = Self(109);
    /// 2024-12-12: removed never-before-used Tailscale SSH public key support (#14373)
    pub const V110: Self = Self(110);
    /// 2025-01-14: Client supports a peer having Node.HomeDERP (issue #14636)
    pub const V111: Self = Self(111);
    /// 2025-01-14: Client interprets AllowedIPs of nil as meaning same as Addresses
    pub const V112: Self = Self(112);
    /// 2025-01-20: Client communicates to control whether funnel is enabled by sending
    /// Hostinfo.IngressEnabled (#14688)
    pub const V113: Self = Self(113);
    /// 2025-01-30: NodeAttrMaxKeyDuration CapMap defined, clients might use it (no tailscaled code
    /// change) (#14829)
    pub const V114: Self = Self(114);
    /// 2025-03-07: Client understands DERPRegion.NoMeasureNoHome.
    pub const V115: Self = Self(115);
    /// 2025-05-05: Client serves MagicDNS "AAAA" if NodeAttrMagicDNSPeerAAAA set on self node
    pub const V116: Self = Self(116);
    /// 2025-05-28: Client understands DisplayMessages (structured health messages), but not
    /// necessarily PrimaryAction.
    pub const V117: Self = Self(117);
    /// 2025-07-01: Client sends Hostinfo.StateEncrypted to report whether the state file is
    /// encrypted at rest (#15830)
    pub const V118: Self = Self(118);
    /// 2025-07-10: Client uses Hostinfo.Location.Priority to prioritize one route over another.
    pub const V119: Self = Self(119);
    /// 2025-07-15: Client understands peer relay disco messages, and implements peer client and
    /// relay server functions
    pub const V120: Self = Self(120);
    /// 2025-07-19: Client understands peer relay endpoint alloc with
    /// `disco.AllocateUDPRelayEndpointRequest` & `disco.AllocateUDPRelayEndpointResponse`
    pub const V121: Self = Self(121);
    /// 2025-07-21: Client sends Hostinfo.ExitNodeID to report which exit node it has selected, if any.
    pub const V122: Self = Self(122);
    /// 2025-07-28: fix deadlock regression from cryptokey routing change (issue #16651)
    pub const V123: Self = Self(123);
    /// 2025-08-08: removed NodeAttrDisableMagicSockCryptoRouting support, crypto routing is now mandatory
    pub const V124: Self = Self(124);
    /// 2025-08-11: dnstype.Resolver adds UseWithExitNode field.
    pub const V125: Self = Self(125);
    /// 2025-09-17: Client uses seamless key renewal unless disabled by control
    /// (tailscale/corp#31479)
    pub const V126: Self = Self(126);
    /// 2025-09-19: can handle C2N /debug/netmap.
    pub const V127: Self = Self(127);
    /// 2025-10-02: can handle C2N /debug/health.
    pub const V128: Self = Self(128);
    /// 2025-10-04: Fixed sleep/wake deadlock in magicsock when using peer relay (PR #17449)
    pub const V129: Self = Self(129);
    /// 2025-10-06: client can send key.HardwareAttestationPublic and
    /// key.HardwareAttestationKeySignature in MapRequest
    pub const V130: Self = Self(130);
    /// 2025-11-25: client respects NodeAttrDefaultAutoUpdate
    pub const V131: Self = Self(131);
    /// 2026-02-13: client respects NodeAttrDisableHostsFileUpdates
    pub const V132: Self = Self(132);
    /// 2026-02-17: client understands NodeAttrForceRegisterMagicDNSIPv4Only; MagicDNS IPv6
    /// registered w/ OS by default
    pub const V133: Self = Self(133);

    /// The current capability version of this Tailscale node.
    pub const CURRENT: Self = Self::V130;

    /// Create a new [`CapabilityVersion`] instance from a `u16`. Note that the versions 0, 1, 2,
    /// and 35 are undefined and will result in an error.
    pub const fn new(value: u16) -> Option<Self> {
        match value {
            v if v < 3 || v == 35 => None,
            _ => Some(Self(value)),
        }
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Convert [`CapabilityVersion`] into a native-endian [`u16`]; little-endian on `x86_64`.
impl From<CapabilityVersion> for u16 {
    fn from(value: CapabilityVersion) -> Self {
        value.0
    }
}

impl TryFrom<u16> for CapabilityVersion {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(())
    }
}
