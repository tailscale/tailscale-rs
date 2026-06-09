use bytes::Buf;

/// Heuristic identification of a packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketIdent {
    /// The type of the packet.
    pub ty: PacketType,
    /// Whether the packet is encapsulated.
    pub encapsulation: Encapsulation,
}

/// Heuristically-determined packet type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum PacketType {
    /// This is a Tailscale disco packet.
    Disco,
    /// This is a WireGuard packet.
    Wireguard,
    /// This is a STUN binding packet.
    StunBinding,
    /// The type of this packet is unknown.
    ///
    /// It should be dropped.
    #[default]
    Unknown,
}

/// The encapsulation format of a packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum Encapsulation {
    /// Packet is not encapsulated.
    #[default]
    None,
    /// Packet is encapsulated in a valid Geneve header.
    Geneve(GeneveHeader),
}

impl Encapsulation {
    /// Return the offset to the payload data contents.
    ///
    /// This skips any encapsulating header (currently Geneve) if present.
    pub const fn payload_offset(&self) -> usize {
        match self {
            Encapsulation::None => 0,
            Encapsulation::Geneve(geneve) => {
                size_of::<GeneveHeader>() + (geneve.opt_len() * 4) as usize
            }
        }
    }
}

impl PacketIdent {
    /// Determine the type and encapsulation of `pkt`.
    ///
    /// This differs from the Go (`magicsock.go:packetLooksLike`) in that
    /// `PacketType::Unknown` is separated from WireGuard traffic and means that the packet
    /// is positively not interpretable as a known packet type. WireGuard is still the catchall, we
    /// just verify the first few bytes of the message here using
    /// [`PacketIdent::could_be_wireguard`].
    pub fn identify(pkt: &[u8]) -> PacketIdent {
        let geneve = Self::parse_geneve(pkt);
        let geneve_ty = geneve.map(|x| x.packet_ty()).unwrap_or_default();

        let encapsulation = geneve.map(Encapsulation::Geneve).unwrap_or_default();
        let payload = &pkt[encapsulation.payload_offset()..];

        let ty = if disco::is_disco_message(payload) {
            PacketType::Disco
        } else if Self::could_be_wireguard(payload) {
            // Assume that all remaining traffic that could be a Wireguard packet is one.
            PacketType::Wireguard
        } else {
            PacketType::Unknown
        };

        let ty = match (ty, geneve_ty) {
            (x, y) if x == y => x,

            // A single Unknown verdict resolves to the known packet type.
            (PacketType::Unknown, x) | (x, PacketType::Unknown) => x,

            // Packet inspection and Geneve disagreed.
            _ => PacketType::Unknown,
        };

        Self { encapsulation, ty }
    }

    /// Attempt to parse `pkt` as a Geneve-encapsulated packet.
    pub fn parse_geneve(mut pkt: &[u8]) -> Option<GeneveHeader> {
        let b = pkt.try_get_u64().ok()?;

        let header = GeneveHeader(b);
        if !header.is_acceptable_data_packet() {
            return None;
        }

        Some(header)
    }

    /// Report whether the packet could be a Wireguard packet.
    ///
    /// Checks certain invariants that must be true if this is Wireguard; does not establish
    /// conclusive proof.
    pub fn could_be_wireguard(pkt: &[u8]) -> bool {
        if pkt.len() < 5 {
            return false;
        }

        let msgty = pkt[0];
        if !(1u8..=4).contains(&msgty) {
            return false;
        }

        [0u8; 4] == pkt[1..=4]
    }
}

bitrs::layout!({
    /// Geneve encapsulation protocol header as described in [RFC8926].
    ///
    /// [RFC8926]: https://www.rfc-editor.org/info/rfc8926/#name-tunnel-header-fields.
    pub struct GeneveHeader(pub u64);
    {
        /// The version of the Geneve packet.
        ///
        /// See [`GeneveHeader::VERSION`] for the current version.
        let version @ 63..62;
        /// The length of the variable-length options in multiples of 4 bytes. Excludes the length
        /// of the header.
        let opt_len @ 61..56;
        /// This is a control packet.
        let control @ 55;
        /// This packet carries critical option fields that must be interpreted or else the packet
        /// dropped.
        let critical @ 54;
        let __ @ 53..48 = 0;
        /// The type of data encapsulated by the header.
        let ethertype @ 47..32;
        /// The virtual network identifier.
        let vni @ 31..8;
        /// Reserved field specified by the RFC to be zero on transmit, ignore on receive.
        ///
        /// Tailscale checks whether it is zeroed because we always zero it.
        let trailer @ 7..0 = 0;
    }
});

impl GeneveHeader {
    /// Current version of the Geneve header.
    pub const VERSION: u8 = 0;

    /// Ethertype indicating this is a Tailscale disco message.
    pub const PROTO_DISCO: u16 = 0x7a11;
    /// Ethertype field indicating this is a WireGuard message.
    pub const PROTO_WIREGUARD: u16 = 0x7a12;

    /// Report whether this is a valid Geneve header.
    ///
    /// This checks both the version (against [`GeneveHeader::VERSION`]) and that the final reserved
    /// field is zero. The RFC specifies that this field should be ignored on receipt, but we always
    /// zero it, so sanity-check that it came from Tailscale.
    pub const fn is_valid(&self) -> bool {
        self.version() == Self::VERSION && self.trailer() == 0
    }

    /// Report whether this is an acceptable Tailscale data packet.
    ///
    /// Ensures that the packet [`is_valid`][GeneveHeader::is_valid], there are no options, this
    /// isn't a control packet, and it doesn't have the critical options bit set.
    pub const fn is_acceptable_data_packet(&self) -> bool {
        self.is_valid() && !self.control() && !self.critical() && self.opt_len() == 0
    }

    /// Report the [`PacketType`] encapsulated by this header.
    ///
    /// If the [`GeneveHeader::ethertype`] isn't recognized, [`PacketType::Unknown`] is returned.
    pub const fn packet_ty(&self) -> PacketType {
        match self.ethertype() {
            Self::PROTO_DISCO => PacketType::Disco,
            Self::PROTO_WIREGUARD => PacketType::Wireguard,
            _ => PacketType::Unknown,
        }
    }
}
