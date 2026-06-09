//! Definitions for an open endpoint address type.
//!
//! [`Endpoint`] is a trait object passed around inside [`DynEndpoint`], which wraps a [`smallbox`]
//! that holds the trait object on the stack if possible (otherwise spilling to heap). This is
//! essentially an emulation of an open enum: the set of endpoint types isn't exhaustively
//! enumerated anywhere and could be extended by a user or outside this module; they just need to
//! provide an implementation of [`Endpoint`] for their endpoint address type. This functionality
//! could be used to provide an underlay transport that uses its own endpoint type, while at the
//! same time permitting components inside our runtime to attempt downcast to a specific address
//! type where this is required for certain functionality (e.g. STUN only makes sense over an IP
//! underlay, and disco on the other hand only exchanges `CallMeMaybe` messages over DERP).

use core::{
    any::Any,
    cmp::Ordering,
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use dyn_eq::DynEq;
use dyn_hash::DynHash;

mod private {
    pub trait Sealed {}
    impl<T> Sealed for T where T: PartialOrd + 'static {}
}

/// Object-safe [`Ord`][core::cmp::Ord].
///
/// This can't provide the same guarantees as true [`Ord`][core::cmp::Ord] because since this is
/// object-safe, the value to compare against (`other`) must be dynamically-typed, so the comparison
/// must be fallible (which isn't permitted by [`Ord::cmp`][core::cmp::Ord::cmp]).
///
/// The _only_ way this trait is permitted to return `None` is if the types aren't the same.
/// Implementing this trait is an assertion that you can provide a total order across a given
/// [`TypeId`][core::any::TypeId]; returning `None` when `self.type_id() == other.type_id()`
/// violates this law.
pub trait DynOrd: Any + DynEq + private::Sealed {
    /// Compare `self` with `other`; see [`Ord::cmp`].
    ///
    /// Must return `None` iff `self.type_id() != other.type_id()`.
    fn dyn_cmp(&self, other: &dyn Any) -> Option<Ordering>;
}

impl<T> DynOrd for T
where
    T: DynEq + Ord + 'static,
{
    fn dyn_cmp(&self, other: &dyn Any) -> Option<Ordering> {
        let downcast = other.downcast_ref::<T>()?;
        Some(self.cmp(downcast))
    }
}

/// Optimistically inlined storage for an [`Endpoint`].
///
/// Uses [`smallbox`] to store any address `size_of::<NodePublicKey>()` or smaller on the stack.
pub type EndpointStorage = smallbox::SmallBox<dyn Endpoint, [u8; size_of::<[u8; 32]>()]>;

/// Type-erased endpoint address intended to be passed around as a trait object.
///
/// The bounds are meant to capture that this should contain ordinary read-only data that can be
/// used as a `HashMap` key (the [`DynHash`] + [`DynOrd`] bounds).
///
/// Implementors should provide `Hash`, `Clone`, `PartialEq`, `Eq`, `PartialOrd`, and `Ord`; the
/// `Dyn*` traits are blanket-impled from these.
pub trait Endpoint: Any + Debug + Send + Sync + DynHash + DynOrd {
    /// Report the type of this endpoint as a string.
    fn ty(&self) -> &str;

    /// Clone this endpoint into a new [`EndpointStorage`].
    fn ep_clone(&self) -> EndpointStorage;

    /// Whether this is a "disco coordinator" endpoint (currently just a proxy for it being a derp
    /// endpoint). If `true`, this endpoint should accept and send `CallMeMaybe` messages, but not
    /// disco `Ping`s and `Pong`s.
    fn is_disco_coordinator(&self) -> bool {
        false
    }
}

dyn_hash::hash_trait_object!(Endpoint);
dyn_eq::eq_trait_object!(Endpoint);

/// Dynamically-typed carrier for an [`Endpoint`].
#[derive(Hash, PartialEq, Eq)]
pub struct DynEndpoint(EndpointStorage);

impl Debug for DynEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl Clone for DynEndpoint {
    fn clone(&self) -> Self {
        Self(self.0.ep_clone())
    }
}

impl PartialOrd for DynEndpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DynEndpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Explicitly grab refs to `&dyn Endpoint`: we want to make sure the `dyn_cmp` doesn't use
        // the smallbox, since this comparison won't work.
        let slf = self.as_ref();
        let other = other.as_ref();

        if let Some(cmp) = slf.dyn_cmp(other) {
            return cmp;
        }

        // NOTE(npry): we know by the failure of `dyn_cmp` that self and other aren't the same
        // underlying type. We still need to provide a total order, but it doesn't need to "make
        // sense" at a semantic level (the values themselves will never be semantically compared),
        // since we're comparing across types -- the order just needs to be stable and consistent.
        //
        // This is used e.g. to put DynEndpoint in HashMap as a key: even if the underlying types
        // are different, we still need to be able to order them _somehow_. Since the compared types
        // are necessarily disjoint, we can just compare them by TypeId (leveraging the invariant
        // from DynOrd).

        assert_ne!(
            slf.type_id(),
            other.type_id(),
            "endpoint types are not comparable by DynOrd but have the same type id",
        );

        slf.type_id().cmp(&other.type_id())
    }
}

impl DynEndpoint {
    /// Get the inner [`Endpoint::ty`].
    pub fn ty(&self) -> &str {
        self.as_ref().ty()
    }

    /// Report whether this is a disco coordinator endpoint that should be used to transmit
    /// `CallMeMaybe` (and ought not to send pings and pongs).
    pub fn is_disco_coordinator(&self) -> bool {
        self.as_ref().is_disco_coordinator()
    }

    /// Construct a UDP [`DynEndpoint`].
    pub fn udp(socket_addr: SocketAddr) -> Self {
        UdpEndpoint(socket_addr).into()
    }

    /// Try to cast this endpoint into a [`SocketAddr`] for a UDP endpoint.
    pub fn as_udp(&self) -> Option<SocketAddr> {
        self.downcast_ref::<UdpEndpoint>().map(|x| x.0)
    }

    /// Construct a DERP [`DynEndpoint`].
    ///
    /// Contained type is [`DerpEndpoint`].
    pub fn derp(socket_addr: [u8; 32]) -> Self {
        DerpEndpoint(socket_addr).into()
    }

    /// Convenience function to cast this endpoint into a node public key for derp.
    pub fn as_derp(&self) -> Option<[u8; 32]> {
        self.downcast_ref::<DerpEndpoint>().map(|x| x.0)
    }

    /// Attempt to downcast the inner endpoint into a `T`.
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        <dyn Any>::downcast_ref::<T>(self.as_ref())
    }
}

impl AsRef<dyn Endpoint> for DynEndpoint {
    fn as_ref(&self) -> &dyn Endpoint {
        &*self.0
    }
}

impl<T> From<T> for DynEndpoint
where
    T: Endpoint,
{
    fn from(value: T) -> Self {
        Self(smallbox::smallbox![value])
    }
}

/// A UDP endpoint address.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct UdpEndpoint(pub SocketAddr);

impl Debug for UdpEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "udp:{}", self.0)
    }
}

impl Endpoint for UdpEndpoint {
    fn ty(&self) -> &str {
        "udp"
    }

    fn ep_clone(&self) -> EndpointStorage {
        smallbox::smallbox![*self]
    }
}

/// A derp endpoint address (node key).
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DerpEndpoint(pub [u8; 32]);

impl Debug for DerpEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "derp:{:02x}", ts_hexdump::IterFmt::contiguous(&self.0))
    }
}

impl Endpoint for DerpEndpoint {
    fn ty(&self) -> &str {
        "derp"
    }

    fn ep_clone(&self) -> EndpointStorage {
        smallbox::smallbox![*self]
    }

    fn is_disco_coordinator(&self) -> bool {
        true
    }
}
