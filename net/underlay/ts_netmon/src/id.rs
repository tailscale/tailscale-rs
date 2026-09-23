use core::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    str::FromStr,
};
use std::borrow::Cow;

/// The unique id of a [`Netmon`][crate::Netmon].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonType(Cow<'static, str>);

impl Display for MonType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self.0.as_ref(), f)
    }
}

impl MonType {
    /// [`MonType`] for the canonical Windows-platform network monitor, built around
    /// Win32's
    /// [`<iphlpapi.h>`](https://learn.microsoft.com/en-us/windows/win32/api/_iphlp/).
    ///
    /// [`InterfaceId`]s with this type are NET_LUIDs.
    pub const WINDOWS_IPHLPAPI: Self = Self::new_static("win32_iphlpapi");

    /// [`MonType`] for the canonical Linux-platform network monitor, built around
    /// [`rtnetlink`](https://www.man7.org/linux/man-pages/man7/rtnetlink.7.html).
    ///
    /// [`InterfaceId`]s with this type are interface indices.
    pub const RTNETLINK: Self = Self::new_static("rtnetlink");

    /// [`MonType`] for the canonical macOS-platform network monitor, built around messages
    /// sent through `PF_ROUTE` sockets.
    ///
    /// [`InterfaceId`]s with this type are interface indices.
    pub const PF_ROUTE: Self = Self::new_static("pf_route");

    /// Convenience helper to construct a new mon type from a `&'static str`.
    ///
    /// # Panics
    ///
    /// If `ty` is not ascii or `ty` contains ':'.
    pub const fn new_static(ty: &'static str) -> Self {
        Self::new(Cow::Borrowed(ty))
    }

    /// Construct a new mon type.
    ///
    /// # Panics
    ///
    /// If `ty` is not ascii or `ty` contains ':'.
    pub const fn new(ty: Cow<'static, str>) -> Self {
        let s = match &ty {
            Cow::Borrowed(s) => *s,
            Cow::Owned(s) => s.as_str(),
        };

        if !s.is_ascii() {
            panic!("id types must be ascii")
        }

        let t = s.as_bytes();

        let mut i = 0;
        while i < t.len() {
            if t[i] == b':' {
                panic!("id type may not contain ':'");
            }

            i += 1;
        }

        Self(ty)
    }
}

impl AsRef<str> for MonType {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// A network interface id.
///
/// The meaning is specific to the particular netmon implementation, which can be
/// identified from [`InterfaceId::ty`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceId {
    ty: MonType,
    value: u64,
}

impl InterfaceId {
    /// Construct a new network interface id.
    pub const fn new(ty: MonType, value: u64) -> Self {
        InterfaceId { ty, value }
    }

    /// Get the [`MonType`] of this id.
    pub const fn ty(&self) -> &MonType {
        &self.ty
    }

    /// Get the value contained in this id (the actual interface id).
    pub const fn value(&self) -> u64 {
        self.value
    }
}

impl Debug for InterfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterfaceId({})", self)
    }
}

impl Display for InterfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ty, self.value)
    }
}

impl FromStr for InterfaceId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ty, value) = s.split_once(':').ok_or(())?;

        Ok(InterfaceId::new(
            MonType::new(ty.to_owned().into()),
            value.parse().map_err(|_| ())?,
        ))
    }
}
