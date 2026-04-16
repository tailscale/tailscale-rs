#![doc = include_str!("../README.md")]

use core::{
    fmt::Formatter,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod async_tokio;
pub mod dial;
mod error;
pub mod frame;

pub use async_tokio::{Client, DefaultClient};
pub use error::Error;

/// A 24-byte nonce for symmetric encryption with ChaCha20Poly1305.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
pub struct Nonce(pub [u8; 24]);

impl From<crypto_box::aead::Nonce<crypto_box::SalsaBox>> for Nonce {
    fn from(value: crypto_box::aead::Nonce<crypto_box::SalsaBox>) -> Self {
        Nonce(value.into())
    }
}

impl From<Nonce> for crypto_box::aead::Nonce<crypto_box::SalsaBox> {
    fn from(value: Nonce) -> Self {
        value.0.into()
    }
}

/// Unique identifier for a derp region.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegionId(pub NonZeroU32);

impl core::fmt::Display for RegionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.get().fmt(f)
    }
}

/// Info about a region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionInfo {
    /// The name of the region.
    pub name: String,

    /// The shortcode for the region, e.g. `nyc` for New York City.
    pub code: String,

    /// Don't attempt to use this region as a home region, and don't measure latency to
    /// it. It is permitted, however, to communicate with servers in the region to contact
    /// peers that do have this region as their home.
    pub no_measure_no_home: bool,
}

/// Info about a specific derp server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerConnInfo {
    /// The hostname of the server.
    pub hostname: String,

    /// The IPv4 address of the server.
    pub ipv4: IpUsage<Ipv4Addr>,
    /// The IPv6 address of the server.
    pub ipv6: IpUsage<Ipv6Addr>,

    /// Configuration used to validate the server's certificate.
    pub tls_validation_config: TlsValidationConfig,

    /// The port to use to connect to the server via HTTPS.
    pub https_port: u16,

    /// The port to use to perform STUN with the server. If `None`, STUN is disabled on this server.
    pub stun_port: Option<u16>,

    /// Whether this server is only to be used for stun.
    pub stun_only: bool,

    /// Whether the server is reachable over port 80 (typically used for captive portal
    /// detection).
    pub supports_port_80: bool,
}

impl ServerConnInfo {
    /// Convenience helper to create a [`ServerConnInfo`] from an HTTPS URL.
    ///
    /// The only canonical way to obtain a [`ServerConnInfo`] is by downloading the DERP
    /// map from a trusted source. This function allows constructing one with certain
    /// heuristic assumptions on the basis of just the HTTPS URL, which by definition
    /// doesn't contain all the information about a given DERP server. Consider this a
    /// warning that a given connection may not succeed if the assumptions made here do not
    /// match the reality of what the actual DERP server supports.
    ///
    /// ## Assumptions
    ///
    /// - The URL uses the `https` scheme
    /// - The URL's host resolves to IPv4 and IPv6 addresses via DNS
    /// - The TLS common name is the url's host
    /// - The STUN port for the server is the default (3478)
    /// - The server doesn't support port 80 connections for captive portal detection
    pub fn default_from_url(url: &url::Url) -> Option<Self> {
        if url.scheme() != "https" {
            return None;
        }

        let hostname = url.host_str()?.to_owned();
        let https_port = url.port().unwrap_or(443);

        Some(Self {
            hostname: hostname.clone(),

            ipv4: IpUsage::UseDns,
            ipv6: IpUsage::UseDns,

            tls_validation_config: TlsValidationConfig::CommonName {
                common_name: hostname,
            },

            https_port,
            stun_port: Some(3478),
            supports_port_80: false,
            stun_only: false,
        })
    }

    /// Build the URL to connect to this derp server over IPv4.
    ///
    /// This is only possible if [`Self::ipv4`][ServerConnInfo::ipv4] is not
    /// [`IpUsage::Disable`].
    pub fn https_url_ipv4(&self) -> Result<Option<url::Url>, url::ParseError> {
        match self.ipv4 {
            IpUsage::Disable => Ok(None),
            IpUsage::FixedAddr(addr) => {
                url::Url::parse(&format!("https://{addr}:{}", self.https_port)).map(Some)
            }
            IpUsage::UseDns => {
                url::Url::parse(&format!("https://{}:{}", self.hostname, self.https_port)).map(Some)
            }
        }
    }

    /// Build the URL to connect to this derp server over IPv6.
    ///
    /// This is only possible if [`Self::ipv6`][ServerConnInfo::ipv6] is not
    /// [`IpUsage::Disable`].
    pub fn https_url_ipv6(&self) -> Result<Option<url::Url>, url::ParseError> {
        match self.ipv6 {
            IpUsage::Disable => Ok(None),
            IpUsage::FixedAddr(addr) => {
                url::Url::parse(&format!("https://{addr}:{}", self.https_port)).map(Some)
            }
            IpUsage::UseDns => {
                url::Url::parse(&format!("https://{}:{}", self.hostname, self.https_port)).map(Some)
            }
        }
    }
}

/// Specifies the usage mode for an IP addressing type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpUsage<T> {
    /// Disable this IP addressing mode entirely.
    Disable,
    /// Use DNS lookups to resolve the address of this node using its hostname.
    UseDns,
    /// Use this fixed address to connect to this node in the specified IP stack.
    FixedAddr(T),
}

/// Configuration for TLS certificate validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsValidationConfig {
    /// The certificate is self-signed and has this SHA256 signature.
    SelfSigned {
        /// The signature of the self-signed cert.
        sha256: [u8; 64],
    },
    /// The certificate has the given common name.
    CommonName {
        /// The common name the certificate should have.
        common_name: String,
    },
    #[cfg(feature = "insecure-for-tests")]
    /// Skip TLS certificate verification entirely. Only for use in tests.
    InsecureForTests,
}

impl TlsValidationConfig {
    const TLS_SELFSIGNED_PREFIX: &str = "sha256-raw:";

    /// Convert a string to a validation config.
    ///
    /// `hostname` is used as a fallback if `s` is empty or invalid.
    pub fn from_str(s: &str, hostname: &str) -> TlsValidationConfig {
        match s {
            "" => TlsValidationConfig::CommonName {
                common_name: hostname.to_owned(),
            },
            x if x.starts_with(Self::TLS_SELFSIGNED_PREFIX) => {
                let mut buf = [0u8; 64];
                let bs = x.strip_prefix(Self::TLS_SELFSIGNED_PREFIX).unwrap().trim();

                match hex::decode_to_slice(bs, &mut buf) {
                    Ok(()) => TlsValidationConfig::SelfSigned { sha256: buf },
                    Err(e) => {
                        tracing::error!(error = %e, "invalid tls selfsigned cert, falling back to hostname");

                        TlsValidationConfig::CommonName {
                            common_name: hostname.to_owned(),
                        }
                    }
                }
            }
            x => TlsValidationConfig::CommonName {
                common_name: x.to_owned(),
            },
        }
    }
}
