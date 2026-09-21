/// Generates a struct that implements all the fields/methods needed by both public and private
/// X25519 keys. Used by `create_x25519_{public_key, private_key, keypair}_type{s}` macros, not
/// intended to be used by itself.
macro_rules! create_x25519_public_key_type {
    ($(#[$attr:meta])* $public_name:ident, $key_prefix:literal) => {
        $(#[$attr])*
        #[derive(
            Clone,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            ::zerocopy::Immutable,
            ::zerocopy::FromBytes,
            ::zerocopy::IntoBytes,
            ::zerocopy::KnownLayout,
            ::zerocopy::Unaligned,
        )]
        #[repr(C)]
        pub struct $public_name([u8; 32]);

        impl $public_name {
            /// Create a new random public key.
            ///
            /// The corresponding private key is discarded, so this is only useful for tests
            /// that need a public key that will never be used for communication.
            pub fn random() -> Self {
                Self($crate::util::random_x25519_public())
            }

            /// Convert the key to a `crypto_box` [`::crypto_box::PublicKey`], to perform cryptographic operations.
            ///
            /// The `crypto_box` type does not preserve the key's Tailscale purpose. You should convert
            /// keys to the `crypto_box` type as close as possible to the cryptographic operations.
            pub fn to_crypto_box(&self) -> ::crypto_box::PublicKey {
                self.0.into()
            }

            /// Convert the key to an `x25519_dalek` [`::x25519_dalek::PublicKey`], to perform cryptographic operations.
            ///
            /// The `x25519_dalek` type does not preserve the key's Tailscale purpose. You should
            /// convert keys to the `x25519_dalek` type as close as possible to the cryptographic operations.
            pub fn to_x25519_dalek(&self) -> ::x25519_dalek::PublicKey {
                self.0.into()
            }

            /// Create a key from a raw byte array.
            ///
            /// Use this sparingly, as it makes it easy to convert bytes into the wrong type of key.
            /// For serialization, prefer embedding the key type directly into a struct, and relying
            /// on zerocopy or serde serialization.
            pub fn from_bytes(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        // TODO: get rid of this default impl. Primary user is ts_control_serde's MapRequest/MapResponse.
        impl ::core::default::Default for $public_name {
            fn default() -> Self {
                Self::random()
            }
        }

        // TODO: get rid of the copy trait. It encourages too much silent copying for a type of marginal size.
        impl ::core::marker::Copy for $public_name {}

        impl $crate::private::SealedExportable for $public_name {
            const KEY_PREFIX: &'static str = $key_prefix;

            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            fn from_bytes(bytes: [u8; 32]) -> Self {
                $public_name(bytes)
            }
        }

        impl ::core::str::FromStr for $public_name {
            type Err = $crate::util::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::util::parse_hex(s, $key_prefix).map($public_name)
            }
        }

        impl ::core::fmt::Debug for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                $crate::util::write_hex(&self.0, $key_prefix, f)
            }
        }

        impl ::core::fmt::Display for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                $crate::util::write_hex(&self.0, $key_prefix, f)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $public_name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<$public_name, D::Error> where D: ::serde::Deserializer<'de> {
                let s = <&str>::deserialize(deserializer)?;
                $crate::util::parse_hex(s, $key_prefix).map_err(::serde::de::Error::custom).map($public_name)
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $public_name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error> where S: ::serde::Serializer {
                serializer.serialize_str(&$crate::util::to_hex_string(&self.0, $key_prefix))
            }
        }
    }
}

macro_rules! create_x25519_private_key_type {
    ($(#[$attr:meta])* $private_name:ident, $key_prefix:literal, $public_name:ident, $pair_name:ident) => {
        $(#[$attr])*
        #[doc = concat!("If you need both the public and private components of the key, use ", stringify!($pair_name), " to avoid repeated recomputation of the public key.")]
        #[derive(Clone, Eq, PartialEq, ::zeroize::ZeroizeOnDrop)]
        pub struct $private_name([u8; 32]);

        impl $private_name {
            /// Create a new random private key.
            pub fn random() -> Self {
                Self($crate::util::random_x25519_private())
            }

            /// Compute the public key counterpart of this private key.
            #[doc = concat!("Consider instead converting the private key to a ", stringify!($pair_name), ", which caches the public key computation.")]
            pub fn public_key(&self) -> $public_name {
                let private = self.to_x25519_dalek();
                let public = ::x25519_dalek::PublicKey::from(&private);
                $public_name(public.to_bytes())
            }

            /// Convert the key to a `crypto_box` [`::crypto_box::SecretKey`], to perform cryptographic operations.
            ///
            /// The `crypto_box` type does not preserve the key's Tailscale purpose. You should convert
            /// keys to the `crypto_box` type as close as possible to the cryptographic operations.
            pub fn to_crypto_box(&self) -> ::crypto_box::SecretKey {
                self.0.into()
            }

            /// Convert the key to an `x25519_dalek` [`::x25519_dalek::StaticSecret`], to perform cryptographic operations.
            ///
            /// The `x25519_dalek` type does not preserve the key's Tailscale purpose. You should
            /// convert keys to the `x25519_dalek` type as close as possible to the cryptographic operations.
            pub fn to_x25519_dalek(&self) -> ::x25519_dalek::StaticSecret {
                self.0.into()
            }
        }

        impl $crate::private::SealedExportable for $private_name {
            const KEY_PREFIX: &'static str = $key_prefix;

            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            fn from_bytes(bytes: [u8; 32]) -> Self {
                $private_name(bytes)
            }
        }

        impl ::core::str::FromStr for $private_name {
            type Err = $crate::util::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::util::parse_hex(s, $key_prefix).map($private_name)
            }
        }

        impl ::core::fmt::Debug for $private_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::write!(f, "{}:[redacted]", $key_prefix)
            }
        }

        impl ::core::fmt::Display for $private_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::write!(f, "{}:[redacted]", $key_prefix)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $private_name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<$private_name, D::Error> where D: ::serde::Deserializer<'de> {
                let s = <&str>::deserialize(deserializer)?;
                $crate::util::parse_hex(s, $key_prefix).map_err(::serde::de::Error::custom).map($private_name)
            }
        }
    }
}

macro_rules! create_x25519_keypair_types {
    (
        $(#[$public_attr:meta])*
        $public_name:ident,
        $public_prefix:literal,
        $(#[$private_attr:meta])*
        $private_name:ident,
        $private_prefix:literal,
        $(#[$pair_attr:meta])*
        $pair_name:ident
    ) => {
        create_x25519_public_key_type!($(#[$public_attr])* $public_name, $public_prefix);
        create_x25519_private_key_type!($(#[$private_attr])* $private_name, $private_prefix, $public_name, $pair_name);

        $(#[$pair_attr])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $pair_name {
            /// The public half of the key pair.
            pub public: $public_name,
            /// The private half of the key pair.
            pub private: $private_name,
        }

        impl $pair_name {
            /// Create a new random keypair.
            pub fn random() -> Self {
                $private_name::random().into()
            }

            /// Convert the key to an `x25519_dalek` keypair, to perform cryptographic operations.
            ///
            /// The `x25519_dalek` type does not preserve the key's Tailscale purpose. You should
            /// convert keys to the `x25519_dalek` type as close as possible to the cryptographic operations.
            pub fn to_x25519_dalek(&self) -> $crate::dalek::X25519KeyPair {
                $crate::dalek::X25519KeyPair{
                    public: self.public.to_x25519_dalek(),
                    private: self.private.to_x25519_dalek(),
                }
            }
        }

        impl $crate::private::SealedExportable for $pair_name {
            const KEY_PREFIX: &'static str = $private_prefix;

            fn as_bytes(&self) -> &[u8; 32] {
                self.private.as_bytes()
            }

            fn from_bytes(bytes: [u8; 32]) -> Self {
                $private_name(bytes).into()
            }
        }

        impl ::core::str::FromStr for $pair_name {
            type Err = $crate::util::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $private_name::from_str(s).map(Self::from)
            }
        }

        impl From<$private_name> for $pair_name {
            fn from(private: $private_name) -> Self {
                let public = private.public_key();
                Self { public, private }
            }
        }

        impl AsRef<$public_name> for $pair_name {
            fn as_ref(&self) -> &$public_name {
                &self.public
            }
        }

        impl AsRef<$private_name> for $pair_name {
            fn as_ref(&self) -> &$private_name {
                &self.private
            }
        }
    };
}

pub(crate) use create_x25519_keypair_types;
pub(crate) use create_x25519_private_key_type;
pub(crate) use create_x25519_public_key_type;
