/// Generates a struct that implements all the fields/methods needed by both public and private
/// X25519 keys. Used by `create_x25519_{public_key, private_key, keypair}_type{s}` macros, not
/// intended to be used by itself.
macro_rules! create_x25519_public_key_type {
    ($(#[$attr:meta])* $public_name:ident, $key_prefix:literal) => {
        $(#[$attr])*
        #[derive(Clone, Eq, PartialEq)]
        pub struct $public_name([u8; 32]);

        impl $public_name {
            /// Return this key as a `u8` byte array.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0
            }

            fn random() -> Self {
                Self($crate::util::random_x25519_public())
            }
        }

        impl ::core::str::FromStr for $public_name {
            type Err = $crate::util::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::util::parse_hex(s, $key_prefix).map($public_name)
            }
        }

        impl From<&$public_name> for ::x25519_dalek::PublicKey {
            fn from(v: &$public_name) -> ::x25519_dalek::PublicKey {
                v.0.into()
            }
        }

        impl From<&$public_name> for ::crypto_box::PublicKey {
            fn from(v: &$public_name) -> ::crypto_box::PublicKey {
                v.0.into()
            }
        }

        impl ::core::fmt::Debug for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                $crate::util::write_hex(self.0, $key_prefix, f)
            }
        }

        impl ::core::fmt::Display for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                $crate::util::write_hex(self.0, $key_prefix, f)
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
                serializer.serialize_str(&$crate::util::to_hex_string(self.0, $key_prefix))
            }
        }
    }
}

macro_rules! create_x25519_private_key_type {
    ($(#[$attr:meta])* $private_name:ident, $key_prefix:literal, $public_name:ident) => {
        $(#[$attr])*
        #[derive(Clone, Eq, PartialEq, ::zeroize::ZeroizeOnDrop)]
        pub struct $private_name([u8; 32]);

        impl $private_name {
            pub fn random() -> Self {
                Self($crate::util::random_x25519_private())
            }

            pub fn public(&self) -> $public_name {
                $public_name($crate::util::x25519_public_from_private(self))
            }
        }

        impl $crate::private::SealedExportable for $private_name {
            fn write_hex(&self, out: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                $crate::util::write_hex(self.0, $key_prefix, out)
            }
        }

        impl $crate::ExportableKey for $private_name {
            fn export(self) -> Export<Self> {
                Export(self)
            }
        }

        impl From<&$private_name> for $public_name {
            fn from(v: &$private_name) -> $public_name {
                v.public()
            }
        }

        impl ::core::str::FromStr for $private_name {
            type Err = $crate::util::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::util::parse_hex(s, $key_prefix).map($private_name)
            }
        }

        impl From<&$private_name> for ::x25519_dalek::StaticSecret {
            fn from(v: &$private_name) -> ::x25519_dalek::StaticSecret {
                v.0.into()
            }
        }

        impl From<&$private_name> for ::crypto_box::SecretKey {
            fn from(v: &$private_name) -> ::crypto_box::SecretKey {
                v.0.into()
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
        create_x25519_private_key_type!($(#[$private_attr])* $private_name, $private_prefix, $public_name);

        $(#[$pair_attr])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $pair_name {
            pub public: $public_name,
            pub private: $private_name,
        }

        impl $pair_name {
            pub fn random() -> Self {
                Self::from($private_name::random())
            }
        }

        impl From<$pair_name> for $crate::Export<$private_name> {
            fn from(v: $pair_name) -> $crate::Export<$private_name> {
                v.private.into()
            }
        }

        impl From<$private_name> for $pair_name {
            fn from(private: $private_name) -> Self {
                let public = private.public();
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

        impl From<&$pair_name> for $crate::dalek::X25519KeyPair {
            fn from(v: &$pair_name) -> Self {
                $crate::dalek::X25519KeyPair{
                    public: (&v.public).into(),
                    private: (&v.private).into(),
                }
            }
        }
    };
}

pub(crate) use create_x25519_keypair_types;
pub(crate) use create_x25519_private_key_type;
pub(crate) use create_x25519_public_key_type;
