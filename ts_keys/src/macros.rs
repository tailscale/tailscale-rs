/// Generates a struct that implements all the fields/methods needed by both public and private
/// X25519 keys. Used by `create_x25519_{public_key, private_key, keypair}_type{s}` macros, not
/// intended to be used by itself.
macro_rules! _create_x25519_base_key_type {
    ($(#[$attr:meta])* $key_name:ident, $key_prefix:literal) => {
        $(#[$attr])*
        #[derive(Clone, Eq, PartialEq, ::zerocopy::FromBytes, ::zerocopy::Immutable, ::zerocopy::IntoBytes, ::zerocopy::KnownLayout)]
        pub struct $key_name(
            [u8; $key_name::KEY_LEN_BYTES]
        );

        impl $key_name {
            /// The length of this key type, in bytes.
            pub const KEY_LEN_BYTES: usize = 32;
            /// The length of a hexidecimal string representation of this key, excluding the
            /// prefix and colon.
            pub const KEY_LEN_HEX_STR: usize = $key_name::KEY_LEN_BYTES * 2;
            /// The length of a hexidecimal string representation of this key, including the
            /// prefix and colon.
            pub const KEY_LEN_FULL_STR: usize = $key_name::KEY_LEN_HEX_STR + $key_name::KEY_PREFIX.len() + 1;
            /// The prefix placed in front of string representations of this key type, such
            /// as "$key_prefix:abcd..."
            pub const KEY_PREFIX: &'static str = $key_prefix;

            /// Return this key as a `u8` byte array.
            pub fn to_bytes(&self) -> [u8; $key_name::KEY_LEN_BYTES] {
                self.0
            }

            /// Return this key as a hex-encoded string.
            pub fn to_key_str(&self) -> ::alloc::string::String {
                use ::alloc::fmt::Write;
                let mut ret = ::alloc::string::String::with_capacity(Self::KEY_LEN_FULL_STR);
                ::core::write!(&mut ret, "{}:", Self::KEY_PREFIX).unwrap();
                for b in self.0.iter() {
                    ::core::write!(&mut ret, "{b:02x}").unwrap();
                }
                ret
            }
        }

        impl ::core::str::FromStr for $key_name {
            type Err = $crate::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.len() != $key_name::KEY_LEN_FULL_STR {
                    return Err($crate::ParseError::WrongLength);
                }

                let mut parts = s.split(':');
                let Some(prefix) = parts.next() else {
                    return Err($crate::ParseError::InvalidFormat);
                };
                if prefix != $key_name::KEY_PREFIX {
                    return Err($crate::ParseError::BadPrefix);
                }

                let Some(hex_str) = parts.next() else {
                    return Err($crate::ParseError::WrongLength);
                };
                if hex_str.len() != $key_name::KEY_LEN_HEX_STR {
                    return Err($crate::ParseError::WrongLength);
                }

                // s.split(':') should only return 2 parts: the prefix and the hex string. If
                // the string contained additional colons, it's malformed and not a valid key
                // string.
                if parts.next().is_some() {
                    return Err($crate::ParseError::InvalidFormat)
                }

                let mut key = $key_name([0u8; $key_name::KEY_LEN_BYTES]);
                for i in (0..$key_name::KEY_LEN_HEX_STR).step_by(2) {
                    let slice = hex_str.get(i..i + 2).unwrap();
                    let keyidx = i / 2;
                    let x = u8::from_str_radix(slice, 16).map_err(|_| $crate::ParseError::InvalidFormat)?;
                    key.0[keyidx] = x;
                }
                Ok(key)
            }
        }

        impl From<[u8; $key_name::KEY_LEN_BYTES]> for $key_name {
            fn from(v: [u8; $key_name::KEY_LEN_BYTES]) -> Self {
                $key_name(v)
            }
        }

        impl From<$key_name> for [u8; $key_name::KEY_LEN_BYTES] {
            fn from(v: $key_name) -> [u8; $key_name::KEY_LEN_BYTES] {
                v.0
            }
        }

        impl From<&$key_name> for [u8; $key_name::KEY_LEN_BYTES] {
            fn from(v: &$key_name) -> [u8; $key_name::KEY_LEN_BYTES] {
                v.0
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $key_name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<$key_name, D::Error> where D: ::serde::Deserializer<'de> {
                use ::core::str::FromStr;

                struct KeyVisitor;

                impl<'a> ::serde::de::Visitor<'a> for KeyVisitor {
                    type Value = $key_name;

                    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                        ::core::write!(
                            formatter,
                            "a {}-character string with the prefix '{}:' followed by {} hex characters",
                            $key_name::KEY_LEN_FULL_STR, $key_name::KEY_PREFIX, $key_name::KEY_LEN_HEX_STR
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> ::core::result::Result<Self::Value, E> where E: ::serde::de::Error {
                        $key_name::from_str(value).map_err(|e| ::serde::de::Error::custom(e))
                    }
                }

                deserializer.deserialize_str(KeyVisitor)
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $key_name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error> where S: ::serde::Serializer {
                serializer.serialize_str(&self.to_key_str())
            }
        }
    }
}

/// Generates a struct that implements all the fields/methods needed by X25519 public keys.
macro_rules! create_x25519_public_key_type {
    ($(#[$attr:meta])* $public_name:ident, $key_prefix:literal) => {
        _create_x25519_base_key_type!($(#[$attr])* #[derive(Copy, Default, Hash, PartialOrd, Ord)] $public_name, $key_prefix);

        impl From<$public_name> for ::x25519_dalek::PublicKey {
            fn from(v: $public_name) -> Self {
                v.0.into()
            }
        }

        impl From<$public_name> for ::crypto_box::PublicKey {
            fn from(v: $public_name) -> Self {
                v.0.into()
            }
        }

        impl From<&$public_name> for ::x25519_dalek::PublicKey {
            fn from(v: &$public_name) -> Self {
                v.0.into()
            }
        }

        impl From<&$public_name> for ::crypto_box::PublicKey {
            fn from(v: &$public_name) -> Self {
                v.0.into()
            }
        }

        impl ::core::fmt::Debug for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{self}")
            }
        }

        impl ::core::fmt::Display for $public_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.to_key_str())?;
                Ok(())
            }
        }
    }
}

/// Generates a struct that implements all the fields/methods needed by X25519 private keys.
macro_rules! create_x25519_private_key_type {
    ($(#[$attr:meta])* $private_name:ident, $public_name:ident, $key_prefix:literal) => {
        _create_x25519_base_key_type!($(#[$attr])* #[derive(::zeroize::ZeroizeOnDrop)] $private_name, $key_prefix);

        impl $private_name {
            /// Generate a new X25519 private key.
            pub fn random() -> Self {
                $private_name(::x25519_dalek::StaticSecret::random().to_bytes())
            }

            /// Calculate the corresponding public key for this private key.
            pub fn public_key(&self) -> $public_name {
                ::crypto_box::SecretKey::from(self).public_key().to_bytes().into()
            }
        }

        impl From<$private_name> for ::x25519_dalek::StaticSecret {
            fn from(v: $private_name) -> Self {
                v.0.into()
            }
        }

        impl From<&$private_name> for ::x25519_dalek::StaticSecret {
            fn from(v: &$private_name) -> Self {
                v.0.into()
            }
        }

        impl From<$private_name> for ::crypto_box::SecretKey {
            fn from(v: $private_name) -> Self {
                v.0.into()
            }
        }

        impl From<&$private_name> for ::crypto_box::SecretKey {
            fn from(v: &$private_name) -> Self {
                v.0.into()
            }
        }

        impl ::core::fmt::Debug for $private_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "[redacted]")
            }
        }
    }
}

/// Generates the public key, private key, and key pair structs with all the fields/methods needed
/// to work with X25519 keys.
macro_rules! create_x25519_keypair_types {
    ($(#[$public_attr:meta])* $public_name:ident, $public_prefix:literal, $(#[$private_attr:meta])* $private_name:ident, $private_prefix:literal, $(#[$pair_attr:meta])* $keypair_name:ident) => {
        create_x25519_public_key_type! { $(#[$public_attr])* $public_name, $public_prefix }
        create_x25519_private_key_type! { $(#[$private_attr])* $private_name, $public_name, $private_prefix }

        impl From<$private_name> for $public_name {
            fn from(v: $private_name) -> Self {
                let private = ::x25519_dalek::StaticSecret::from(v.0);
                let public = ::x25519_dalek::PublicKey::from(&private);
                $public_name(public.to_bytes())
            }
        }

        $(#[$pair_attr])*
        #[cfg_attr(feature = "serde", derive(::serde::Deserialize, ::serde::Serialize))]
        #[derive(Clone, Debug, Eq, PartialEq, ::zerocopy::FromBytes, ::zerocopy::Immutable, ::zerocopy::IntoBytes, ::zerocopy::KnownLayout)]
        pub struct $keypair_name {
            /// This keypair's public key.
            pub public: $public_name,
            /// This keypair's private key.
            pub private: $private_name,
        }

        impl $keypair_name {
            /// Generate a new X25519 public/private key pair.
            pub fn new() -> Self {
                let private = $private_name::random();
                let public = private.public_key();
                Self {
                    private,
                    public,
                }
            }
        }

        impl Default for $keypair_name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<$private_name> for $keypair_name {
            fn from(private: $private_name) -> Self {
                let public = private.public_key();
                Self {
                    private,
                    public,
                }
            }
        }

        impl From<$keypair_name> for X25519KeyPair {
            fn from(v: $keypair_name) -> Self {
                X25519KeyPair{
                    public: v.public.into(),
                    private: v.private.into(),
                }
            }
        }

        impl From<&$keypair_name> for X25519KeyPair {
            fn from(v: &$keypair_name) -> Self {
                X25519KeyPair{
                    public: (&v.public).into(),
                    private: (&v.private).into(),
                }
            }
        }

        impl From<$keypair_name> for ::x25519_dalek::PublicKey {
            fn from(v: $keypair_name) -> Self {
                v.public.into()
            }
        }

        impl From<&$keypair_name> for ::x25519_dalek::PublicKey {
            fn from(v: &$keypair_name) -> Self {
                v.public.into()
            }
        }

        impl From<$keypair_name> for ::crypto_box::PublicKey {
            fn from(v: $keypair_name) -> Self {
                v.public.into()
            }
        }

        impl From<&$keypair_name> for ::crypto_box::PublicKey {
            fn from(v: &$keypair_name) -> Self {
                v.public.into()
            }
        }

        impl From<$keypair_name> for ::x25519_dalek::StaticSecret {
            fn from(v: $keypair_name) -> Self {
                v.private.into()
            }
        }

        impl From<&$keypair_name> for ::x25519_dalek::StaticSecret {
            fn from(v: &$keypair_name) -> Self {
                (&v.private).into()
            }
        }

        impl From<$keypair_name> for ::crypto_box::SecretKey {
            fn from(v: $keypair_name) -> Self {
                v.private.into()
            }
        }

        impl From<&$keypair_name> for ::crypto_box::SecretKey {
            fn from(v: &$keypair_name) -> Self {
                (&v.private).into()
            }
        }
    }
}

pub(crate) use _create_x25519_base_key_type;
pub(crate) use create_x25519_keypair_types;
pub(crate) use create_x25519_private_key_type;
pub(crate) use create_x25519_public_key_type;
