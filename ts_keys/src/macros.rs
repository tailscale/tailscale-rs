macro_rules! x25519_public {
    ($(#[$attr:meta])* $marker_type:ident, $public_prefix:literal) => {
        $(#[$attr])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Default, Hash, PartialOrd, Ord)]
        pub struct $marker_type;

        impl X25519Public for $marker_type {
            const PUBLIC_KEY_PREFIX: &'static str = $public_prefix;
        }
    };
}

macro_rules! x25519_pair {
    (
        $(#[$attr:meta])*
        $marker_type:ident,
        $public_prefix:literal,
        $private_prefix:literal,
    ) => {
        $(#[$attr])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Default, Hash, PartialOrd, Ord)]
        pub struct $marker_type;

        impl X25519Public for $marker_type {
            const PUBLIC_KEY_PREFIX: &'static str = $public_prefix;
        }

        impl X25519Private for $marker_type {
            const PRIVATE_KEY_PREFIX: &'static str = $private_prefix;
        }
    };
}

pub(crate) use x25519_pair;
pub(crate) use x25519_public;
