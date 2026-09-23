//! Serde helpers for control types.

use alloc::{string::ToString, vec::Vec};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{
    Deserialize, Deserializer,
    de::{
        DeserializeOwned,
        value::{BytesDeserializer, SeqDeserializer, StrDeserializer},
    },
};

/// Deserialize from a string field containing base64 by first decoding the base64, then
/// invoking a [`BytesDeserializer`] to produce a `T`.
pub fn deserialize_base64_string<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let str = <&'de str>::deserialize(deserializer)?;

    if str.is_empty() {
        Ok(None)
    } else {
        let bytes = STANDARD
            .decode(str.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Some(T::deserialize(BytesDeserializer::new(&bytes))?))
    }
}

/// Deserialize a comma-delimited string field as `Vec<T>`.
pub fn deserialize_string_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let str = <&'de str>::deserialize(deserializer)?;
    if str.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(Vec::<T>::deserialize(SeqDeserializer::new(str.split(',')))?)
    }
}

/// Deserialize a string field as `Option<T>` by treating the empty string as `None`.
pub fn deserialize_string_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let str = <&'de str>::deserialize(deserializer)?;
    if str.is_empty() {
        Ok(None)
    } else {
        Ok(Some(T::deserialize(StrDeserializer::new(str))?))
    }
}

/// Produce a deserializer for an optional value of type `$value`. The deserializer for the
/// `$repr` type is run first, then the `$filter_map` fn is used to produce an optional
/// value for the inner `$value` type.
///
/// Intended to be used with types where some range of values is used to indicate
/// optionality, e.g. the empty string, zero, negative numbers, or an explicit sentinel.
///
/// # Examples
///
/// ```rust
/// # use ts_control_serde::mk_option_deserializer;
///
/// mk_option_deserializer!(usize_gt_2, usize, Inner, |val| (val > 2).then_some(Inner(val)));
///
/// #[derive(serde::Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "usize_gt_2")]
///     value: Option<Inner>
/// }
///
/// #[derive(Debug, PartialEq, serde::Deserialize)]
/// struct Inner(usize);
///
/// let deserialized = serde_json::from_str::<MyStruct>(r#"{"value": 1}"#).unwrap();
/// assert_eq!(deserialized.value, None);
///
/// let deserialized = serde_json::from_str::<MyStruct>(r#"{"value": 4}"#).unwrap();
/// assert_eq!(deserialized.value, Some(Inner(4)));
/// ```
#[macro_export]
macro_rules! mk_option_deserializer {
    ($(#[$meta:meta])* $vis:vis $name:ident, $repr:ty, $value:ty, $filter_map:expr) => {
        $(#[$meta])*
        $vis fn $name<'de, D>(d: D) -> core::result::Result<core::option::Option<$value>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            use ::serde::Deserialize;

            let v = <$repr>::deserialize(d)?;
            Ok($filter_map(v))
        }
    }
}

crate::mk_option_deserializer!(
    /// Deserialize a derp region id into an optional
    /// [`DerpRegionId`][crate::DerpRegionId]. Zero values are treated as `None`.
    pub derp_region_id, u32, crate::DerpRegionId, |id| {
    core::num::NonZeroU32::new(id).map(crate::DerpRegionId::from)
});

/// Report whether the value is the default for its type.
///
/// Avoid using this function to check large types, as it must actually construct the empty
/// value to perform the check.
pub fn is_default<T>(t: &T) -> bool
where
    T: Default + PartialEq,
{
    t == &T::default()
}
